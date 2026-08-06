"""High-level operations shared by the web UI and the CLI:
preflight -> write -> postflight, plus list / remove / check."""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from . import generator, parser, technitium, validators
from .generator import GeneratorError, ServiceSpec
from .technitium import TechnitiumClient, TechnitiumError, ZoneKind, ZoneRecord, ZoneVerdict
from .validators import CheckResult, HttpsResult

log = logging.getLogger("traefikctl")


class OperationError(Exception):
    pass


@dataclass
class Preflight:
    name_ok: bool
    checks: list[CheckResult] = field(default_factory=list)
    collision: str = ""  # description of a router-name collision, if any
    file_exists: bool = False
    zone: ZoneVerdict | None = None  # Technitium verdict (None = not run)

    @property
    def blockers(self) -> list[CheckResult]:
        return [c for c in self.checks if c.level == "block"]

    @property
    def warnings(self) -> list[CheckResult]:
        return [c for c in self.checks if c.level == "warn"]

    @property
    def can_proceed(self) -> bool:
        """True when writing needs no force flag."""
        return (
            self.name_ok
            and not self.collision
            and not self.file_exists
            and not self.blockers
        )


def run_preflight(spec: ServiceSpec, settings: Settings) -> Preflight:
    pf = Preflight(name_ok=generator.valid_name(spec.name))
    if not pf.name_ok:
        pf.checks.append(
            CheckResult(
                False,
                "block",
                f"invalid name {spec.name!r}",
                "Use lowercase letters, digits and hyphens only.",
            )
        )
        return pf

    url_err = validators.backend_url_valid(spec.backend)
    if url_err:
        pf.checks.append(CheckResult(False, "block", url_err))
        return pf

    if spec.insecure and spec.backend.startswith("http://"):
        pf.checks.append(
            CheckResult(
                False,
                "warn",
                "insecure transport requested for an http:// backend",
                "The skip-verify transport only applies to https backends; "
                "if the backend serves TLS (e.g. Proxmox), use https://.",
            )
        )

    own_file = settings.dynamic_dir / f"{spec.name}.yml"
    pf.file_exists = own_file.exists()
    if pf.file_exists:
        pf.checks.append(
            CheckResult(
                False,
                "block",
                f"{own_file.name} already exists",
                "Overwriting requires force; the old file is backed up to "
                f"{spec.name}.yml.bak.",
            )
        )

    scan = parser.scan(settings.dynamic_dir)
    existing = scan.router(spec.name)
    if existing and existing.file != own_file:
        pf.collision = (
            f"router {spec.name!r} is already defined in {existing.file.name}"
        )
        pf.checks.append(
            CheckResult(
                False,
                "block",
                pf.collision,
                "Pick a different name or edit that file manually.",
            )
        )

    pf.zone = technitium.classify(spec.fqdn(settings), settings)
    zone_check = _zone_verdict_check(pf.zone)
    if zone_check:
        pf.checks.append(zone_check)

    pf.checks.append(validators.dns_check(spec.fqdn(settings), settings))
    pf.checks.append(validators.tcp_check(spec.backend))
    return pf


def _zone_verdict_check(verdict: ZoneVerdict) -> CheckResult | None:
    """Render a ZoneVerdict as a pre-flight CheckResult (None = show nothing,
    used when the integration is unconfigured)."""
    if verdict.kind == ZoneKind.DISABLED_INTEGRATION:
        return None
    if verdict.kind == ZoneKind.UNAVAILABLE:
        return CheckResult(
            False,
            "warn",
            "zone introspection unavailable — resolution check only",
            f"Technitium API did not answer ({verdict.detail}). "
            "Publishing still works; conflicts can't be detected at the zone level.",
        )
    if verdict.kind == ZoneKind.NO_RECORD:
        return CheckResult(True, "ok", "Technitium zone: " + verdict.detail)
    if verdict.kind == ZoneKind.INGRESS_ALIAS:
        return CheckResult(True, "ok", "Technitium zone: " + verdict.detail)
    if verdict.kind == ZoneKind.MISSING_RECORD:
        return CheckResult(
            False,
            "block",
            "Technitium zone: no A record for this name",
            verdict.detail,
        )
    conflicts = "; ".join(r.label for r in verdict.records)
    return CheckResult(
        False,
        "block",
        f"Technitium zone conflict: {conflicts}",
        verdict.detail,
    )


def render_preview(spec: ServiceSpec, settings: Settings) -> str:
    return generator.render(spec, settings)


def add_service(
    spec: ServiceSpec, settings: Settings, force: bool = False
) -> Path:
    pf = run_preflight(spec, settings)
    if not pf.can_proceed and not force:
        problems = "; ".join(c.summary for c in pf.blockers) or pf.collision
        raise OperationError(f"pre-flight blocked the write: {problems}")
    if pf.collision:
        # A collision in ANOTHER file is never overridable — force only
        # covers overwriting the tool's own NAME.yml.
        raise OperationError(pf.collision)
    path = generator.write_service(spec, settings, force=force)
    log.info("wrote %s (host=%s backend=%s)", path, spec.fqdn(settings), spec.backend)
    return path


def run_postflight(
    host: str, settings: Settings, settle_seconds: float = 2.0, attempts: int = 3
) -> HttpsResult:
    """Probe the new route through the ingress. The file watcher needs a
    moment to load the file — a 404 (or a stale 3xx from the old config)
    right after writing usually just means 'not loaded yet', so retry a few
    times before reporting it."""

    def stale(code: int | None) -> bool:
        return code is None or code == 404 or 300 <= code < 400

    result = None
    for _ in range(attempts):
        time.sleep(settle_seconds)
        result = validators.https_check(host, settings)
        if not stale(result.status_code):
            return result
    if result is not None and result.status_code == 404:
        result.ok = False
        result.hints = [
            "Traefik answered 404 — the router may not have loaded, or the "
            "backend returns 404 for '/'. Re-run the check in a few seconds."
        ] + result.hints
    elif result is not None and result.status_code is not None:
        result.hints = [
            f"Traefik still answered {result.status_code} after "
            f"{attempts} attempts — this may be a stale answer from the old "
            "config, or the backend genuinely redirects '/'. Re-run the "
            "check in a few seconds."
        ] + result.hints
    return result


def list_services(settings: Settings) -> parser.ScanResult:
    return parser.scan(settings.dynamic_dir)


def remove_service(name: str, settings: Settings) -> Path:
    if not generator.valid_name(name):
        raise OperationError(f"invalid name {name!r}")
    path = settings.dynamic_dir / f"{name}.yml"
    scan = parser.scan(settings.dynamic_dir)
    if not path.exists():
        found = scan.router(name)
        if found:
            raise OperationError(
                f"router {name!r} lives in {found.file.name}, not {name}.yml — "
                "edit that file manually."
            )
        raise OperationError(f"no such service: {name}.yml not found")
    others = [r.name for r in scan.routers_in(path) if r.name != name]
    if others:
        raise OperationError(
            f"{path.name} also defines router(s) {', '.join(sorted(others))} — "
            "refusing to delete a multi-router file; edit it manually."
        )
    path.unlink()
    log.info("removed %s", path)
    return path


@dataclass
class DeleteOutcome:
    record: ZoneRecord
    message: str
    negative_ttl: int | None = None


def delete_zone_record(
    fqdn: str, rtype: str, value: str, disabled: bool, settings: Settings
) -> DeleteOutcome:
    """The guided fix: delete ONE conflicting record in Technitium after the
    caller's explicit confirmation. Re-fetches the record so we only ever
    delete something that still exists exactly as the user confirmed it."""
    client = TechnitiumClient(settings)
    if not client.enabled:
        raise OperationError("Technitium integration is not configured")
    try:
        candidates = [
            r
            for r in client.get_records(fqdn)
            if r.type.upper() == rtype.upper()
            and r.value == value
            and r.disabled == disabled
        ]
    except Exception as e:
        raise OperationError(f"could not re-read the record before deleting: {e}")
    if not candidates:
        raise OperationError(
            f"no record {fqdn} {rtype} → {value} found — it may already be "
            "gone; re-run pre-flight."
        )
    record = candidates[0]
    reason = client.denylist_reason(record)
    if reason:
        raise OperationError(f"refusing to delete {record.label}: {reason}")
    try:
        client.delete_record(record)
    except TechnitiumError as e:
        raise OperationError(f"Technitium refused the delete: {e}")
    neg_ttl = client.get_negative_ttl()
    ttl_note = (
        f"resolvers that already asked may serve stale NXDOMAIN for up to "
        f"{neg_ttl} seconds (the zone's negative TTL)"
        if neg_ttl
        else "resolvers that already asked may serve stale NXDOMAIN until "
        "the zone's negative TTL expires"
    )
    log.info("deleted Technitium record %s — %s", record.label, ttl_note)
    if settings.wildcard_covers_ingress:
        outcome_note = (
            "The wildcard now covers the name at the authoritative server"
        )
    else:
        outcome_note = (
            f"Now create an A record {fqdn} → {settings.ingress_ip} in "
            "Technitium to publish it on this ingress"
        )
    return DeleteOutcome(
        record=record,
        message=f"Deleted {record.label}. {outcome_note}; {ttl_note}.",
        negative_ttl=neg_ttl,
    )


@dataclass
class CreateOutcome:
    fqdn: str
    ip: str
    message: str


def create_zone_record(fqdn: str, settings: Settings) -> CreateOutcome:
    """The guided create: in explicit mode only, create the missing A record
    fqdn -> this ingress IP after the caller's explicit confirmation.
    Re-classifies first so we only ever create when the verdict is still
    MISSING_RECORD — never over an existing record of any kind."""
    if settings.wildcard_covers_ingress:
        raise OperationError(
            "record creation is only available in explicit-record mode — on "
            "this ingress the wildcard already covers published names"
        )
    client = TechnitiumClient(settings)
    if not client.enabled:
        raise OperationError("Technitium integration is not configured")
    verdict = technitium.classify(fqdn, settings)
    if verdict.kind == ZoneKind.UNAVAILABLE:
        raise OperationError(
            f"could not verify the zone before creating: {verdict.detail}"
        )
    if verdict.kind != ZoneKind.MISSING_RECORD:
        raise OperationError(
            f"not creating: the zone state for {fqdn} is "
            f"{verdict.kind.value!r}, not a missing record — re-run pre-flight."
        )
    try:
        client.create_a_record(fqdn)
    except TechnitiumError as e:
        raise OperationError(f"Technitium refused the create: {e}")
    return CreateOutcome(
        fqdn=fqdn,
        ip=settings.ingress_ip,
        message=(
            f"Created {fqdn} A → {settings.ingress_ip}. The authoritative "
            "server answers immediately; resolvers that already cached the "
            "wildcard answer may serve it until their TTL expires."
        ),
    )


@dataclass
class ZonePanelRow:
    record: ZoneRecord
    # wildcard | direct-access | ingress-aliased | other-ingress | disabled | infra
    category: str
    shadows: str = ""  # name of a published service this record shadows


@dataclass
class ZonePanel:
    available: bool
    rows: list[ZonePanelRow] = field(default_factory=list)
    wildcard_ok: bool = False
    wildcard_detail: str = ""
    error: str = ""
    # Explicit mode only: published services whose name has no enabled
    # A record -> this ingress, i.e. wildcard-covered by the other ingress.
    missing_published: list[str] = field(default_factory=list)


def zone_panel(settings: Settings) -> ZonePanel:
    """Read-only zone overview for the DNS page / CLI dns command."""
    client = TechnitiumClient(settings)
    if not client.enabled:
        return ZonePanel(available=False, error="Technitium integration not configured")
    try:
        records = client.get_zone()
    except Exception as e:
        return ZonePanel(available=False, error=f"Technitium API unavailable: {e}")

    published = {
        r.host: r.name for r in parser.scan(settings.dynamic_dir).routers if r.host
    }
    zone = settings.technitium_zone.lower()
    panel = ZonePanel(available=True)
    wildcard_name = f"*.{zone}"

    wildcard = [
        r for r in records if r.name.lower() == wildcard_name and r.type == "A"
    ]
    wildcard_target = ""
    if not wildcard:
        panel.wildcard_ok = False
        if settings.wildcard_covers_ingress:
            panel.wildcard_detail = (
                f"NO wildcard A record found for {wildcard_name} — published "
                "services will not resolve. This must be fixed in Technitium."
            )
        else:
            panel.wildcard_detail = (
                f"NO wildcard A record found for {wildcard_name} — this "
                "ingress does not depend on it, but the service ingress does. "
                "Check Technitium."
            )
    else:
        w = wildcard[0]
        wildcard_target = w.rdata.get("ipAddress", "")
        if w.disabled:
            panel.wildcard_ok = False
            panel.wildcard_detail = f"wildcard exists but is DISABLED ({w.label})"
        elif settings.wildcard_covers_ingress:
            if wildcard_target != settings.ingress_ip:
                panel.wildcard_ok = False
                panel.wildcard_detail = (
                    f"wildcard points at {w.value}, not the ingress "
                    f"({settings.ingress_ip}) — routing architecture is broken"
                )
            else:
                panel.wildcard_ok = True
                panel.wildcard_detail = f"{wildcard_name} → {settings.ingress_ip}"
        else:
            if wildcard_target == settings.ingress_ip:
                panel.wildcard_ok = False
                panel.wildcard_detail = (
                    f"wildcard points at THIS ingress ({settings.ingress_ip}) — "
                    "on the management ingress it must point at the service "
                    "ingress; routing architecture is broken"
                )
            else:
                panel.wildcard_ok = True
                panel.wildcard_detail = (
                    f"{wildcard_name} → {w.value} (other ingress) — names "
                    "without a specific record land there, not here"
                )

    for r in sorted(records, key=lambda r: (r.name, r.type)):
        name = r.name.lower()
        if name == wildcard_name:
            category = "wildcard"
        elif r.type in ("SOA", "NS"):
            category = "infra"
        elif r.disabled:
            category = "disabled"
        elif r.type == "A" and r.rdata.get("ipAddress") == settings.ingress_ip:
            category = "ingress-aliased"
        elif (
            not settings.wildcard_covers_ingress
            and r.type == "A"
            and wildcard_target
            and r.rdata.get("ipAddress") == wildcard_target
        ):
            category = "other-ingress"
        else:
            category = "direct-access"
        shadows = ""
        if category in ("direct-access", "disabled", "other-ingress") and name in published:
            shadows = published[name]
        panel.rows.append(ZonePanelRow(record=r, category=category, shadows=shadows))

    if not settings.wildcard_covers_ingress:
        aliased = {
            r.name.lower()
            for r in records
            if r.type == "A"
            and not r.disabled
            and r.rdata.get("ipAddress") == settings.ingress_ip
        }
        panel.missing_published = sorted(
            svc for host, svc in published.items() if host.lower() not in aliased
        )
    return panel


@dataclass
class ServiceHealth:
    entry: parser.RouterEntry
    dns: CheckResult | None = None
    tcp: list[CheckResult] = field(default_factory=list)
    https: HttpsResult | None = None
    zone: ZoneVerdict | None = None
    zone_check: CheckResult | None = None


def check_service(entry: parser.RouterEntry, settings: Settings) -> ServiceHealth:
    health = ServiceHealth(entry=entry)
    if entry.host:
        health.zone = technitium.classify(entry.host, settings)
        health.zone_check = _zone_verdict_check(health.zone)
        health.dns = validators.dns_check(entry.host, settings)
    for backend in entry.backends:
        health.tcp.append(validators.tcp_check(backend))
    if entry.host:
        health.https = validators.https_check(entry.host, settings)
    return health


def check_by_name(name: str, settings: Settings) -> ServiceHealth:
    scan = parser.scan(settings.dynamic_dir)
    entry = scan.router(name)
    if entry is None:
        raise OperationError(f"no router named {name!r} in {settings.dynamic_dir}")
    return check_service(entry, settings)


def check_all(settings: Settings) -> list[ServiceHealth]:
    scan = parser.scan(settings.dynamic_dir)
    return [check_service(e, settings) for e in scan.routers]
