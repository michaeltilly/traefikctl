"""High-level operations shared by the web UI and the CLI:
preflight -> write -> postflight, plus list / remove / check."""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from . import generator, parser, validators
from .generator import GeneratorError, ServiceSpec
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

    pf.checks.append(validators.dns_check(spec.fqdn(settings), settings))
    pf.checks.append(validators.tcp_check(spec.backend))
    return pf


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
class ServiceHealth:
    entry: parser.RouterEntry
    dns: CheckResult | None = None
    tcp: list[CheckResult] = field(default_factory=list)
    https: HttpsResult | None = None


def check_service(entry: parser.RouterEntry, settings: Settings) -> ServiceHealth:
    health = ServiceHealth(entry=entry)
    if entry.host:
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
