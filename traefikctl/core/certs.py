"""Certificate health for this ingress: what it is actually serving, and
whether automatic renewal can work.

Two questions, answered with read-only probes only (no new mounts, no
Docker socket, no acme.json, no ACME credentials):

1. Expiry — connect to the ingress with SNI for each published host and
   read the certificate it really serves. Issuer-agnostic.
2. Renewal health — a cert that is inside the renewal window but not yet
   replaced means renewal is failing. Plus the dependency checks that
   would have caught the 2026-11 outage weeks early: port-53
   interception, which public zone an ACME client would pick for the
   challenge, and ACME directory reachability.
"""

import logging
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from ..config import Settings
from . import parser

log = logging.getLogger("traefikctl.certs")

# TEST-NET-1 (RFC 5737): nothing should ever answer DNS here. A reply means
# something on the path is intercepting port 53.
CANARY_IP = "192.0.2.53"
CANARY_TIMEOUT = 2.0
PROBE_TIMEOUT = 5.0
# Renewal should land within this many days of the window opening; past
# that, treat the cert as "renewal overdue".
RENEWAL_GRACE_DAYS = 2
TRAEFIK_DEFAULT_CERT = "TRAEFIK DEFAULT CERT"

LEVELS = ("ok", "warn", "crit")


def worst(levels) -> str:
    rank = {lvl: i for i, lvl in enumerate(LEVELS)}
    return max(levels, key=lambda lvl: rank[lvl], default="ok")


@dataclass
class ServedCert:
    """The certificate the ingress served for one or more hostnames."""

    hosts: list[str]
    error: str = ""
    issuer: str = ""
    subject: str = ""
    sans: list[str] = field(default_factory=list)
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None

    @property
    def is_default(self) -> bool:
        return TRAEFIK_DEFAULT_CERT in self.subject or TRAEFIK_DEFAULT_CERT in self.issuer

    def days_remaining(self, now: datetime) -> float | None:
        if self.not_after is None:
            return None
        return (self.not_after - now).total_seconds() / 86400


@dataclass
class Finding:
    level: str  # ok | warn | crit
    summary: str
    detail: str = ""


@dataclass
class CertReport:
    generated_at: datetime
    certs: list[ServedCert] = field(default_factory=list)
    expiry: list[Finding] = field(default_factory=list)
    renewal: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        return worst(f.level for f in self.expiry + self.renewal)

    @property
    def expiry_status(self) -> str:
        return worst(f.level for f in self.expiry)

    @property
    def renewal_status(self) -> str:
        return worst(f.level for f in self.renewal)

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.expiry + self.renewal if f.level != "ok"]

    def to_dict(self) -> dict:
        def iso(d):
            return d.isoformat() if d else None

        return {
            "generated_at": iso(self.generated_at),
            "status": self.status,
            "certs": [
                {
                    "hosts": c.hosts,
                    "issuer": c.issuer,
                    "subject": c.subject,
                    "sans": c.sans,
                    "not_before": iso(c.not_before),
                    "not_after": iso(c.not_after),
                    "days_remaining": None
                    if c.not_after is None
                    else round(c.days_remaining(self.generated_at), 1),
                    "error": c.error,
                }
                for c in self.certs
            ],
            "expiry": [vars(f) for f in self.expiry],
            "renewal": [vars(f) for f in self.renewal],
        }


# ---------------------------------------------------------------- probes


def _decode_der(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
        f.write(pem)
        f.flush()
        return ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]


def _cert_time(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def _rdn_text(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def probe_cert(host: str, settings: Settings) -> ServedCert:
    """Fetch the cert the ingress serves for host (SNI), straight from the
    ingress IP so local DNS can't change the answer."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((settings.ingress_ip, 443), timeout=PROBE_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        info = _decode_der(der)
    except (OSError, ssl.SSLError, ValueError) as e:
        return ServedCert(hosts=[host], error=f"{type(e).__name__}: {e}")
    return ServedCert(
        hosts=[host],
        issuer=_rdn_text(info.get("issuer", ())),
        subject=_rdn_text(info.get("subject", ())),
        sans=[v for k, v in info.get("subjectAltName", ()) if k == "DNS"],
        serial=str(info.get("serialNumber", "")),
        not_before=_cert_time(info["notBefore"]) if "notBefore" in info else None,
        not_after=_cert_time(info["notAfter"]) if "notAfter" in info else None,
    )


def probe_interception(settings: Settings) -> tuple[bool | None, str]:
    """(True, detail) if port 53 is intercepted, (False, ..) if clean,
    (None, error) if the probe itself failed oddly."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [CANARY_IP]
    r.lifetime = CANARY_TIMEOUT
    try:
        ans = r.resolve(settings.domain_suffix, "SOA", raise_on_no_answer=False)
    except dns.resolver.LifetimeTimeout:
        return False, f"no answer from {CANARY_IP} (expected)"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        # Any DNS response at all — even NXDOMAIN/SERVFAIL — means a server
        # on the path answered for an address that has none.
        return True, f"{CANARY_IP} returned a DNS error response"
    except (dns.exception.DNSException, OSError) as e:
        return None, str(e)
    soa = ""
    if ans.rrset is not None:
        soa = " — answered SOA " + str(ans.rrset[0]).split()[0]
    return True, f"{CANARY_IP} answered{soa}"


def probe_challenge_zone(settings: Settings) -> tuple[str | None, str]:
    """The zone an ACME DNS-01 client would pick for the challenge record,
    found the way lego does it: SOA walk through the public resolvers."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(settings.public_resolvers)
    r.lifetime = 6.0
    name = f"_acme-challenge.{settings.domain_suffix}"
    try:
        zone = dns.resolver.zone_for_name(name, resolver=r)
    except (dns.exception.DNSException, OSError) as e:
        return None, str(e)
    return zone.to_text(omit_final_dot=True), ""


def probe_acme_directory(settings: Settings) -> tuple[bool, str]:
    try:
        resp = httpx.get(settings.acme_directory_url, timeout=PROBE_TIMEOUT)
        resp.raise_for_status()
        if "newOrder" in resp.json():
            return True, ""
        return False, "directory JSON has no newOrder endpoint"
    except (httpx.HTTPError, ValueError) as e:
        return False, str(e)


# ------------------------------------------------------------ evaluation


def check_hosts(settings: Settings) -> list[str]:
    """Every published host on this ingress plus any extra configured names
    (label-defined routers such as the dashboard aren't in the dynamic dir)."""
    hosts = [r.host for r in parser.scan(settings.dynamic_dir).routers if r.host]
    hosts += settings.cert_check_hosts
    seen, out = set(), []
    for h in hosts:
        key = h.lower()
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def group_certs(served: list[ServedCert]) -> list[ServedCert]:
    """Collapse per-host probes into distinct certificates. Failed probes
    stay separate so each failing host is visible."""
    groups: dict[tuple, ServedCert] = {}
    out: list[ServedCert] = []
    for s in served:
        if s.error:
            out.append(s)
            continue
        key = (s.serial, s.issuer, s.not_after)
        if key in groups:
            groups[key].hosts.extend(s.hosts)
        else:
            groups[key] = s
            out.append(s)
    return out


def _fmt_date(d: datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M UTC")


def evaluate_expiry(certs: list[ServedCert], settings: Settings, now: datetime) -> list[Finding]:
    findings = []
    for c in certs:
        hosts = ", ".join(c.hosts)
        if c.error:
            findings.append(Finding(
                "crit", f"could not read the certificate served for {hosts}", c.error))
            continue
        if c.is_default:
            findings.append(Finding(
                "crit", f"{hosts}: serving Traefik's self-signed default certificate",
                "No issued certificate covers this name — clients get a browser "
                "warning. Issuance has never succeeded or the cert was lost."))
            continue
        days = c.days_remaining(now)
        when = _fmt_date(c.not_after)
        if days < 0:
            findings.append(Finding(
                "crit", f"EXPIRED {abs(days):.1f} days ago ({when})",
                f"Served for {hosts}. Issuer: {c.issuer}."))
        elif days < settings.cert_crit_days:
            findings.append(Finding(
                "crit", f"expires in {days:.1f} days ({when})",
                f"Under the {settings.cert_crit_days}-day critical threshold. "
                f"Served for {hosts}. Issuer: {c.issuer}."))
        elif days < settings.cert_warn_days:
            findings.append(Finding(
                "warn", f"expires in {days:.1f} days ({when})",
                f"Under the {settings.cert_warn_days}-day warning threshold. "
                f"Served for {hosts}. Issuer: {c.issuer}."))
        else:
            findings.append(Finding(
                "ok", f"{days:.0f} days remaining (expires {when})",
                f"Served for {hosts}. Issuer: {c.issuer}."))
    return findings


def evaluate_issuer(certs: list[ServedCert], settings: Settings) -> list[Finding]:
    """Flag certificates whose issuer isn't the expected ACME CA. A foreign
    issuer (e.g. DigiCert) means something other than this Traefik's
    pipeline is answering on 443; a STAGING issuer means a test cert leaked
    into production. Unreadable/default certs are already reported by
    evaluate_expiry and are skipped here."""
    expected = settings.cert_expected_issuer.strip()
    findings = []
    checked = 0
    for c in certs:
        if c.error or c.is_default:
            continue
        checked += 1
        hosts = ", ".join(c.hosts)
        if "STAGING" in c.issuer.upper():
            findings.append(Finding(
                "crit", f"{hosts}: serving a Let's Encrypt STAGING certificate",
                f"Issuer: {c.issuer}. Staging certs are untrusted by browsers — "
                "a staging caServer was likely left in the Traefik resolver."))
        elif expected and expected.lower() not in c.issuer.lower():
            findings.append(Finding(
                "warn", f"{hosts}: unexpected issuer (expected {expected})",
                f"Issuer: {c.issuer}. Something other than this ingress's ACME "
                "pipeline may be answering on 443 for these names — check DNS "
                "and what is listening before trusting the expiry date."))
    if checked and not findings and expected:
        findings.append(Finding(
            "ok", f"issuer is {expected} on all {checked} served certificate"
            f"{'s' if checked != 1 else ''}"))
    return findings


def evaluate_renewal(
    certs: list[ServedCert],
    interception: tuple[bool | None, str],
    zone: tuple[str | None, str],
    acme: tuple[bool, str],
    settings: Settings,
    now: datetime,
) -> list[Finding]:
    findings = []

    # 1. Overdue: inside the renewal window but not replaced.
    window = settings.cert_renew_window_days
    overdue_at = window - RENEWAL_GRACE_DAYS
    readable = [c for c in certs if not c.error and not c.is_default and c.not_after]
    late = [c for c in readable if c.days_remaining(now) < overdue_at]
    if late:
        c = min(late, key=lambda c: c.not_after)
        days = c.days_remaining(now)
        failing_for = window - days
        findings.append(Finding(
            "crit" if days < settings.cert_crit_days else "warn",
            f"renewal overdue — should have renewed ~{failing_for:.0f} days ago",
            f"Automatic renewal starts {window} days before expiry; this cert "
            f"has {days:.1f} days left and has not been replaced, so renewal "
            "is failing. Check the Traefik logs for 'Error renewing'."))
    elif readable:
        nxt = min(readable, key=lambda c: c.not_after)
        due = nxt.days_remaining(now) - window
        findings.append(Finding(
            "ok", "renewal on schedule",
            f"Next automatic renewal due in ~{max(due, 0):.0f} days "
            f"({window} days before expiry)."))

    # 2. Port-53 interception canary.
    intercepted, detail = interception
    if intercepted is True:
        findings.append(Finding(
            "crit", "DNS is being intercepted on port 53",
            f"{detail}. Something on the network path (e.g. a gateway "
            "ad-blocking / content-filtering / forced-DNS feature) answers DNS "
            "meant for public resolvers. DNS-01 renewal cannot see Cloudflare "
            "and will fail. Exempt this ingress from the redirect."))
    elif intercepted is False:
        findings.append(Finding("ok", "no port-53 interception", detail))
    else:
        findings.append(Finding("warn", "interception canary inconclusive", detail))

    # 3. Which zone an ACME client would write the challenge into.
    found, err = zone
    expected = settings.acme_zone
    if found is None:
        findings.append(Finding(
            "warn", "could not determine the challenge zone via public DNS", err))
    elif found.lower() == expected.lower():
        findings.append(Finding(
            "ok", f"challenge zone resolves to {found}",
            f"Public resolvers ({', '.join(settings.public_resolvers)}) see "
            f"_acme-challenge.{settings.domain_suffix} inside {found}, where "
            "the DNS-01 provider writes it."))
    elif found.lower() == settings.domain_suffix.lower():
        findings.append(Finding(
            "crit", f"challenge zone resolves to the internal zone {found}",
            f"Public resolvers report {found} as its own zone, so the ACME "
            f"client looks for a provider zone named {found} instead of "
            f"{expected} and the order fails ('zone could not be found'). "
            "Usually caused by DNS interception or an accidental public "
            "delegation."))
    else:
        findings.append(Finding(
            "warn", f"challenge zone resolves to {found}, expected {expected}",
            "The DNS-01 provider may not manage this zone."))

    # 4. ACME directory reachable.
    ok, err = acme
    if ok:
        findings.append(Finding(
            "ok", "ACME directory reachable", settings.acme_directory_url))
    else:
        findings.append(Finding(
            "crit", "ACME directory unreachable",
            f"{settings.acme_directory_url}: {err}"))
    return findings


def build_report(settings: Settings, now: datetime | None = None) -> CertReport:
    now = now or datetime.now(timezone.utc)
    served = [probe_cert(h, settings) for h in check_hosts(settings)]
    certs = group_certs(served)
    report = CertReport(generated_at=now, certs=certs)
    if not certs:
        report.expiry.append(Finding(
            "warn", "no hostnames to check",
            "Nothing is published and TRAEFIKCTL_CERT_CHECK_HOSTS is empty."))
    else:
        report.expiry = evaluate_expiry(certs, settings, now)
        report.expiry += evaluate_issuer(certs, settings)
    report.renewal = evaluate_renewal(
        certs,
        probe_interception(settings),
        probe_challenge_zone(settings),
        probe_acme_directory(settings),
        settings,
        now,
    )
    return report


# ----------------------------------------------------------------- cache


class CertMonitor:
    """Holds the latest report; refreshed in the background so page loads
    never wait on network probes."""

    def __init__(self, settings: Settings, interval: float = 900.0):
        self.settings = settings
        self.interval = interval
        self._report: CertReport | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def report(self) -> CertReport | None:
        return self._report

    def refresh(self) -> CertReport:
        with self._lock:
            try:
                report = build_report(self.settings)
            except Exception as e:  # never let a probe bug kill the UI
                log.exception("certificate check failed")
                report = CertReport(
                    generated_at=datetime.now(timezone.utc),
                    expiry=[Finding("warn", "certificate check crashed", str(e))],
                )
            self._report = report
        level = {"ok": logging.INFO, "warn": logging.WARNING, "crit": logging.ERROR}[report.status]
        log.log(level, "certificate check: %s (%s)", report.status.upper(),
                "; ".join(f.summary for f in report.problems) or "all checks passed")
        return report

    def start(self) -> None:
        if self._thread is not None:
            return

        def loop():
            while True:
                self.refresh()
                time.sleep(self.interval)

        self._thread = threading.Thread(target=loop, name="cert-monitor", daemon=True)
        self._thread.start()
