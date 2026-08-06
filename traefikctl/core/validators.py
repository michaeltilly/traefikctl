"""Pre-flight and post-flight network checks: DNS, TCP reachability, and a
live HTTPS probe through the ingress with certificate inspection."""

import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import dns.exception
import dns.resolver

from ..config import Settings


@dataclass
class CheckResult:
    ok: bool
    level: str  # "ok" | "warn" | "block"
    summary: str
    detail: str = ""


@dataclass
class HttpsResult:
    ok: bool
    summary: str
    status_code: int | None = None
    cert_issuer: str = ""
    cert_subject: str = ""
    hints: list[str] = field(default_factory=list)


def dns_check(host: str, settings: Settings) -> CheckResult:
    """Resolve host against the authoritative Technitium server and require
    the answer to be the ingress IP (i.e. the wildcard, not an override)."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [settings.dns_server]
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(host, "A")
        addrs = sorted(rr.address for rr in answers)
    except dns.resolver.NXDOMAIN:
        return CheckResult(
            False,
            "block",
            f"{host} does not resolve at {settings.dns_server}",
            "Expected the wildcard *.{suffix} record to answer. Check the "
            "Technitium zone.".format(suffix=settings.domain_suffix),
        )
    except (dns.exception.DNSException, OSError) as e:
        return CheckResult(
            False,
            "warn",
            f"DNS lookup against {settings.dns_server} failed: {e}",
            "Could not verify where the name points.",
        )
    if addrs == [settings.ingress_ip]:
        return CheckResult(True, "ok", f"{host} → {settings.ingress_ip} (ingress)")
    return CheckResult(
        False,
        "block",
        f"{host} resolves to {', '.join(addrs)} — NOT the ingress "
        f"({settings.ingress_ip})",
        "A specific A record in Technitium overrides the wildcard and traffic "
        "will BYPASS Traefik. Fix: delete that A record for "
        f"{host!r} in the Technitium zone {settings.domain_suffix!r} "
        f"(http://{settings.dns_server}:5380), then retry.",
    )


def _backend_host_port(backend: str) -> tuple[str, int]:
    parts = urlsplit(backend)
    if not parts.hostname:
        raise ValueError(f"backend URL {backend!r} has no host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.hostname, port


def backend_url_valid(backend: str) -> str | None:
    """Return an error message if the backend URL is unusable, else None."""
    parts = urlsplit(backend)
    if parts.scheme not in ("http", "https"):
        return f"backend URL must start with http:// or https:// (got {backend!r})"
    try:
        _backend_host_port(backend)
    except ValueError as e:
        return str(e)
    return None


def tcp_check(backend: str, timeout: float = 3.0) -> CheckResult:
    """TCP connect to the backend. Unreachable is a warning, not a failure —
    the service may simply not be up yet."""
    try:
        host, port = _backend_host_port(backend)
    except ValueError as e:
        return CheckResult(False, "block", str(e))
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as e:
        return CheckResult(
            False,
            "warn",
            f"backend {host}:{port} not reachable ({e})",
            "The route will be created but will 502 until the backend is up.",
        )
    return CheckResult(True, "ok", f"backend {host}:{port} accepts connections")


def https_check(host: str, settings: Settings, timeout: float = 6.0) -> HttpsResult:
    """GET https://host by connecting straight to the ingress IP with SNI set
    to the hostname — independent of local DNS — and report the status code
    and the served certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((settings.ingress_ip, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                issuer, subject = _cert_names(der)
                request = (
                    f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                    "User-Agent: traefikctl\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(request.encode())
                status = _read_status(tls, timeout)
    except (OSError, ssl.SSLError) as e:
        return HttpsResult(
            False,
            f"HTTPS probe to {settings.ingress_ip}:443 (SNI {host}) failed: {e}",
            hints=_failure_hints(),
        )
    ok = status is not None and status < 500
    result = HttpsResult(
        ok,
        f"https://{host} answered HTTP {status}"
        if status is not None
        else f"https://{host}: TLS OK but no HTTP status read",
        status_code=status,
        cert_issuer=issuer,
        cert_subject=subject,
    )
    if not ok:
        result.hints = _failure_hints()
    return result


def _failure_hints() -> list[str]:
    return [
        "A specific Technitium A record may override the wildcard and bypass "
        "Traefik — check DNS for the name.",
        "The backend may be down — Traefik answers 502/504 when it can't "
        "reach the service.",
        "Traefik may have rejected the YAML — check `docker logs traefik` "
        "on ingress01.",
    ]


def _cert_names(der: bytes | None) -> tuple[str, str]:
    if not der:
        return "", ""
    try:
        import tempfile

        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
            f.write(pem)
            f.flush()
            info = ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
        issuer = ", ".join(
            f"{k}={v}" for rdn in info.get("issuer", ()) for k, v in rdn
        )
        subject = ", ".join(
            f"{k}={v}" for rdn in info.get("subject", ()) for k, v in rdn
        )
        return issuer, subject
    except Exception:
        return "", ""


def _read_status(tls: ssl.SSLSocket, timeout: float) -> int | None:
    tls.settimeout(timeout)
    data = b""
    try:
        while b"\r\n" not in data and len(data) < 1024:
            chunk = tls.recv(256)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return None
