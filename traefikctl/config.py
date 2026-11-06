"""Runtime settings, overridable via environment variables.

Defaults are the TillyNet ingress01 values; the Docker deployment overrides
dynamic_dir to the container-side mount point.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

_FALSY = {"false", "0", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() not in _FALSY


def _env_list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.split(",") if p.strip()]


@dataclass
class Settings:
    dynamic_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("TRAEFIKCTL_DYNAMIC_DIR", "/opt/traefik/config/dynamic")
        )
    )
    domain_suffix: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_DOMAIN_SUFFIX", "shire.tillynet.com"
        )
    )
    ingress_ip: str = field(
        default_factory=lambda: os.environ.get("TRAEFIKCTL_INGRESS_IP", "10.10.30.4")
    )
    cert_resolver: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_CERT_RESOLVER", "letsencrypt"
        )
    )
    entrypoint: str = field(
        default_factory=lambda: os.environ.get("TRAEFIKCTL_ENTRYPOINT", "websecure")
    )
    dns_server: str = field(
        default_factory=lambda: os.environ.get("TRAEFIKCTL_DNS_SERVER", "10.10.30.30")
    )
    insecure_transport: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_INSECURE_TRANSPORT", "insecure-backend"
        )
    )
    transports_file: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_TRANSPORTS_FILE", "transports.yml"
        )
    )
    # Ingress mode. True (ingress01): the zone wildcard points at THIS
    # ingress, so a name with no specific record is covered. False
    # (ingress02): the wildcard points at the OTHER ingress, so every
    # published name requires a specific A record -> this ingress IP.
    wildcard_covers_ingress: bool = field(
        default_factory=lambda: _env_bool("TRAEFIKCTL_WILDCARD_COVERS_INGRESS", True)
    )
    # Display identity for the UI header and log hints, so two instances
    # are unmistakable in adjacent browser tabs.
    instance_name: str = field(
        default_factory=lambda: os.environ.get("TRAEFIKCTL_INSTANCE_NAME", "ingress01")
    )
    # Certificate monitor (expiry + renewal health). Read-only probes.
    cert_monitor: bool = field(
        default_factory=lambda: _env_bool("TRAEFIKCTL_CERT_MONITOR", True)
    )
    # Extra hostnames to probe beyond the dynamic-dir routers — e.g. the
    # dashboard and traefikctl itself, which are Docker-label routers.
    cert_check_hosts: list[str] = field(
        default_factory=lambda: _env_list("TRAEFIKCTL_CERT_CHECK_HOSTS", "")
    )
    cert_warn_days: int = field(
        default_factory=lambda: int(os.environ.get("TRAEFIKCTL_CERT_WARN_DAYS", "21"))
    )
    cert_crit_days: int = field(
        default_factory=lambda: int(os.environ.get("TRAEFIKCTL_CERT_CRIT_DAYS", "7"))
    )
    # Organization expected in the served certificate's issuer. Anything
    # else (e.g. a DigiCert cert) means something other than this Traefik's
    # ACME pipeline is answering. Empty disables the check. A Let's Encrypt
    # STAGING issuer is always critical.
    cert_expected_issuer: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_CERT_EXPECTED_ISSUER", "Let's Encrypt"
        )
    )
    # Traefik renews this many days before expiry (30 for 90-day certs).
    cert_renew_window_days: int = field(
        default_factory=lambda: int(
            os.environ.get("TRAEFIKCTL_CERT_RENEW_WINDOW_DAYS", "30")
        )
    )
    # The public DNS zone the DNS-01 provider writes challenge records into.
    # Default: the domain suffix minus its first label (shire.tillynet.com
    # -> tillynet.com).
    acme_zone: str = field(
        default_factory=lambda: os.environ.get("TRAEFIKCTL_ACME_ZONE")
        or os.environ.get("TRAEFIKCTL_DOMAIN_SUFFIX", "shire.tillynet.com").split(".", 1)[-1]
    )
    public_resolvers: list[str] = field(
        default_factory=lambda: _env_list("TRAEFIKCTL_PUBLIC_RESOLVERS", "1.1.1.1,8.8.8.8")
    )
    acme_directory_url: str = field(
        default_factory=lambda: os.environ.get(
            "TRAEFIKCTL_ACME_DIRECTORY",
            "https://acme-v02.api.letsencrypt.org/directory",
        )
    )
    # Technitium integration — absence of the token cleanly disables it.
    technitium_url: str = field(
        default_factory=lambda: os.environ.get(
            "TECHNITIUM_URL", "http://10.10.30.30:5380"
        )
    )
    technitium_zone: str = field(
        default_factory=lambda: os.environ.get(
            "TECHNITIUM_ZONE", os.environ.get("TRAEFIKCTL_DOMAIN_SUFFIX", "shire.tillynet.com")
        )
    )
    technitium_token: str = field(
        default_factory=lambda: os.environ.get("TECHNITIUM_API_TOKEN", "")
    )


def get_settings() -> Settings:
    return Settings()
