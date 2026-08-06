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
