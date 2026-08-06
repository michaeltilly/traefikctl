"""Runtime settings, overridable via environment variables.

Defaults are the TillyNet ingress01 values; the Docker deployment overrides
dynamic_dir to the container-side mount point.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


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
