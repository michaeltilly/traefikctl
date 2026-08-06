"""Render and atomically write Traefik dynamic-config service files."""

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import jinja2
import yaml

from ..config import Settings

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    keep_trailing_newline=True,
    undefined=jinja2.StrictUndefined,
)


class GeneratorError(Exception):
    pass


@dataclass
class ServiceSpec:
    name: str
    backend: str
    host: str | None = None  # defaults to NAME.<domain_suffix>
    insecure: bool = False
    middlewares: list[str] = field(default_factory=list)

    def fqdn(self, settings: Settings) -> str:
        return self.host or f"{self.name}.{settings.domain_suffix}"


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def render(spec: ServiceSpec, settings: Settings) -> str:
    """Render the service YAML and verify it parses before returning it."""
    if not valid_name(spec.name):
        raise GeneratorError(
            f"invalid name {spec.name!r}: lowercase alphanumeric and hyphens only"
        )
    content = _env.get_template("service.yml.j2").render(
        name=spec.name,
        host=spec.fqdn(settings),
        backend=spec.backend,
        insecure=spec.insecure,
        middlewares=spec.middlewares,
        entrypoint=settings.entrypoint,
        cert_resolver=settings.cert_resolver,
        insecure_transport=settings.insecure_transport,
    )
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as e:  # template bug — never write it
        raise GeneratorError(f"rendered YAML does not parse: {e}") from e
    if spec.name not in parsed.get("http", {}).get("routers", {}):
        raise GeneratorError("rendered YAML is missing the expected router")
    return content


def atomic_write(path: Path, content: str) -> None:
    """Write via a temp file + rename so the Traefik watcher never sees a
    partial file. The temp file has no .yml extension, so the file provider
    ignores it entirely."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)  # mkstemp defaults to 0600; match the house files
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def ensure_transports_file(settings: Settings) -> None:
    """Make sure the shared insecure serversTransport exists.

    Creates transports.yml if absent. If the file exists but lacks the
    transport, we refuse to modify a file we didn't create and tell the
    caller to fix it by hand.
    """
    path = settings.dynamic_dir / settings.transports_file
    if not path.exists():
        content = (
            "http:\n"
            "  serversTransports:\n"
            f"    {settings.insecure_transport}:\n"
            "      insecureSkipVerify: true\n"
        )
        atomic_write(path, content)
        return
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise GeneratorError(f"{path} exists but is not valid YAML: {e}") from e
    transports = (data.get("http") or {}).get("serversTransports") or {}
    if settings.insecure_transport not in transports:
        raise GeneratorError(
            f"{path} exists but does not define {settings.insecure_transport!r}; "
            "add it manually — traefikctl will not edit files it did not create"
        )


def write_service(
    spec: ServiceSpec, settings: Settings, force: bool = False
) -> Path:
    """Render and write NAME.yml. Refuses to overwrite unless force; on
    force the previous file is backed up to NAME.yml.bak first."""
    path = settings.dynamic_dir / f"{spec.name}.yml"
    if path.exists() and not force:
        raise GeneratorError(f"{path} already exists (use force to overwrite)")
    content = render(spec, settings)
    if spec.insecure:
        ensure_transports_file(settings)
    if path.exists():
        shutil.copy2(path, path.with_suffix(".yml.bak"))
    atomic_write(path, content)
    return path
