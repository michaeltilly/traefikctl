"""Tolerant parser for every YAML file in the dynamic directory.

Hand-written files that don't follow traefikctl conventions must still be
readable: we extract what we can and flag what we can't.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HOST_RE = re.compile(r"Host\(`([^`]+)`\)")


@dataclass
class RouterEntry:
    name: str
    file: Path
    rule: str = ""
    host: str = ""
    service: str = ""
    middlewares: list[str] = field(default_factory=list)
    backends: list[str] = field(default_factory=list)
    insecure_transport: str = ""


@dataclass
class ScanResult:
    routers: list[RouterEntry] = field(default_factory=list)
    transports: dict[str, Path] = field(default_factory=dict)
    errors: dict[Path, str] = field(default_factory=dict)  # file -> problem

    def router(self, name: str) -> RouterEntry | None:
        for r in self.routers:
            if r.name == name:
                return r
        return None

    def routers_in(self, file: Path) -> list[RouterEntry]:
        return [r for r in self.routers if r.file == file]


def _parse_file(path: Path, result: ScanResult) -> None:
    try:
        data = yaml.safe_load(path.read_text())
    except (yaml.YAMLError, OSError) as e:
        result.errors[path] = f"unparseable: {e}"
        return
    if data is None:
        return
    if not isinstance(data, dict):
        result.errors[path] = "not a mapping at top level"
        return
    http = data.get("http")
    if not isinstance(http, dict):
        return  # no http section (tcp/udp or unrelated file) — nothing to list
    services = http.get("services") if isinstance(http.get("services"), dict) else {}
    for tname in (http.get("serversTransports") or {}) if isinstance(
        http.get("serversTransports"), dict
    ) else {}:
        result.transports[tname] = path
    routers = http.get("routers")
    if not isinstance(routers, dict):
        return
    for rname, rdef in routers.items():
        if not isinstance(rdef, dict):
            result.errors[path] = f"router {rname!r} is not a mapping"
            continue
        entry = RouterEntry(name=str(rname), file=path)
        entry.rule = str(rdef.get("rule", ""))
        m = HOST_RE.search(entry.rule)
        entry.host = m.group(1) if m else ""
        entry.service = str(rdef.get("service", ""))
        mws = rdef.get("middlewares")
        if isinstance(mws, list):
            entry.middlewares = [str(m) for m in mws]
        sdef = services.get(entry.service)
        if isinstance(sdef, dict):
            lb = sdef.get("loadBalancer")
            if isinstance(lb, dict):
                entry.insecure_transport = str(lb.get("serversTransport") or "")
                servers = lb.get("servers")
                if isinstance(servers, list):
                    entry.backends = [
                        str(s.get("url"))
                        for s in servers
                        if isinstance(s, dict) and s.get("url")
                    ]
        result.routers.append(entry)


def scan(dynamic_dir: Path) -> ScanResult:
    result = ScanResult()
    if not dynamic_dir.is_dir():
        result.errors[dynamic_dir] = "dynamic directory does not exist"
        return result
    for path in sorted(dynamic_dir.iterdir()):
        if path.suffix in (".yml", ".yaml") and path.is_file():
            _parse_file(path, result)
    return result
