# traefikctl — TillyNet service publishing tool

Publishes services behind the Traefik ingress on `ingress01` by generating
dynamic-config YAML files into `/opt/traefik/config/dynamic/` (hot-reloaded —
no restart ever needed). Web UI first, CLI included. Does **zero** certificate
work: the `letsencrypt` wildcard for `*.shire.tillynet.com` covers every name.

## Web UI

**https://traefikctl.shire.tillynet.com** (behind the `dash-auth` basicauth
middleware — same credentials as the Traefik dashboard).

- **Services** — every router found in the dynamic dir: name, host, backend,
  insecure-transport, middlewares, source file. Hand-written files are parsed
  tolerantly; malformed ones are flagged, never fatal.
- **Add service** — fill in name + backend URL → **Run pre-flight checks**
  (name/collision check, DNS against Technitium, TCP probe of the backend,
  YAML preview) → **Confirm** writes the file atomically, then a post-flight
  probe reports the HTTP status and served certificate.
- **Service detail** — per-service health check (DNS / TCP / HTTPS + cert) and
  removal with type-the-name confirmation. Routers living in files traefikctl
  didn't create can't be removed from the UI — edit those by hand.

Pre-flight blocks (overridable with **Force**, except collisions):
- a specific Technitium A record overriding the wildcard — traffic would
  bypass Traefik; the fix is deleting that record at `http://10.10.30.30:5380`
- `NAME.yml` already exists (Force backs it up to `NAME.yml.bak` first)
- a router of the same name in **another** file — never overridable

An unreachable backend is only a warning: the route is created and will 502
until the service comes up.

## CLI

Runs anywhere the library is installed; on ingress01 the easiest path is
through the container:

```bash
docker exec traefikctl python -m traefikctl.cli list
```

```bash
docker exec traefikctl python -m traefikctl.cli add jellyfin --backend http://10.10.30.5:8096
```

```bash
docker exec traefikctl python -m traefikctl.cli add proxmox --backend https://10.10.10.40:8006 --insecure
```

```bash
docker exec traefikctl python -m traefikctl.cli add app --backend http://10.10.30.7:3000 --middleware authentik-forward-auth --dry-run
```

```bash
docker exec traefikctl python -m traefikctl.cli check --all
```

```bash
docker exec traefikctl python -m traefikctl.cli remove jellyfin --yes
```

- `--insecure` adds `serversTransport: insecure-backend` for HTTPS backends
  with self-signed certs (Proxmox, OPNsense…). `transports.yml` is created if
  missing; if it exists but lacks the transport, the tool refuses and tells
  you to add it by hand.
- `--host FQDN` overrides the default `NAME.shire.tillynet.com`.
- `--dry-run` prints the YAML and writes nothing.
- `--force` overwrites an existing `NAME.yml` (after backing it up) and
  overrides a DNS block.

## Deployment

```bash
docker compose up -d --build
```

The compose file enforces the security guardrails:

- **No `ports:`** — the app is an admin surface, reachable only through
  Traefik with the `dash-auth` middleware on its router.
- **Exactly one bind mount** — `/opt/traefik/config/dynamic`. Never
  `/opt/traefik` root, never the Docker socket, never `acme.json`/`.env`.
- Runs as `1000:1000` (tillyadmin) so generated files match existing
  ownership; the app refuses to start if the mount is absent or unwritable.
- Config via environment variables (`TRAEFIKCTL_DYNAMIC_DIR`,
  `TRAEFIKCTL_DOMAIN_SUFFIX`, `TRAEFIKCTL_INGRESS_IP`,
  `TRAEFIKCTL_CERT_RESOLVER`, `TRAEFIKCTL_ENTRYPOINT`,
  `TRAEFIKCTL_DNS_SERVER`) — TillyNet values are the defaults.

The project currently lives at `/home/tillyadmin/traefikctl` (creating
`/opt/traefikctl` needs a one-time sudo). To move it to the planned location:

```bash
sudo mkdir -p /opt/traefikctl && sudo chown tillyadmin:tillyadmin /opt/traefikctl && cp -r /home/tillyadmin/traefikctl/. /opt/traefikctl/ && cd /opt/traefikctl && docker compose up -d
```

## Guardrails (hard rules baked into the code)

- Never touches `traefik.yml`, `docker-compose.yml`, `.env`, or `acme.json`
- Never restarts the Traefik container — the file provider hot-reloads
- Never does ACME/certificate operations
- Never runs as root or needs sudo
- Never modifies files it didn't create (read-only parsing only; sole
  exception: creating `transports.yml` when absent)
- Atomic writes (temp file without a `.yml` extension + rename) — Traefik's
  watcher never sees a partial file
- Removal refuses multi-router files and files it didn't create

## Tests

```bash
docker run --rm -v $PWD/tests:/app/tests:ro traefikctl:latest sh -c "pip -q install pytest && python -m pytest tests -q"
```

27 unit tests cover template rendering against golden files, name validation,
atomic-write crash safety, force/backup, transports handling, tolerant
parsing, collision detection, and remove guardrails.

## Layout

```
traefikctl/
  config.py            env-driven settings (TillyNet defaults)
  templates/service.yml.j2   the one YAML template (house style)
  core/
    generator.py       render, validate name, atomic write, transports
    parser.py          tolerant scan of every file in the dynamic dir
    validators.py      DNS (Technitium), TCP probe, HTTPS + cert inspection
    operations.py      preflight → write → postflight, list/remove/check
  web/                 FastAPI + Jinja2 server-rendered UI
  cli.py               typer wrapper
tests/                 pytest suite + golden files
```
