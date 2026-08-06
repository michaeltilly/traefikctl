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
  `TRAEFIKCTL_DNS_SERVER`, `TRAEFIKCTL_WILDCARD_COVERS_INGRESS`,
  `TRAEFIKCTL_INSTANCE_NAME`) — TillyNet ingress01 values are the defaults.

### Ingress modes

One codebase serves both TillyNet ingresses; the difference is how the
zone wildcard relates to the instance, controlled by
`TRAEFIKCTL_WILDCARD_COVERS_INGRESS`:

- **Wildcard mode** (`true`, the default — ingress01, 10.10.30.4): the zone
  wildcard `*.shire.tillynet.com` points at this ingress, so a name with
  **no** specific record is covered and any specific record is an override.
- **Explicit mode** (`false` — ingress02, 10.10.10.4, the management
  ingress): the wildcard points at the *other* ingress, so every published
  name **requires** a specific A record → this ingress IP. Pre-flight
  verdicts invert accordingly: no record now **blocks**, with a guided
  create offered (web pre-flight panel or `add ... --fix-dns` in the CLI)
  that makes the required record `NAME → <ingress IP>` after explicit
  confirmation; an explicit record → this ingress is the required pass state;
  a record pointing elsewhere blocks, with the message distinguishing
  "points at the other ingress (wildcard target)" from "points at a
  device". The guided delete flow and its denylist are identical in both
  modes, and API-unavailable still degrades to the resolution-only check.
  The `/dns` panel additionally classifies records pointing at the wildcard
  target as `other-ingress` and lists published services that are missing
  their required record.

`TRAEFIKCTL_INSTANCE_NAME` sets the header identity so two instances are
unmistakable in adjacent tabs.

Per-ingress environment, the two real deployments:

```yaml
# ingress01 (service ingress) — all defaults; shown explicit for clarity
TRAEFIKCTL_INGRESS_IP: 10.10.30.4
TRAEFIKCTL_DNS_SERVER: 10.10.30.30
TRAEFIKCTL_WILDCARD_COVERS_INGRESS: "true"
TRAEFIKCTL_INSTANCE_NAME: ingress01

# ingress02 (management ingress)
TRAEFIKCTL_INGRESS_IP: 10.10.10.4
TRAEFIKCTL_DNS_SERVER: 10.10.30.30
TRAEFIKCTL_WILDCARD_COVERS_INGRESS: "false"
TRAEFIKCTL_INSTANCE_NAME: ingress02
```

The project currently lives at `/home/tillyadmin/traefikctl` (creating
`/opt/traefikctl` needs a one-time sudo). To move it to the planned location:

```bash
sudo mkdir -p /opt/traefikctl && sudo chown tillyadmin:tillyadmin /opt/traefikctl && cp -r /home/tillyadmin/traefikctl/. /opt/traefikctl/ && cd /opt/traefikctl && docker compose up -d
```

## Technitium integration (optional)

With an API token configured, pre-flight sees the authoritative zone as it
actually is — including **disabled records**, which still occupy a name and
block the wildcard (authoritative NXDOMAIN) while being invisible to a plain
resolution check.

**Provisioning the token** (one-time, in the Technitium UI):
1. Administration → Users → Add User (e.g. `traefikctl-api`)
2. Zones → your zone → Options → Zone Permissions → grant that user
   View/Modify on the zone only
3. Administration → Sessions → Create Token for that user; put it in `.env`
   (copy `.env.example`, `chmod 600 .env`)

**What it adds:**
- Pre-flight classifies the name against the zone: no record (wildcard
  covers it), ingress-aliased duplicate (harmless), enabled record pointing
  elsewhere (conflict — blocks), or disabled record (conflict — blocks, with
  an explanation of the occupancy behavior)
- A **guided fix**: the conflicting record can be deleted from inside the
  pre-flight panel (web) or with `add ... --fix-dns` (CLI), always behind an
  explicit confirmation showing exactly what will be deleted. Post-delete
  messaging quotes the zone's real negative TTL so stale-NXDOMAIN waits are
  expected, not mysterious
- A read-only **DNS panel** (`/dns` in the web UI, `traefikctl dns` in the
  CLI): wildcard health, every record classified (direct-access /
  ingress-aliased / disabled / infra), and warnings when a record shadows a
  published service

**Integration guardrails:**
- Exactly two write operations, both behind an explicit confirmation:
  the guided **delete** (conflict resolution, both modes) and the guided
  **create** (explicit mode only, offered when pre-flight reports a missing
  record). The create is deliberately narrow: always `NAME → <this ingress
  IP>`, TTL 3600 — the target is not caller-supplied, so the tool can only
  ever point a name at itself. Creation is refused for the apex, wildcards,
  `dns1`, names outside the zone, any name that already has records, and
  everywhere in wildcard mode. Records are never modified
- Hard denylist: the wildcard, the zone apex, `dns1`, and all SOA/NS records
  can never be deleted, and record types the tool doesn't understand are
  refused with a pointer to the Technitium console
- All API calls time out at 3 s; if Technitium is down or the token is bad,
  pre-flight degrades to the resolution-only check with a visible "zone
  introspection unavailable" note — DNS being down never blocks publishing
- No token configured → the integration is disabled and the tool behaves
  exactly as before, with zero API traffic (unit-tested)

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
