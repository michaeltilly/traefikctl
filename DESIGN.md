# traefikctl UI — design plan (control-plane redesign, v1)

Presentation-layer only. No route/core changes; tests stay green untouched.

## Token palette

Dark (default) — cool deep slate, blue-gray undertones:

| token | hex | role |
|---|---|---|
| `--bg0` | `#0e1420` | page |
| `--bg1` | `#141c2b` | surface / card |
| `--bg2` | `#1b2637` | raised / hover / table header |
| `--line` | `#25324a` | hairlines, borders |
| `--ink` | `#dce4f0` | primary text |
| `--ink-mut` | `#8d9ab0` | secondary text |
| `--ink-faint` | `#5d6c84` | tertiary / disabled text |
| `--accent` | `#54a9cf` | interactive affordances + focus only |
| `--ok` | `#41b673` | healthy / pass (semantic only) |
| `--warn` | `#d9a23c` | warning / degraded (semantic only) |
| `--bad` | `#e0635a` | fail / blocked (semantic only) |
| `--off` | `#6b7787` | disabled / unknown (semantic only) |

Light — same hue family, flipped value scale: bg0 `#eef1f6`, bg1 `#ffffff`,
bg2 `#e3e9f1`, line `#cdd6e2`, ink `#1a2534`, ink-mut `#56647a`, ink-faint
`#8b97a9`, accent `#20759e`, ok `#177f47`, warn `#8f6410`, bad `#bb392f`,
off `#75808f`. State colors darkened for AA contrast on white.

Accent rationale: steel cyan sits in the network-tooling tradition (switch
UIs, terminal link colors) without tipping into acid-green hacker cliché;
it is cold enough to stay out of the semantic green/amber/red channel.

## Typefaces

- **Inter** (400/500/600) — chrome, labels, prose.
- **JetBrains Mono** (400/600) — every technical value: hostnames, IPs,
  ports, URLs, filenames, YAML, record types, TTLs, timestamps.
- Self-hosted woff2 (latin subset) in `web/static/fonts/`; zero CDN at
  runtime. `font-variant-numeric: tabular-nums` on all tables and mono.

## Layout concept

- Thin persistent top bar (48px): wordmark `traefikctl` + top-nav
  (Services · Add service · DNS) left; environment identity
  `ingress01 · *.shire.tillynet.com → 10.10.30.4` in mono + theme toggle
  right. Top-nav over sidebar: three sections and one operator do not
  justify a nav rail's cost in horizontal density.
- Content max-width 1200px, compact paddings (8–12px cells), hairline
  tables with `--bg2` header rows, uppercase 11px letter-spaced column
  labels.

## Signature: the verdict ledger

A bordered block that reads like elevated CLI output:

- Header strip: `PRE-FLIGHT` (uppercase, letter-spaced, faint) + target
  fqdn in mono + timestamp right-aligned.
- One row per check, grid `[28px glyph | finding]`: state glyph (`✓ ! ✕ ◌`)
  in a fixed mono column colored by state; finding text with technical
  values in mono; secondary detail line in muted text underneath.
- Blocked rows that carry a guided fix render the action *inside* the row:
  an indented sub-row with the record in mono and the red "Delete record
  in Technitium…" button.
- Left border of the whole ledger tinted by worst state present
  (ok → green, warn → amber, block → red, degraded → amber).
- Post-flight and detail-page health checks reuse the identical component
  (`POST-FLIGHT`, `HEALTH` headers).

## Page one-liners

1. **Services** — dense data table (name / host / backend / TLS / health
   pill / middlewares / file / actions); malformed-files panel as a
   distinct amber warning region; empty state invites first publish.
2. **Add flow** — two-column ≥1100px (form left, help right → ledger
   below); insecure toggle gets one-sentence inline helper; confirm step
   is a visually distinct "about to write NAME.yml" state block with the
   YAML preview; conflicts fixable inline in the ledger.
3. **Detail** — config summary card (all values mono), HEALTH ledger with
   timestamp + "Re-run checks" button.
4. **DNS** — wildcard as highlighted first-class row above the table;
   classification encoded as colored pills; shadowing called out in red;
   degraded state is a calm amber notice bar.
5. **Removal** — type-to-confirm block styled as deliberate friction:
   red-tinted bordered region, mono echo of what will be deleted.
6. **Global** — result pages open with an outcome banner (same verb as the
   button that caused it); errors state what happened + what to do next.

## Self-critique pass (against the brief)

1. *Cliché check:* first accent draft `#58c4e0` was too luminous toward
   "glow dashboard" — dulled to `#54a9cf`/`#20759e`. Dark bg0 kept at
   slate `#0e1420`, not black. No gradients, no glassmorphism, no ambient
   animation. PASS after revision.
2. *Density check:* first layout draft had 16px cell padding and
   card-per-service on the list page — replaced with a true table at
   8–12px cells; cards reserved for the ledger and confirm moments. PASS
   after revision.
3. *Semantic-color discipline:* pills/badges audit — the old UI used a
   warn-colored badge for the insecure transport marker decoratively; in
   the redesign it becomes a neutral mono tag, since an insecure
   transport is configuration, not a degraded state. PASS after revision.
4. *HTMX:* the brief assumes existing HTMX; the codebase has none. Adding
   it would be a functional-layer change — kept server-rendered full-page
   flows (they also survive outages best). Loading states scoped out with
   it. The detail page's "Re-run checks" is a plain GET, timestamped.
5. *Auth-failure page:* basicauth 401 is emitted by Traefik before the app
   is reached; styling it means changing Traefik config — out of scope by
   the prime directive. Documented as a known boundary.

## QA floor

Focus-visible rings (2px accent) on every interactive element; logical tab
order (source order); `prefers-reduced-motion` guard on the two
transitions (ledger row state fade, banner slide); responsive to ~840px
via horizontal-scroll table containers; sentence case; buttons name their
verb. Theme toggle persists via `localStorage`, applied pre-paint in
`<head>` to avoid flash.
