"""Optional CLI wrapper around the traefikctl core library."""

import logging
import sys

import typer

from .config import get_settings
from .core import operations
from .core.generator import GeneratorError, ServiceSpec

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s"
)

cli = typer.Typer(help="Publish services behind the TillyNet Traefik ingress.")

OK = typer.style("✓", fg=typer.colors.GREEN)
WARN = typer.style("⚠", fg=typer.colors.YELLOW)
BAD = typer.style("✗", fg=typer.colors.RED)

_MARK = {"ok": OK, "warn": WARN, "block": BAD}


def _print_check(c) -> None:
    typer.echo(f"  {_MARK[c.level]} {c.summary}")
    if c.detail:
        typer.echo(f"      {c.detail}")


@cli.command()
def add(
    name: str,
    backend: str = typer.Option(..., "--backend", help="Backend URL, e.g. http://10.10.30.5:8096"),
    host: str = typer.Option("", "--host", help="FQDN override (default NAME.<suffix>)"),
    insecure: bool = typer.Option(False, "--insecure", help="Backend has a self-signed cert"),
    middleware: str = typer.Option("", "--middleware", help="Comma-separated middleware names"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file / override DNS block"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print YAML, write nothing"),
    fix_dns: bool = typer.Option(False, "--fix-dns", help="Offer to delete a conflicting Technitium record"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactive confirmation for --fix-dns"),
):
    """Publish NAME.<suffix> → BACKEND."""
    settings = get_settings()
    spec = ServiceSpec(
        name=name.strip().lower(),
        backend=backend.strip(),
        host=host.strip() or None,
        insecure=insecure,
        middlewares=[m.strip() for m in middleware.split(",") if m.strip()],
    )
    if dry_run:
        try:
            typer.echo(operations.render_preview(spec, settings), nl=False)
        except GeneratorError as e:
            typer.secho(str(e), fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        return

    typer.echo(f"Pre-flight for {spec.fqdn(settings)}:")
    pf = operations.run_preflight(spec, settings)
    for c in pf.checks:
        _print_check(c)

    if fix_dns and pf.zone and pf.zone.blocks:
        for rec in pf.zone.records:
            typer.echo(f"\nConflicting record: {rec.label}")
            if not yes:
                typer.confirm("Delete this record in Technitium?", abort=True)
            try:
                outcome = operations.delete_zone_record(
                    rec.name, rec.type, rec.value, rec.disabled, settings
                )
            except operations.OperationError as e:
                typer.secho(str(e), fg=typer.colors.RED, err=True)
                raise typer.Exit(1)
            typer.echo(f"{OK} {outcome.message}")
        typer.echo("Re-running pre-flight:")
        pf = operations.run_preflight(spec, settings)
        for c in pf.checks:
            _print_check(c)

    try:
        path = operations.add_service(spec, settings, force=force)
    except (operations.OperationError, GeneratorError) as e:
        typer.secho(f"blocked: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.echo(f"wrote {path}")
    typer.echo("Post-flight:")
    post = operations.run_postflight(spec.fqdn(settings), settings)
    typer.echo(f"  {OK if post.ok else BAD} {post.summary}")
    if post.cert_issuer:
        typer.echo(f"      issuer:  {post.cert_issuer}")
        typer.echo(f"      subject: {post.cert_subject}")
    for hint in post.hints:
        typer.echo(f"  {WARN} {hint}")
    raise typer.Exit(0 if post.ok else 1)


@cli.command("list")
def list_cmd():
    """List every router found in the dynamic directory."""
    settings = get_settings()
    scan = operations.list_services(settings)
    if scan.routers:
        rows = [("NAME", "HOST", "BACKEND", "INSECURE", "MIDDLEWARES", "FILE")] + [
            (
                r.name,
                r.host or r.rule or "—",
                ", ".join(r.backends) or "—",
                r.insecure_transport or "no",
                ", ".join(r.middlewares) or "—",
                r.file.name,
            )
            for r in scan.routers
        ]
        widths = [max(len(row[i]) for row in rows) for i in range(6)]
        for row in rows:
            typer.echo("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    else:
        typer.echo("no routers found")
    for f, err in scan.errors.items():
        typer.secho(f"{WARN} {f.name}: {err}", fg=typer.colors.YELLOW, err=True)


@cli.command()
def remove(
    name: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete NAME.yml (single-router files only)."""
    settings = get_settings()
    if not yes:
        typer.confirm(f"Delete {name}.yml and unpublish {name}?", abort=True)
    try:
        path = operations.remove_service(name, settings)
    except operations.OperationError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.echo(f"removed {path}")


@cli.command()
def check(
    name: str = typer.Argument("", help="Service name (omit with --all)"),
    all_: bool = typer.Option(False, "--all", help="Health sweep of every service"),
):
    """Re-run pre-flight + post-flight checks without changing anything."""
    settings = get_settings()
    if all_:
        healths = operations.check_all(settings)
    elif name:
        try:
            healths = [operations.check_by_name(name, settings)]
        except operations.OperationError as e:
            typer.secho(str(e), fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
    else:
        typer.secho("give a NAME or --all", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    failed = False
    for h in healths:
        typer.secho(f"{h.entry.name} ({h.entry.file.name})", bold=True)
        if h.zone_check:
            _print_check(h.zone_check)
            failed |= h.zone_check.level == "block"
        if h.dns:
            _print_check(h.dns)
            failed |= h.dns.level == "block"
        for t in h.tcp:
            _print_check(t)
        if h.https:
            typer.echo(f"  {OK if h.https.ok else BAD} {h.https.summary}")
            if h.https.cert_issuer:
                typer.echo(f"      issuer: {h.https.cert_issuer}")
            failed |= not h.https.ok
    raise typer.Exit(1 if failed else 0)


@cli.command()
def dns():
    """Read-only view of the Technitium zone with classification."""
    settings = get_settings()
    panel = operations.zone_panel(settings)
    if not panel.available:
        typer.secho(panel.error, fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1)
    mark = OK if panel.wildcard_ok else BAD
    typer.echo(f"{mark} wildcard: {panel.wildcard_detail}")
    rows = [("RECORD", "TYPE", "VALUE", "CATEGORY", "NOTES")] + [
        (
            row.record.name,
            row.record.type,
            row.record.value if len(row.record.value) < 40 else row.record.value[:37] + "...",
            row.category,
            f"shadows {row.shadows}!" if row.shadows else "",
        )
        for row in panel.rows
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(5)]
    for r in rows:
        typer.echo("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
