"""traefikctl web UI — FastAPI + server-rendered Jinja2 templates.

Every state-changing action goes through an explicit confirm step and is
logged to stdout with the resulting filename. The app refuses to start if
the dynamic directory is missing or unwritable.
"""

import logging
import os
import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import get_settings
from ..core import operations, parser
from ..core.generator import ServiceSpec

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("traefikctl.web")

settings = get_settings()

app = FastAPI(title="traefikctl", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _parse_middlewares(raw: str) -> list[str]:
    return [m.strip() for m in raw.split(",") if m.strip()]


@app.on_event("startup")
def verify_mount() -> None:
    d = settings.dynamic_dir
    if not d.is_dir():
        log.critical("dynamic dir %s does not exist — is the bind mount present?", d)
        raise SystemExit(2)
    try:
        with tempfile.NamedTemporaryFile(dir=d, prefix=".writecheck-", suffix=".tmp"):
            pass
    except OSError as e:
        log.critical("dynamic dir %s is not writable (%s)", d, e)
        raise SystemExit(2)
    log.info(
        "traefikctl up — dynamic dir %s, domain %s, ingress %s (uid=%s)",
        d, settings.domain_suffix, settings.ingress_ip, os.getuid(),
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    scan = operations.list_services(settings)
    return templates.TemplateResponse(
        request, "index.html", {"scan": scan, "settings": settings}
    )


@app.get("/add", response_class=HTMLResponse)
def add_form(request: Request):
    return templates.TemplateResponse(
        request, "add.html", {"settings": settings, "pf": None, "spec": None}
    )


@app.post("/add/preflight", response_class=HTMLResponse)
def add_preflight(
    request: Request,
    name: str = Form(""),
    backend: str = Form(""),
    host: str = Form(""),
    insecure: bool = Form(False),
    middlewares: str = Form(""),
    force: bool = Form(False),
):
    spec = ServiceSpec(
        name=name.strip().lower(),
        backend=backend.strip(),
        host=host.strip() or None,
        insecure=insecure,
        middlewares=_parse_middlewares(middlewares),
    )
    pf = operations.run_preflight(spec, settings)
    preview = ""
    if pf.name_ok:
        try:
            preview = operations.render_preview(spec, settings)
        except Exception as e:  # backend URL errors etc. already in pf
            log.warning("preview render failed: %s", e)
    # force may only override an existing NAME.yml or a DNS blocker —
    # never a collision with a router in another file.
    confirmable = pf.can_proceed or (force and not pf.collision)
    return templates.TemplateResponse(
        request,
        "add.html",
        {
            "settings": settings,
            "pf": pf,
            "spec": spec,
            "preview": preview,
            "force": force,
            "confirmable": confirmable,
            "middlewares_raw": middlewares,
        },
    )


@app.post("/add/confirm", response_class=HTMLResponse)
def add_confirm(
    request: Request,
    name: str = Form(...),
    backend: str = Form(...),
    host: str = Form(""),
    insecure: bool = Form(False),
    middlewares: str = Form(""),
    force: bool = Form(False),
):
    spec = ServiceSpec(
        name=name.strip().lower(),
        backend=backend.strip(),
        host=host.strip() or None,
        insecure=insecure,
        middlewares=_parse_middlewares(middlewares),
    )
    try:
        path = operations.add_service(spec, settings, force=force)
    except (operations.OperationError, Exception) as e:
        log.error("add %s failed: %s", spec.name, e)
        return templates.TemplateResponse(
            request,
            "result.html",
            {"settings": settings, "ok": False, "title": f"Add {spec.name} failed",
             "message": str(e), "post": None, "name": spec.name},
        )
    post = operations.run_postflight(spec.fqdn(settings), settings)
    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "settings": settings,
            "ok": True,
            "title": f"{spec.name} published",
            "message": f"wrote {path}",
            "post": post,
            "host": spec.fqdn(settings),
            "name": spec.name,
        },
    )


@app.get("/service/{name}", response_class=HTMLResponse)
def service_detail(request: Request, name: str):
    try:
        health = operations.check_by_name(name, settings)
    except operations.OperationError as e:
        return templates.TemplateResponse(
            request,
            "result.html",
            {"settings": settings, "ok": False, "title": "Not found",
             "message": str(e), "post": None, "name": name},
        )
    own_file = settings.dynamic_dir / f"{name}.yml"
    removable = health.entry.file == own_file
    return templates.TemplateResponse(
        request,
        "detail.html",
        {"settings": settings, "h": health, "removable": removable},
    )


@app.post("/remove/{name}", response_class=HTMLResponse)
def remove(request: Request, name: str, confirm: str = Form("")):
    if confirm != name:
        return templates.TemplateResponse(
            request,
            "result.html",
            {"settings": settings, "ok": False, "title": "Not removed",
             "message": f"Confirmation text did not match {name!r}.",
             "post": None, "name": name},
        )
    try:
        path = operations.remove_service(name, settings)
    except operations.OperationError as e:
        return templates.TemplateResponse(
            request,
            "result.html",
            {"settings": settings, "ok": False, "title": f"Remove {name} failed",
             "message": str(e), "post": None, "name": name},
        )
    return templates.TemplateResponse(
        request,
        "result.html",
        {"settings": settings, "ok": True, "title": f"{name} removed",
         "message": f"deleted {path} — the route will 404 within seconds",
         "post": None, "name": None},
    )


@app.get("/dns", response_class=HTMLResponse)
def dns_panel(request: Request):
    panel = operations.zone_panel(settings)
    return templates.TemplateResponse(
        request, "dns.html", {"settings": settings, "panel": panel}
    )


def _spec_fields(
    name: str, backend: str, host: str, insecure: bool, middlewares: str, force: bool
) -> dict:
    return {
        "name": name, "backend": backend, "host": host,
        "insecure": insecure, "middlewares": middlewares, "force": force,
    }


@app.post("/dns/delete-confirm", response_class=HTMLResponse)
def dns_delete_confirm(
    request: Request,
    fqdn: str = Form(...),
    rtype: str = Form(...),
    value: str = Form(...),
    rdisabled: str = Form("false"),
    # original add-form context so the user can bounce back to pre-flight
    name: str = Form(""),
    backend: str = Form(""),
    host: str = Form(""),
    insecure: bool = Form(False),
    middlewares: str = Form(""),
    force: bool = Form(False),
):
    return templates.TemplateResponse(
        request,
        "dns_delete.html",
        {
            "settings": settings,
            "fqdn": fqdn, "rtype": rtype, "value": value,
            "rdisabled": rdisabled == "true",
            "spec_fields": _spec_fields(name, backend, host, insecure, middlewares, force),
        },
    )


@app.post("/dns/delete", response_class=HTMLResponse)
def dns_delete(
    request: Request,
    fqdn: str = Form(...),
    rtype: str = Form(...),
    value: str = Form(...),
    rdisabled: str = Form("false"),
    name: str = Form(""),
    backend: str = Form(""),
    host: str = Form(""),
    insecure: bool = Form(False),
    middlewares: str = Form(""),
    force: bool = Form(False),
):
    try:
        outcome = operations.delete_zone_record(
            fqdn, rtype, value, rdisabled == "true", settings
        )
    except operations.OperationError as e:
        log.error("zone delete %s %s failed: %s", fqdn, rtype, e)
        return templates.TemplateResponse(
            request,
            "result.html",
            {"settings": settings, "ok": False, "title": "Record not deleted",
             "message": str(e), "post": None, "name": None},
        )
    return templates.TemplateResponse(
        request,
        "dns_deleted.html",
        {
            "settings": settings,
            "outcome": outcome,
            "spec_fields": _spec_fields(name, backend, host, insecure, middlewares, force)
            if name
            else None,
        },
    )


@app.get("/health")
def health():
    return {"ok": True}
