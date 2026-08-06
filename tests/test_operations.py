import pytest

from traefikctl.core import generator, operations, validators
from traefikctl.core.generator import ServiceSpec
from traefikctl.core.validators import CheckResult, HttpsResult


@pytest.fixture(autouse=True)
def stub_network(monkeypatch):
    """Operations tests never touch the network."""
    monkeypatch.setattr(
        validators, "dns_check",
        lambda host, settings: CheckResult(True, "ok", f"{host} → ingress"),
    )
    monkeypatch.setattr(
        validators, "tcp_check",
        lambda backend, timeout=3.0: CheckResult(True, "ok", "reachable"),
    )


def test_preflight_ok_path(settings):
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://x:1"), settings
    )
    assert pf.can_proceed and not pf.blockers


def test_preflight_blocks_existing_file(settings):
    generator.write_service(ServiceSpec(name="app", backend="http://x:1"), settings)
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://y:2"), settings
    )
    assert pf.file_exists and not pf.can_proceed


def test_preflight_blocks_bad_backend_url(settings):
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="10.10.30.5:8096"), settings
    )
    assert pf.blockers and not pf.can_proceed


def test_preflight_detects_cross_file_collision(settings):
    (settings.dynamic_dir / "other.yml").write_text(
        "http:\n  routers:\n    app:\n      rule: \"Host(`app.x`)\"\n      service: app\n"
    )
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://x:1"), settings
    )
    assert pf.collision
    # collision is never overridable, even with force
    with pytest.raises(operations.OperationError):
        operations.add_service(
            ServiceSpec(name="app", backend="http://x:1"), settings, force=True
        )


def test_dns_block_requires_force(settings, monkeypatch):
    monkeypatch.setattr(
        validators, "dns_check",
        lambda host, s: CheckResult(False, "block", "overridden A record"),
    )
    spec = ServiceSpec(name="app", backend="http://x:1")
    with pytest.raises(operations.OperationError):
        operations.add_service(spec, settings)
    assert not (settings.dynamic_dir / "app.yml").exists()
    operations.add_service(spec, settings, force=True)
    assert (settings.dynamic_dir / "app.yml").exists()


def test_preflight_warns_insecure_on_http_backend(settings):
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://x:1", insecure=True), settings
    )
    warns = [c for c in pf.checks if c.level == "warn"]
    assert any("insecure transport" in c.summary for c in warns)
    # a warning must not block the write
    assert pf.can_proceed


def test_preflight_no_insecure_warning_for_https_backend(settings):
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="https://x:1", insecure=True), settings
    )
    assert not any("insecure transport" in c.summary for c in pf.checks)


def _postflight_probes(monkeypatch, codes):
    """Stub https_check to pop status codes in order; return the call log."""
    seen = []

    def fake(host, settings, timeout=6.0):
        code = codes[min(len(seen), len(codes) - 1)]
        seen.append(code)
        return HttpsResult(True, f"HTTP {code}", status_code=code)

    monkeypatch.setattr(validators, "https_check", fake)
    monkeypatch.setattr(operations.time, "sleep", lambda s: None)
    return seen


def test_postflight_retries_stale_3xx(settings, monkeypatch):
    seen = _postflight_probes(monkeypatch, [301, 301, 200])
    result = operations.run_postflight("app.x", settings, attempts=3)
    assert result.status_code == 200
    assert len(seen) == 3


def test_postflight_reports_persistent_3xx_with_hint(settings, monkeypatch):
    seen = _postflight_probes(monkeypatch, [301])
    result = operations.run_postflight("app.x", settings, attempts=3)
    assert result.status_code == 301
    assert len(seen) == 3
    assert any("stale" in h for h in result.hints)


def test_postflight_retries_404_then_succeeds(settings, monkeypatch):
    seen = _postflight_probes(monkeypatch, [404, 200])
    result = operations.run_postflight("app.x", settings, attempts=3)
    assert result.status_code == 200
    assert len(seen) == 2


def test_remove_single_router_file(settings):
    generator.write_service(ServiceSpec(name="app", backend="http://x:1"), settings)
    operations.remove_service("app", settings)
    assert not (settings.dynamic_dir / "app.yml").exists()


def test_remove_refuses_multi_router_file(settings):
    (settings.dynamic_dir / "app.yml").write_text(
        "http:\n  routers:\n"
        "    app:\n      rule: \"Host(`app.x`)\"\n      service: app\n"
        "    extra:\n      rule: \"Host(`extra.x`)\"\n      service: extra\n"
    )
    with pytest.raises(operations.OperationError, match="multi-router"):
        operations.remove_service("app", settings)
    assert (settings.dynamic_dir / "app.yml").exists()


def test_remove_router_in_foreign_file_refused(settings):
    (settings.dynamic_dir / "handwritten.yml").write_text(
        "http:\n  routers:\n    app:\n      rule: \"Host(`app.x`)\"\n      service: app\n"
    )
    with pytest.raises(operations.OperationError, match="handwritten.yml"):
        operations.remove_service("app", settings)


def test_remove_missing_service(settings):
    with pytest.raises(operations.OperationError, match="not found"):
        operations.remove_service("nope", settings)
