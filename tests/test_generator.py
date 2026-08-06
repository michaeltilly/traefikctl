from pathlib import Path

import pytest
import yaml

from traefikctl.core import generator
from traefikctl.core.generator import GeneratorError, ServiceSpec

GOLDEN = Path(__file__).parent / "golden"


def test_render_matches_golden_plain(settings):
    spec = ServiceSpec(name="testapp", backend="http://10.10.30.5:8096")
    assert generator.render(spec, settings) == (GOLDEN / "testapp.yml").read_text()


def test_render_matches_golden_insecure_with_middleware(settings):
    spec = ServiceSpec(
        name="proxmox",
        backend="https://10.10.10.40:8006",
        insecure=True,
        middlewares=["authentik-forward-auth"],
    )
    assert generator.render(spec, settings) == (GOLDEN / "proxmox.yml").read_text()


def test_render_host_override(settings):
    spec = ServiceSpec(name="app", backend="http://x:1", host="other.example.com")
    data = yaml.safe_load(generator.render(spec, settings))
    assert data["http"]["routers"]["app"]["rule"] == "Host(`other.example.com`)"


@pytest.mark.parametrize("bad", ["", "UPPER", "has_underscore", "-lead", "trail-", "dots.no"])
def test_invalid_names_rejected(settings, bad):
    assert not generator.valid_name(bad)
    with pytest.raises(GeneratorError):
        generator.render(ServiceSpec(name=bad, backend="http://x:1"), settings)


def test_write_refuses_overwrite_without_force(settings):
    spec = ServiceSpec(name="app", backend="http://x:1")
    generator.write_service(spec, settings)
    with pytest.raises(GeneratorError, match="already exists"):
        generator.write_service(spec, settings)


def test_force_backs_up_old_file(settings):
    generator.write_service(ServiceSpec(name="app", backend="http://old:1"), settings)
    generator.write_service(
        ServiceSpec(name="app", backend="http://new:2"), settings, force=True
    )
    assert "http://old:1" in (settings.dynamic_dir / "app.yml.bak").read_text()
    assert "http://new:2" in (settings.dynamic_dir / "app.yml").read_text()


def test_insecure_creates_transports_file(settings):
    generator.write_service(
        ServiceSpec(name="app", backend="https://x:1", insecure=True), settings
    )
    data = yaml.safe_load((settings.dynamic_dir / "transports.yml").read_text())
    assert data["http"]["serversTransports"]["insecure-backend"] == {
        "insecureSkipVerify": True
    }


def test_insecure_leaves_existing_transports_alone(settings):
    tf = settings.dynamic_dir / "transports.yml"
    original = "http:\n  serversTransports:\n    insecure-backend:\n      insecureSkipVerify: true\n"
    tf.write_text(original)
    generator.write_service(
        ServiceSpec(name="app", backend="https://x:1", insecure=True), settings
    )
    assert tf.read_text() == original


def test_insecure_errors_when_transport_missing_from_existing_file(settings):
    (settings.dynamic_dir / "transports.yml").write_text("http:\n  serversTransports: {}\n")
    with pytest.raises(GeneratorError, match="add it manually"):
        generator.write_service(
            ServiceSpec(name="app", backend="https://x:1", insecure=True), settings
        )


def test_atomic_write_leaves_no_partial_on_failure(settings, monkeypatch):
    # Simulate a crash mid-write: the target must not exist, and no .yml
    # temp file may be visible to the Traefik watcher.
    def boom(*a, **k):
        raise RuntimeError("crash")

    monkeypatch.setattr("os.replace", boom)
    with pytest.raises(RuntimeError):
        generator.atomic_write(settings.dynamic_dir / "app.yml", "http: {}\n")
    leftovers = list(settings.dynamic_dir.iterdir())
    assert not (settings.dynamic_dir / "app.yml").exists()
    assert all(p.suffix not in (".yml", ".yaml") for p in leftovers)
