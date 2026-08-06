"""Ingress-mode matrix: wildcard mode (ingress01, default) vs explicit mode
(ingress02). Covers every cell of the mode/zone-state table plus the config
plumbing, mode-aware dns_check messaging, and the explicit-mode zone panel."""

import httpx
import pytest

from traefikctl.config import Settings, _env_bool
from traefikctl.core import operations, validators
from traefikctl.core.technitium import (
    TechnitiumClient,
    ZoneKind,
    classify,
)
from traefikctl.core.validators import CheckResult

ZONE = "shire.tillynet.com"
MGMT_INGRESS = "10.10.10.4"
SVC_INGRESS = "10.10.30.4"


@pytest.fixture
def explicit(settings):
    settings.technitium_token = "test-token"
    settings.technitium_zone = ZONE
    settings.wildcard_covers_ingress = False
    settings.ingress_ip = MGMT_INGRESS
    settings.instance_name = "ingress02"
    return settings


@pytest.fixture
def wildcard(settings):
    settings.technitium_token = "test-token"
    settings.technitium_zone = ZONE
    return settings


def _record(name, rtype="A", value="10.10.10.99", disabled=False, ttl=3600):
    key = {"A": "ipAddress", "CNAME": "cname"}[rtype]
    return {"name": name, "type": rtype, "ttl": ttl, "disabled": disabled,
            "rData": {key: value}}


def _mock_zone(monkeypatch, records):
    """Serve `records` for any records/get call; classify's per-name filter
    and the wildcard-target lookup both work against the same list."""
    def fake_call(self, endpoint, **params):
        assert "records/get" in endpoint
        return {"records": records}
    monkeypatch.setattr(TechnitiumClient, "_call", fake_call)


# ---- config plumbing ----

def test_env_bool_parsing(monkeypatch):
    for raw, expected in [
        ("false", False), ("FALSE", False), ("0", False), ("no", False),
        ("off", False), ("true", True), ("1", True), ("yes", True), ("", True),
    ]:
        monkeypatch.setenv("X_TEST_FLAG", raw)
        assert _env_bool("X_TEST_FLAG", True) is expected, raw
    monkeypatch.delenv("X_TEST_FLAG")
    assert _env_bool("X_TEST_FLAG", True) is True
    assert _env_bool("X_TEST_FLAG", False) is False


def test_default_settings_are_wildcard_mode_ingress01():
    s = Settings()
    assert s.wildcard_covers_ingress is True
    assert s.instance_name == "ingress01"


def test_mode_env_vars(monkeypatch):
    monkeypatch.setenv("TRAEFIKCTL_WILDCARD_COVERS_INGRESS", "false")
    monkeypatch.setenv("TRAEFIKCTL_INSTANCE_NAME", "ingress02")
    s = Settings()
    assert s.wildcard_covers_ingress is False
    assert s.instance_name == "ingress02"


# ---- classify: the verdict table, explicit-mode column ----

def test_explicit_no_record_blocks_with_create_guidance(explicit, monkeypatch):
    _mock_zone(monkeypatch, [])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.MISSING_RECORD
    assert v.blocks
    assert f"app.{ZONE} → {MGMT_INGRESS}" in v.detail
    assert "never creates" in v.detail


def test_explicit_record_to_this_ingress_passes(explicit, monkeypatch):
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", value=MGMT_INGRESS)])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.INGRESS_ALIAS and not v.blocks
    assert "required state" in v.detail


def test_explicit_record_at_other_ingress_blocks_with_distinction(
    explicit, monkeypatch
):
    _mock_zone(monkeypatch, [
        _record(f"*.{ZONE}", value=SVC_INGRESS),
        _record(f"app.{ZONE}", value=SVC_INGRESS),
    ])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.CONFLICT and v.blocks
    assert f"other ingress ({SVC_INGRESS})" in v.detail
    assert v.records[0].value == SVC_INGRESS  # guided delete still offered


def test_explicit_record_at_device_blocks_with_device_message(
    explicit, monkeypatch
):
    _mock_zone(monkeypatch, [
        _record(f"*.{ZONE}", value=SVC_INGRESS),
        _record(f"app.{ZONE}", value="10.10.10.50"),
    ])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.CONFLICT and v.blocks
    assert "points at a device" in v.detail


def test_explicit_device_conflict_without_wildcard_record(explicit, monkeypatch):
    # No wildcard in the zone at all — distinction degrades to the generic
    # device message rather than crashing or misclassifying.
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", value="10.10.10.50")])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.CONFLICT and "points at a device" in v.detail


def test_explicit_disabled_record_blocks(explicit, monkeypatch):
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", disabled=True)])
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.DISABLED_CONFLICT and v.blocks
    # explicit-mode fix guidance: delete THEN create the record
    assert f"A record app.{ZONE} → {MGMT_INGRESS}" in v.detail


def test_explicit_unavailable_degrades(explicit, monkeypatch):
    def boom(self, endpoint, **params):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(TechnitiumClient, "_call", boom)
    v = classify(f"app.{ZONE}", explicit)
    assert v.kind == ZoneKind.UNAVAILABLE and not v.blocks


def test_explicit_disabled_integration(settings):
    settings.technitium_token = ""
    settings.wildcard_covers_ingress = False
    v = classify(f"app.{ZONE}", settings)
    assert v.kind == ZoneKind.DISABLED_INTEGRATION and not v.blocks


# ---- classify: wildcard-mode column unchanged ----

def test_wildcard_no_record_still_passes(wildcard, monkeypatch):
    _mock_zone(monkeypatch, [])
    v = classify(f"app.{ZONE}", wildcard)
    assert v.kind == ZoneKind.NO_RECORD and not v.blocks
    assert "wildcard covers this name" in v.detail


def test_wildcard_alias_still_notes_duplicate(wildcard, monkeypatch):
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", value=wildcard.ingress_ip)])
    v = classify(f"app.{ZONE}", wildcard)
    assert v.kind == ZoneKind.INGRESS_ALIAS and "duplicate" in v.detail


def test_wildcard_conflict_message_unchanged(wildcard, monkeypatch):
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", value="10.10.30.5")])
    v = classify(f"app.{ZONE}", wildcard)
    assert v.kind == ZoneKind.CONFLICT
    assert "overrides the wildcard" in v.detail


def test_wildcard_disabled_message_unchanged(wildcard, monkeypatch):
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", disabled=True)])
    v = classify(f"app.{ZONE}", wildcard)
    assert v.kind == ZoneKind.DISABLED_CONFLICT
    assert "let the wildcard take over" in v.detail


# ---- preflight integration ----

def _quiet_network(monkeypatch):
    monkeypatch.setattr(validators, "dns_check",
                        lambda h, s: CheckResult(True, "ok", "dns"))
    monkeypatch.setattr(validators, "tcp_check",
                        lambda b, timeout=3.0: CheckResult(True, "ok", "tcp"))


def test_preflight_explicit_missing_record_blocks(explicit, monkeypatch):
    from traefikctl.core.generator import ServiceSpec
    _quiet_network(monkeypatch)
    _mock_zone(monkeypatch, [])
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://x:1"), explicit
    )
    assert pf.zone.kind == ZoneKind.MISSING_RECORD
    assert not pf.can_proceed
    blocker = [c for c in pf.blockers if "no A record" in c.summary]
    assert blocker and MGMT_INGRESS in blocker[0].detail


def test_preflight_explicit_alias_proceeds(explicit, monkeypatch):
    from traefikctl.core.generator import ServiceSpec
    _quiet_network(monkeypatch)
    _mock_zone(monkeypatch, [_record(f"app.{ZONE}", value=MGMT_INGRESS)])
    pf = operations.run_preflight(
        ServiceSpec(name="app", backend="http://x:1"), explicit
    )
    assert pf.zone.kind == ZoneKind.INGRESS_ALIAS
    assert pf.can_proceed


# ---- dns_check messaging ----

class _FakeAnswer:
    def __init__(self, address):
        self.address = address


def _mock_resolve(monkeypatch, result):
    class FakeResolver:
        def __init__(self, configure=False):
            self.nameservers = []
            self.lifetime = 0
        def resolve(self, host, rtype):
            if isinstance(result, Exception):
                raise result
            return [_FakeAnswer(a) for a in result]
    monkeypatch.setattr(validators.dns.resolver, "Resolver", FakeResolver)


def test_dns_check_explicit_nxdomain_says_create(explicit, monkeypatch):
    import dns.resolver as r
    _mock_resolve(monkeypatch, r.NXDOMAIN())
    c = validators.dns_check(f"app.{ZONE}", explicit)
    assert c.level == "block"
    assert f"Create app.{ZONE} → {MGMT_INGRESS}" in c.detail


def test_dns_check_explicit_wrong_answer_explains_both_cases(
    explicit, monkeypatch
):
    _mock_resolve(monkeypatch, [SVC_INGRESS])
    c = validators.dns_check(f"app.{ZONE}", explicit)
    assert c.level == "block"
    assert "create the record" in c.detail and "delete that record" in c.detail


def test_dns_check_wildcard_messages_unchanged(wildcard, monkeypatch):
    import dns.resolver as r
    _mock_resolve(monkeypatch, r.NXDOMAIN())
    c = validators.dns_check(f"app.{ZONE}", wildcard)
    assert "Expected the wildcard" in c.detail
    _mock_resolve(monkeypatch, ["10.10.30.5"])
    c = validators.dns_check(f"app.{ZONE}", wildcard)
    assert "overrides the wildcard" in c.detail


def test_dns_check_explicit_correct_answer_passes(explicit, monkeypatch):
    _mock_resolve(monkeypatch, [MGMT_INGRESS])
    c = validators.dns_check(f"app.{ZONE}", explicit)
    assert c.ok and c.level == "ok"


# ---- failure hints ----

def test_failure_hints_name_the_instance(explicit):
    hints = validators._failure_hints(explicit)
    assert any("ingress02" in h for h in hints)
    assert any(MGMT_INGRESS in h for h in hints)


def test_failure_hints_default_unchanged(settings):
    hints = validators._failure_hints(settings)
    assert any("on ingress01." in h for h in hints)
    assert any("override the wildcard" in h for h in hints)


# ---- zone panel, explicit mode ----

def _panel_zone(explicit):
    return [
        _record(f"*.{ZONE}", value=SVC_INGRESS),
        _record(f"dns1.{ZONE}", value="10.10.30.30"),
        _record(f"k2pve.{ZONE}", value=MGMT_INGRESS),
        _record(f"whoami.{ZONE}", value=SVC_INGRESS),
        _record(f"idrac-r630.{ZONE}", value="10.10.10.50"),
    ]


def test_zone_panel_explicit_wildcard_at_other_ingress_is_ok(
    explicit, monkeypatch
):
    _mock_zone(monkeypatch, _panel_zone(explicit))
    panel = operations.zone_panel(explicit)
    assert panel.available and panel.wildcard_ok
    assert "other ingress" in panel.wildcard_detail


def test_zone_panel_explicit_categories(explicit, monkeypatch):
    _mock_zone(monkeypatch, _panel_zone(explicit))
    panel = operations.zone_panel(explicit)
    cats = {row.record.name: row.category for row in panel.rows}
    assert cats[f"*.{ZONE}"] == "wildcard"
    assert cats[f"k2pve.{ZONE}"] == "ingress-aliased"
    assert cats[f"whoami.{ZONE}"] == "other-ingress"
    assert cats[f"idrac-r630.{ZONE}"] == "direct-access"


def test_zone_panel_explicit_wildcard_at_this_ingress_is_broken(
    explicit, monkeypatch
):
    _mock_zone(monkeypatch, [_record(f"*.{ZONE}", value=MGMT_INGRESS)])
    panel = operations.zone_panel(explicit)
    assert not panel.wildcard_ok
    assert "THIS ingress" in panel.wildcard_detail


def test_zone_panel_explicit_missing_published(explicit, monkeypatch):
    (explicit.dynamic_dir / "orphan.yml").write_text(
        "http:\n  routers:\n    orphan:\n"
        f'      rule: "Host(`orphan.{ZONE}`)"\n'
        "      service: orphan\n"
    )
    (explicit.dynamic_dir / "k2pve.yml").write_text(
        "http:\n  routers:\n    k2pve:\n"
        f'      rule: "Host(`k2pve.{ZONE}`)"\n'
        "      service: k2pve\n"
    )
    _mock_zone(monkeypatch, _panel_zone(explicit))
    panel = operations.zone_panel(explicit)
    assert panel.missing_published == ["orphan"]


def test_zone_panel_explicit_other_ingress_record_shadows_published(
    explicit, monkeypatch
):
    (explicit.dynamic_dir / "whoami.yml").write_text(
        "http:\n  routers:\n    whoami:\n"
        f'      rule: "Host(`whoami.{ZONE}`)"\n'
        "      service: whoami\n"
    )
    _mock_zone(monkeypatch, _panel_zone(explicit))
    panel = operations.zone_panel(explicit)
    row = [r for r in panel.rows if r.record.name == f"whoami.{ZONE}"][0]
    assert row.category == "other-ingress" and row.shadows == "whoami"


def test_zone_panel_wildcard_mode_has_no_missing_published(
    wildcard, monkeypatch
):
    (wildcard.dynamic_dir / "app.yml").write_text(
        "http:\n  routers:\n    app:\n"
        f'      rule: "Host(`app.{ZONE}`)"\n'
        "      service: app\n"
    )
    _mock_zone(monkeypatch, [_record(f"*.{ZONE}", value=wildcard.ingress_ip)])
    panel = operations.zone_panel(wildcard)
    assert panel.missing_published == []
    assert "other-ingress" not in {r.category for r in panel.rows}
