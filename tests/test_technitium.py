import httpx
import pytest

from traefikctl.core import operations, technitium
from traefikctl.core.technitium import (
    TechnitiumClient,
    TechnitiumError,
    ZoneKind,
    ZoneRecord,
    classify,
)

ZONE = "shire.tillynet.com"


@pytest.fixture
def zsettings(settings):
    settings.technitium_token = "test-token"
    settings.technitium_zone = ZONE
    return settings


def _record(name, rtype="A", value="10.10.10.99", disabled=False, ttl=3600):
    key = {"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname",
           "TXT": "text", "NS": "nameServer", "SOA": "primaryNameServer"}[rtype]
    return {"name": name, "type": rtype, "ttl": ttl, "disabled": disabled,
            "rData": {key: value}}


def _mock_records(monkeypatch, records):
    def fake_call(self, endpoint, **params):
        assert "records/get" in endpoint
        return {"records": records}
    monkeypatch.setattr(TechnitiumClient, "_call", fake_call)


# ---- classify ----

def test_classify_disabled_integration(settings):
    settings.technitium_token = ""
    v = classify(f"app.{ZONE}", settings)
    assert v.kind == ZoneKind.DISABLED_INTEGRATION and not v.blocks


def test_classify_unavailable_on_api_error(zsettings, monkeypatch):
    def boom(self, endpoint, **params):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(TechnitiumClient, "_call", boom)
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.UNAVAILABLE and not v.blocks


def test_classify_no_record(zsettings, monkeypatch):
    _mock_records(monkeypatch, [])
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.NO_RECORD and not v.blocks


def test_classify_ingress_alias(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"app.{ZONE}", value=zsettings.ingress_ip)])
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.INGRESS_ALIAS and not v.blocks


def test_classify_enabled_conflict(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"app.{ZONE}", value="10.10.10.5")])
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.CONFLICT and v.blocks
    assert v.records[0].value == "10.10.10.5"


def test_classify_disabled_conflict_the_k2pve_case(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"app.{ZONE}", disabled=True)])
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.DISABLED_CONFLICT and v.blocks
    assert "occupies the name" in v.detail


def test_classify_ignores_other_names(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"other.{ZONE}", value="10.10.10.5")])
    v = classify(f"app.{ZONE}", zsettings)
    assert v.kind == ZoneKind.NO_RECORD


# ---- denylist ----

@pytest.mark.parametrize(
    "name,rtype",
    [
        (f"*.{ZONE}", "A"),
        (ZONE, "A"),
        (f"dns1.{ZONE}", "A"),
        (ZONE, "NS"),
        (ZONE, "SOA"),
    ],
)
def test_denylist_refuses_protected(zsettings, name, rtype):
    client = TechnitiumClient(zsettings)
    value = "x" if rtype not in ("A",) else "10.10.30.4"
    rec = ZoneRecord(name=name, type=rtype, ttl=60, disabled=False,
                     rdata={"ipAddress": value} if rtype == "A" else {"nameServer": value})
    assert client.denylist_reason(rec) is not None
    with pytest.raises(TechnitiumError, match="refusing"):
        client.delete_record(rec)


def test_denylist_refuses_unknown_types(zsettings):
    client = TechnitiumClient(zsettings)
    rec = ZoneRecord(name=f"app.{ZONE}", type="SRV", ttl=60, disabled=False, rdata={})
    assert "Technitium console" in client.denylist_reason(rec)


def test_denylist_allows_normal_a_record(zsettings):
    client = TechnitiumClient(zsettings)
    rec = ZoneRecord(name=f"app.{ZONE}", type="A", ttl=60, disabled=True,
                     rdata={"ipAddress": "10.10.10.5"})
    assert client.denylist_reason(rec) is None


# ---- delete_zone_record operation ----

def test_delete_zone_record_success(zsettings, monkeypatch):
    deleted = []

    def fake_call(self, endpoint, **params):
        if "delete" in endpoint:
            deleted.append(params)
            return {}
        if params.get("listZone"):
            return {"records": [_record(ZONE, "SOA", "dns1")
                                | {"rData": {"minimum": 900}}]}
        return {"records": [_record(f"app.{ZONE}", disabled=True)]}

    monkeypatch.setattr(TechnitiumClient, "_call", fake_call)
    outcome = operations.delete_zone_record(
        f"app.{ZONE}", "A", "10.10.10.99", True, zsettings
    )
    assert deleted and deleted[0]["ipAddress"] == "10.10.10.99"
    assert outcome.negative_ttl == 900
    assert "900 seconds" in outcome.message


def test_delete_zone_record_gone_already(zsettings, monkeypatch):
    _mock_records(monkeypatch, [])
    with pytest.raises(operations.OperationError, match="already be"):
        operations.delete_zone_record(f"app.{ZONE}", "A", "10.10.10.99", True, zsettings)


def test_delete_zone_record_denylist(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"*.{ZONE}", value="10.10.30.4")])
    with pytest.raises(operations.OperationError, match="refusing"):
        operations.delete_zone_record(f"*.{ZONE}", "A", "10.10.30.4", False, zsettings)


def test_delete_zone_record_permission_denied_no_retry(zsettings, monkeypatch):
    calls = []

    def fake_call(self, endpoint, **params):
        if "delete" in endpoint:
            calls.append(1)
            raise TechnitiumError("Access was denied.")
        return {"records": [_record(f"app.{ZONE}", disabled=True)]}

    monkeypatch.setattr(TechnitiumClient, "_call", fake_call)
    with pytest.raises(operations.OperationError, match="Access was denied"):
        operations.delete_zone_record(f"app.{ZONE}", "A", "10.10.10.99", True, zsettings)
    assert len(calls) == 1  # surfaced, not retried


# ---- preflight integration ----

def test_preflight_zone_block(zsettings, monkeypatch):
    from traefikctl.core import validators
    from traefikctl.core.generator import ServiceSpec
    from traefikctl.core.validators import CheckResult

    monkeypatch.setattr(validators, "dns_check",
                        lambda h, s: CheckResult(True, "ok", "dns"))
    monkeypatch.setattr(validators, "tcp_check",
                        lambda b, timeout=3.0: CheckResult(True, "ok", "tcp"))
    _mock_records(monkeypatch, [_record(f"app.{ZONE}", disabled=True)])
    pf = operations.run_preflight(ServiceSpec(name="app", backend="http://x:1"), zsettings)
    assert pf.zone.kind == ZoneKind.DISABLED_CONFLICT
    assert not pf.can_proceed
    assert any("Technitium zone conflict" in c.summary for c in pf.blockers)


def test_preflight_unchanged_without_token(settings, monkeypatch):
    from traefikctl.core import validators
    from traefikctl.core.generator import ServiceSpec
    from traefikctl.core.validators import CheckResult

    settings.technitium_token = ""
    monkeypatch.setattr(validators, "dns_check",
                        lambda h, s: CheckResult(True, "ok", "dns"))
    monkeypatch.setattr(validators, "tcp_check",
                        lambda b, timeout=3.0: CheckResult(True, "ok", "tcp"))
    called = []
    monkeypatch.setattr(TechnitiumClient, "_call",
                        lambda self, e, **p: called.append(e))
    pf = operations.run_preflight(ServiceSpec(name="app", backend="http://x:1"), settings)
    assert pf.can_proceed
    assert not called  # zero API traffic when unconfigured
    assert not any("Technitium" in c.summary for c in pf.checks)


# ---- zone panel ----

def test_zone_panel_classification_and_shadowing(zsettings, monkeypatch):
    (zsettings.dynamic_dir / "jellyfin.yml").write_text(
        "http:\n  routers:\n    jellyfin:\n"
        f'      rule: "Host(`jellyfin.{ZONE}`)"\n'
        "      service: jellyfin\n"
    )
    records = [
        _record(f"*.{ZONE}", value=zsettings.ingress_ip),
        _record(ZONE, "NS", "dns1"),
        _record(f"dns1.{ZONE}", value="10.10.30.30"),
        _record(f"traefik.{ZONE}", value=zsettings.ingress_ip),
        _record(f"jellyfin.{ZONE}", value="10.10.30.5"),  # shadows published svc
        _record(f"ghost.{ZONE}", disabled=True),
    ]
    _mock_records(monkeypatch, records)
    panel = operations.zone_panel(zsettings)
    assert panel.available and panel.wildcard_ok
    cats = {row.record.name + "/" + row.record.type: row.category for row in panel.rows}
    assert cats[f"*.{ZONE}/A"] == "wildcard"
    assert cats[f"{ZONE}/NS"] == "infra"
    assert cats[f"dns1.{ZONE}/A"] == "direct-access"
    assert cats[f"traefik.{ZONE}/A"] == "ingress-aliased"
    assert cats[f"jellyfin.{ZONE}/A"] == "direct-access"
    assert cats[f"ghost.{ZONE}/A"] == "disabled"
    shadow = [r for r in panel.rows if r.record.name == f"jellyfin.{ZONE}"][0]
    assert shadow.shadows == "jellyfin"


def test_zone_panel_flags_broken_wildcard(zsettings, monkeypatch):
    _mock_records(monkeypatch, [_record(f"*.{ZONE}", value="10.10.99.99")])
    panel = operations.zone_panel(zsettings)
    assert panel.available and not panel.wildcard_ok
    assert "broken" in panel.wildcard_detail
