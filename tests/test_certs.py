"""Certificate monitor: expiry thresholds, renewal-health signals (including
the 2026-11 DNS-interception failure signature), probes, cache, web/CLI."""

from datetime import datetime, timedelta, timezone

import dns.exception
import dns.name
import dns.resolver
import httpx
import pytest

from traefikctl.core import certs
from traefikctl.core.certs import CertReport, Finding, ServedCert

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
LE = "countryName=US, organizationName=Let's Encrypt, commonName=YR2"


def cert(days, hosts=("k2pve.shire.tillynet.com",), serial="AA", issuer=LE, subject="commonName=*.shire.tillynet.com"):
    return ServedCert(
        hosts=list(hosts), issuer=issuer, subject=subject,
        sans=["*.shire.tillynet.com", "shire.tillynet.com"], serial=serial,
        not_before=NOW - timedelta(days=90 - days), not_after=NOW + timedelta(days=days),
    )


CLEAN = (False, "no answer from 192.0.2.53 (expected)")
ZONE_OK = ("tillynet.com", "")
ACME_OK = (True, "")


def renewal(settings, certs_, interception=CLEAN, zone=ZONE_OK, acme=ACME_OK):
    return certs.evaluate_renewal(certs_, interception, zone, acme, settings, NOW)


def levels(findings):
    return [f.level for f in findings]


# ---- settings ----

def test_defaults(settings):
    assert settings.cert_monitor is True
    assert settings.cert_warn_days == 21 and settings.cert_crit_days == 7
    assert settings.cert_renew_window_days == 30
    assert settings.acme_zone == "tillynet.com"  # suffix minus first label
    assert settings.public_resolvers == ["1.1.1.1", "8.8.8.8"]
    assert settings.cert_check_hosts == []


def test_env_overrides(monkeypatch):
    from traefikctl.config import Settings
    monkeypatch.setenv("TRAEFIKCTL_CERT_CHECK_HOSTS", "a.x.com, b.x.com,")
    monkeypatch.setenv("TRAEFIKCTL_ACME_ZONE", "example.org")
    monkeypatch.setenv("TRAEFIKCTL_CERT_MONITOR", "false")
    s = Settings()
    assert s.cert_check_hosts == ["a.x.com", "b.x.com"]
    assert s.acme_zone == "example.org"
    assert s.cert_monitor is False


# ---- expiry ----

@pytest.mark.parametrize("days,level,text", [
    (89, "ok", "days remaining"),
    (21.5, "ok", "days remaining"),
    (20, "warn", "expires in 20.0 days"),
    (6.9, "crit", "expires in 6.9 days"),
    (-1.8, "crit", "EXPIRED 1.8 days ago"),
])
def test_expiry_thresholds(settings, days, level, text):
    [f] = certs.evaluate_expiry([cert(days)], settings, NOW)
    assert f.level == level and text in f.summary


def test_expiry_is_issuer_agnostic(settings):
    [f] = certs.evaluate_expiry(
        [cert(10, issuer="countryName=US, organizationName=DigiCert Inc, commonName=X")],
        settings, NOW)
    assert f.level == "warn" and "DigiCert" in f.detail


def test_expiry_default_cert_is_critical(settings):
    c = cert(300, subject="commonName=TRAEFIK DEFAULT CERT", issuer="commonName=TRAEFIK DEFAULT CERT")
    [f] = certs.evaluate_expiry([c], settings, NOW)
    assert f.level == "crit" and "default certificate" in f.summary


def test_expiry_probe_error_is_critical(settings):
    [f] = certs.evaluate_expiry(
        [ServedCert(hosts=["x.shire.tillynet.com"], error="ConnectionRefusedError")], settings, NOW)
    assert f.level == "crit" and "x.shire.tillynet.com" in f.summary


def test_custom_thresholds(settings):
    settings.cert_warn_days, settings.cert_crit_days = 40, 14
    assert levels(certs.evaluate_expiry([cert(30), cert(10, serial="B")], settings, NOW)) == ["warn", "crit"]


# ---- grouping ----

def test_group_certs_merges_same_cert_keeps_errors_separate():
    a = cert(80, hosts=["a"]); b = cert(80, hosts=["b"]); other = cert(80, hosts=["c"], serial="ZZ")
    err = ServedCert(hosts=["d"], error="boom")
    grouped = certs.group_certs([a, b, other, err])
    assert [g.hosts for g in grouped] == [["a", "b"], ["c"], ["d"]]


# ---- renewal health ----

def test_renewal_all_clear(settings):
    fs = renewal(settings, [cert(80)])
    assert levels(fs) == ["ok", "ok", "ok", "ok"]
    assert "due in ~50 days" in fs[0].detail


def test_renewal_overdue_warn(settings):
    [f] = [f for f in renewal(settings, [cert(25)]) if "renewal" in f.summary]
    assert f.level == "warn" and "overdue" in f.summary and "~5 days ago" in f.summary


def test_renewal_inside_grace_is_not_overdue(settings):
    # 29 days left: window opened 1 day ago — Traefik's daily tick may not
    # have run yet. Not flagged.
    [f] = [f for f in renewal(settings, [cert(29)]) if "renewal" in f.summary]
    assert f.level == "ok"


def test_renewal_overdue_crit_when_near_expiry(settings):
    [f] = [f for f in renewal(settings, [cert(3)]) if "renewal" in f.summary]
    assert f.level == "crit"


def test_renewal_overdue_uses_soonest_cert(settings):
    fs = renewal(settings, [cert(80, serial="A"), cert(22, serial="B")])
    assert "~8 days ago" in fs[0].summary


def test_interception_detected_is_critical(settings):
    fs = renewal(settings, [cert(80)], interception=(True, "192.0.2.53 answered SOA dns1.shire.tillynet.com."))
    f = [f for f in fs if "port 53" in f.summary][0]
    assert f.level == "crit" and "Exempt this ingress" in f.detail


def test_interception_inconclusive_warns(settings):
    fs = renewal(settings, [cert(80)], interception=(None, "network unreachable"))
    assert any(f.level == "warn" and "inconclusive" in f.summary for f in fs)


def test_zone_is_internal_zone_the_2026_11_signature(settings):
    fs = renewal(settings, [cert(80)], zone=("shire.tillynet.com", ""))
    f = [f for f in fs if "challenge zone" in f.summary][0]
    assert f.level == "crit" and "zone could not be found" in f.detail


def test_zone_unexpected_warns(settings):
    fs = renewal(settings, [cert(80)], zone=("other.net", ""))
    assert any(f.level == "warn" and "expected tillynet.com" in f.summary for f in fs)


def test_zone_lookup_failure_warns(settings):
    fs = renewal(settings, [cert(80)], zone=(None, "timeout"))
    assert any(f.level == "warn" and "could not determine" in f.summary for f in fs)


def test_acme_unreachable_is_critical(settings):
    fs = renewal(settings, [cert(80)], acme=(False, "connect timeout"))
    assert any(f.level == "crit" and "ACME directory unreachable" in f.summary for f in fs)


def test_report_status_is_worst():
    r = CertReport(generated_at=NOW, expiry=[Finding("ok", "a")], renewal=[Finding("warn", "b"), Finding("crit", "c")])
    assert r.status == "crit" and r.expiry_status == "ok" and r.renewal_status == "crit"
    assert [p.summary for p in r.problems] == ["b", "c"]


# ---- probes (network mocked) ----

class FakeResolver:
    behavior = None
    def __init__(self, configure=False):
        self.nameservers, self.lifetime = [], 0
    def resolve(self, name, rtype, raise_on_no_answer=True):
        if isinstance(self.behavior, Exception):
            raise self.behavior
        return self.behavior


def _patch_resolver(monkeypatch, behavior):
    FakeResolver.behavior = behavior
    monkeypatch.setattr(certs.dns.resolver, "Resolver", FakeResolver)


def test_probe_interception_timeout_is_clean(settings, monkeypatch):
    _patch_resolver(monkeypatch, dns.resolver.LifetimeTimeout(timeout=2, errors=[]))
    assert certs.probe_interception(settings)[0] is False


def test_probe_interception_answer_is_intercepted(settings, monkeypatch):
    class Ans:
        rrset = ["dns1.shire.tillynet.com. hostadmin.shire.tillynet.com. 54 900 300 604800 900"]
    _patch_resolver(monkeypatch, Ans())
    hit, detail = certs.probe_interception(settings)
    assert hit is True and "dns1.shire.tillynet.com." in detail


def test_probe_interception_error_response_is_intercepted(settings, monkeypatch):
    _patch_resolver(monkeypatch, dns.resolver.NXDOMAIN())
    assert certs.probe_interception(settings)[0] is True


def test_probe_challenge_zone(settings, monkeypatch):
    monkeypatch.setattr(certs.dns.resolver, "zone_for_name",
                        lambda name, resolver=None: dns.name.from_text("tillynet.com"))
    assert certs.probe_challenge_zone(settings) == ("tillynet.com", "")


def test_probe_challenge_zone_failure(settings, monkeypatch):
    def boom(name, resolver=None):
        raise dns.exception.Timeout()
    monkeypatch.setattr(certs.dns.resolver, "zone_for_name", boom)
    zone, err = certs.probe_challenge_zone(settings)
    assert zone is None and err


def test_probe_acme_directory(settings, monkeypatch):
    class R:
        def raise_for_status(self): pass
        def json(self): return {"newOrder": "https://x/new-order"}
    monkeypatch.setattr(certs.httpx, "get", lambda url, timeout: R())
    assert certs.probe_acme_directory(settings) == (True, "")
    def down(url, timeout):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(certs.httpx, "get", down)
    assert certs.probe_acme_directory(settings)[0] is False


def test_check_hosts_combines_routers_and_extras(settings):
    (settings.dynamic_dir / "k2pve.yml").write_text(
        'http:\n  routers:\n    k2pve:\n      rule: "Host(`k2pve.shire.tillynet.com`)"\n      service: k2pve\n')
    settings.cert_check_hosts = ["ingress02.shire.tillynet.com", "K2PVE.shire.tillynet.com"]
    assert certs.check_hosts(settings) == ["k2pve.shire.tillynet.com", "ingress02.shire.tillynet.com"]


def test_build_report_end_to_end(settings, monkeypatch):
    settings.cert_check_hosts = ["a.shire.tillynet.com", "b.shire.tillynet.com"]
    monkeypatch.setattr(certs, "probe_cert", lambda h, s: cert(25, hosts=[h]))
    monkeypatch.setattr(certs, "probe_interception", lambda s: (True, "answered"))
    monkeypatch.setattr(certs, "probe_challenge_zone", lambda s: ("shire.tillynet.com", ""))
    monkeypatch.setattr(certs, "probe_acme_directory", lambda s: (True, ""))
    r = certs.build_report(settings, now=NOW)
    assert len(r.certs) == 1 and r.certs[0].hosts == ["a.shire.tillynet.com", "b.shire.tillynet.com"]
    assert r.status == "crit"
    d = r.to_dict()
    assert d["status"] == "crit" and d["certs"][0]["days_remaining"] == 25.0


def test_monitor_survives_probe_crash(settings, monkeypatch):
    def crash(s):
        raise RuntimeError("bug")
    monkeypatch.setattr(certs, "build_report", crash)
    mon = certs.CertMonitor(settings)
    r = mon.refresh()
    assert r.status == "warn" and mon.report is r


# ---- web + CLI ----

@pytest.fixture
def client(settings, monkeypatch):
    from fastapi.testclient import TestClient
    from traefikctl.web import app as webapp
    monkeypatch.setattr(webapp, "settings", settings)
    monkeypatch.setattr(webapp.cert_monitor, "settings", settings)
    monkeypatch.setattr(webapp.cert_monitor, "start", lambda: None)
    webapp.templates.env.globals["cert_report"] = lambda: webapp.cert_monitor.report
    return TestClient(webapp.app), webapp


def _set_report(webapp, status):
    f = {"ok": Finding("ok", "fine"), "warn": Finding("warn", "renewal overdue — test"),
         "crit": Finding("crit", "DNS is being intercepted on port 53")}[status]
    webapp.cert_monitor._report = CertReport(generated_at=NOW, certs=[cert(80)], expiry=[Finding("ok", "x")], renewal=[f])


def test_web_banner_on_every_page_when_failing(client):
    c, webapp = client
    _set_report(webapp, "crit")
    r = c.get("/")
    assert "Certificate CRITICAL" in r.text and "DNS is being intercepted" in r.text
    assert "TLS CRIT" in r.text


def test_web_no_banner_when_ok(client):
    c, webapp = client
    _set_report(webapp, "ok")
    r = c.get("/")
    assert "Certificate CRITICAL" not in r.text and "Certificate warning" not in r.text
    assert "TLS OK" in r.text


def test_web_certs_page_renders(client):
    c, webapp = client
    _set_report(webapp, "warn")
    r = c.get("/certs")
    assert r.status_code == 200
    assert "Renewal health" in r.text and "renewal overdue" in r.text and "k2pve.shire.tillynet.com" in r.text


def test_web_api_certs(client):
    c, webapp = client
    _set_report(webapp, "ok")
    j = c.get("/api/certs").json()
    assert j["enabled"] is True and j["status"] == "ok"


def test_cli_exit_codes(settings, monkeypatch):
    from typer.testing import CliRunner
    from traefikctl import cli
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    for status, code in (("ok", 0), ("warn", 1), ("crit", 2)):
        rep = CertReport(generated_at=NOW, renewal=[Finding(status, f"{status} finding")])
        monkeypatch.setattr(certs, "build_report", lambda s, r=rep: r)
        res = CliRunner().invoke(cli.cli, ["certs"])
        assert res.exit_code == code, res.output
