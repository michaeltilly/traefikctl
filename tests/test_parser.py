from traefikctl.core import parser


def test_scan_reads_tool_style_and_handwritten(settings):
    (settings.dynamic_dir / "dns-admin.yml").write_text(
        "http:\n  routers:\n    dns-admin:\n"
        '      rule: "Host(`dns-admin.shire.tillynet.com`)"\n'
        "      entryPoints: [websecure]\n"
        "      service: dns-admin\n"
        "  services:\n    dns-admin:\n      loadBalancer:\n"
        "        servers:\n          - url: \"http://10.10.30.30:5380\"\n"
    )
    (settings.dynamic_dir / "transports.yml").write_text(
        "http:\n  serversTransports:\n    insecure-backend:\n      insecureSkipVerify: true\n"
    )
    result = parser.scan(settings.dynamic_dir)
    assert not result.errors
    assert result.transports == {
        "insecure-backend": settings.dynamic_dir / "transports.yml"
    }
    (r,) = result.routers
    assert r.name == "dns-admin"
    assert r.host == "dns-admin.shire.tillynet.com"
    assert r.backends == ["http://10.10.30.30:5380"]
    assert r.insecure_transport == ""


def test_scan_flags_malformed_yaml_without_dying(settings):
    (settings.dynamic_dir / "broken.yml").write_text("http:\n  routers:\n   bad indent: [")
    (settings.dynamic_dir / "good.yml").write_text(
        "http:\n  routers:\n    good:\n      rule: \"Host(`g.x`)\"\n      service: good\n"
    )
    result = parser.scan(settings.dynamic_dir)
    assert [r.name for r in result.routers] == ["good"]
    assert settings.dynamic_dir / "broken.yml" in result.errors


def test_scan_tolerates_unconventional_files(settings):
    (settings.dynamic_dir / "weird.yml").write_text("tcp:\n  routers: {}\n")
    (settings.dynamic_dir / "empty.yml").write_text("")
    (settings.dynamic_dir / "multi.yml").write_text(
        "http:\n  routers:\n"
        "    a:\n      rule: \"Host(`a.x`)\"\n      service: a\n"
        "    b:\n      rule: \"PathPrefix(`/b`)\"\n      service: missing\n"
    )
    result = parser.scan(settings.dynamic_dir)
    assert not result.errors
    names = {r.name for r in result.routers}
    assert names == {"a", "b"}
    b = result.router("b")
    assert b.host == "" and b.backends == []
    assert len(result.routers_in(settings.dynamic_dir / "multi.yml")) == 2
