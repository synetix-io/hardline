import json
import re
from pathlib import Path

import pytest

from hardline import ai
from hardline.parser import ParseError, parse, version_tuple
from hardline.redact import redact
from hardline.rules import RULES, _is_patched
from hardline.scoring import build_report

FIX = Path(__file__).parent.parent / "fixtures"


def load(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def ids(report) -> set[str]:
    return {f.id for f in report.findings}


# ── parser ───────────────────────────────────────────────────────────────────

def test_parse_header_and_sections():
    cfg = parse(load("vulnerable.rsc"))
    assert cfg.version == "7.19.2"
    assert cfg.model == "RB5009UG+S+"
    assert cfg.identity == "TWR7-EDGE"
    assert cfg.service("telnet").args["disabled"] == "no"
    assert cfg.wan_interface_list() == "WAN"
    assert cfg.wan_interfaces() == ["ether1-wan"]


def test_parse_set_with_find_target_and_quotes():
    cfg = parse('/interface ethernet\nset [ find default-name=ether1 ] name="my wan" comment="a=b c"\n')
    e = cfg.section("/interface ethernet")[0]
    assert e.cmd == "set"
    assert e.target == "[ find default-name=ether1 ]"
    assert e.args["name"] == "my wan"
    assert e.args["comment"] == "a=b c"


def test_parse_line_continuation():
    text = "/ip firewall filter\nadd action=drop chain=input \\\n    comment=\"x\" \\\n    in-interface-list=WAN\n"
    cfg = parse(text)
    e = cfg.section("/ip firewall filter")[0]
    assert e.args["in-interface-list"] == "WAN"
    assert e.args["comment"] == "x"


def test_parse_inline_path_command():
    cfg = parse("/system identity set name=EDGE1\n/user set admin disabled=yes\n")
    assert cfg.identity == "EDGE1"
    assert cfg.section("/user")[0].target == "admin"


@pytest.mark.parametrize("bad", ["", "   \n", "just some prose with no commands", "\x00\x01binary"])
def test_parse_rejects_garbage(bad):
    with pytest.raises(ParseError):
        parse(bad)


def test_version_compare():
    assert version_tuple("7.19.2") == (7, 19, 2)
    assert version_tuple("6.49.10 (long-term)") == (6, 49, 10)
    assert _is_patched("7.19.2") is False
    assert _is_patched("7.23.4") is True
    assert _is_patched("7.24.1") is False
    assert _is_patched("7.24.2") is True
    assert _is_patched("6.49.20") is False
    assert _is_patched("6.49.21") is True
    assert _is_patched(None) is None


# ── rules ────────────────────────────────────────────────────────────────────

def test_vulnerable_router_is_an_f_with_mikrotrick():
    r = build_report(parse(load("vulnerable.rsc")))
    assert r.grade == "F"
    assert r.mikrotrick_exposed is True
    assert r.counts["critical"] >= 3
    expected = {"HL-001", "HL-003", "HL-004", "HL-005", "HL-006", "HL-007", "HL-008", "HL-009",
                "HL-013", "HL-014", "HL-015", "HL-017", "HL-019", "HL-021", "HL-023", "HL-030",
                "HL-031", "HL-033"}
    assert expected <= ids(r), expected - ids(r)


def test_hardened_router_is_clean_or_near():
    r = build_report(parse(load("hardened.rsc")))
    assert r.mikrotrick_exposed is False
    assert r.patched is True
    assert r.counts["critical"] == 0 and r.counts["high"] == 0
    assert r.grade in ("A", "B"), [f.id for f in r.findings]
    assert "HL-003" not in ids(r)
    assert "HL-030" not in ids(r)


def test_critical_caps_grade_at_d():
    text = load("hardened.rsc").replace("7.24.2", "7.19.2")  # only the version regresses
    r = build_report(parse(text))
    assert "HL-001" in ids(r)
    assert r.findings[0].severity == "high"  # firewall + address restriction downgrade it
    text2 = text.replace('add action=drop chain=input comment="drop wan" in-interface-list=WAN log=yes log-prefix=WAN-DROP\n', "")
    r2 = build_report(parse(text2))
    assert r2.counts["critical"] >= 1
    assert r2.grade in ("D", "F")


def test_remediation_uses_real_names():
    r = build_report(parse(load("vulnerable.rsc")))
    f = next(f for f in r.findings if f.id == "HL-003")
    assert any("in-interface-list=WAN" in line for line in f.fix)
    f = next(f for f in r.findings if f.id == "HL-009")
    assert any("10.50.0.0/24" in line for line in f.fix)


def test_every_rule_has_fix_and_text():
    r = build_report(parse(load("vulnerable.rsc")))
    for f in r.findings:
        assert f.fix and f.observed and f.why, f.id
    assert len(RULES) >= 25


def test_findings_sorted_by_severity():
    r = build_report(parse(load("vulnerable.rsc")))
    order = ["critical", "high", "medium", "low", "info"]
    sevs = [order.index(f.severity) for f in r.findings]
    assert sevs == sorted(sevs)


def test_rules_never_touch_disk(tmp_path, monkeypatch):
    # The scan path must be pure: no file I/O with config content.
    import builtins
    real_open = builtins.open
    opened = []

    def spy(*a, **k):
        opened.append(a[0] if a else k.get("file"))
        return real_open(*a, **k)

    monkeypatch.setattr(builtins, "open", spy)
    build_report(parse(load("vulnerable.rsc")))
    assert opened == []


# ── redaction ────────────────────────────────────────────────────────────────

def test_redaction_strips_secrets():
    s = ('add name=admin group=full password=Admin123 '
         'community=public private-key="abc def" pre-shared-key=hunter2 '
         'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8d7c6b5a4 user@host')
    out = redact(s)
    for secret in ("Admin123", "hunter2", "abc def", "AAAAB3Nza"):
        assert secret not in out
    assert "password=<redacted>" in out
    assert "name=admin" in out  # non-secrets survive


def test_snmp_community_names_are_masked_but_defaults_kept():
    out = redact("add addresses=10.0.0.5/32 name=Kx93pQ2m read-access=yes\nset [ find default=yes ] name=public\nadd name=ether1-wan list=WAN")
    assert "Kx93pQ2m" not in out and "name=public" in out and "name=ether1-wan" in out


def test_report_evidence_is_redacted():
    r = build_report(parse(load("vulnerable.rsc")))
    blob = json.dumps(r.to_dict())
    for secret in ("Admin123", "noc2024", "Sp1ynx!"):
        assert secret not in blob


def test_ai_payload_has_no_secrets_and_no_raw_export():
    r = build_report(parse(load("vulnerable.rsc")))
    payload = ai._payload(r)
    for secret in ("Admin123", "noc2024", "Sp1ynx!"):
        assert secret not in payload
    assert "/ip firewall nat" not in payload  # only findings go out, never the export


# ── prompt injection & AI guardrails ────────────────────────────────────────

def test_injection_text_does_not_change_deterministic_findings():
    r = build_report(parse(load("injection.rsc")))
    assert r.grade in ("D", "F")
    assert "HL-005" in ids(r)  # telnet still flagged despite the comment
    assert "HL-001" in ids(r)  # 6.49.10 < 6.49.21 with ssh default-on
    assert "HL-999" not in ids(r)


def test_ai_scrub_removes_invented_rule_ids():
    out = ai._scrub("Fix HL-003 first, then HL-999 and HL-005.", {"HL-003", "HL-005"})
    assert "HL-999" not in out and "HL-003" in out and "HL-005" in out


def test_ai_disabled_by_env_returns_none(monkeypatch):
    monkeypatch.setenv("HARDLINE_AI", "0")
    r = build_report(parse(load("vulnerable.rsc")))
    assert ai.summarize(r) is None


def test_ai_failure_is_swallowed(monkeypatch):
    monkeypatch.delenv("HARDLINE_AI", raising=False)
    import anthropic

    class Boom:
        def __init__(self, *a, **k):
            raise anthropic.APIConnectionError(request=None)  # type: ignore[arg-type]

    monkeypatch.setattr(anthropic, "Anthropic", Boom)
    r = build_report(parse(load("vulnerable.rsc")))
    assert ai.summarize(r) is None


# ── web app ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLINE_AI", "0")
    from hardline import app as appmod
    monkeypatch.setattr(appmod, "COUNTER_PATH", tmp_path / "scans.json")
    from fastapi.testclient import TestClient
    return TestClient(appmod.app)


def test_index_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "MikroTrick" in r.text
    assert "Content-Security-Policy" in r.headers


def test_scan_form_returns_report(client):
    r = client.post("/scan", data={"export_text": load("vulnerable.rsc"), "ai": "0"})
    assert r.status_code == 200
    assert "MikroTrick exposed: YES" in r.text
    assert "HL-003" in r.text
    assert "Admin123" not in r.text
    assert 'class="letter g-F"' in r.text


def test_scan_upload(client):
    r = client.post("/scan", files={"file": ("router.rsc", load("hardened.rsc"), "text/plain")}, data={"ai": "0"})
    assert r.status_code == 200
    assert "MikroTrick exposed: no" in r.text


def test_scan_bad_input_is_400(client):
    r = client.post("/scan", data={"export_text": "hello world", "ai": "0"})
    assert r.status_code == 400
    assert "No RouterOS commands" in r.text


def test_api_scan_json(client):
    r = client.post("/api/scan", json={"export": load("vulnerable.rsc")})
    assert r.status_code == 200
    body = r.json()
    assert body["grade"] == "F" and body["mikrotrick_exposed"] is True
    assert any(f["id"] == "HL-001" for f in body["findings"])


def test_counter_increments_without_storing_config(client, tmp_path):
    client.post("/api/scan", json={"export": load("vulnerable.rsc")})
    client.post("/api/scan", json={"export": load("hardened.rsc")})
    data = json.loads((tmp_path / "scans.json").read_text())
    day = next(iter(data))
    assert data[day]["scans"] == 2
    assert data[day]["mikrotrick"] == 1
    assert "TWR7-EDGE" not in (tmp_path / "scans.json").read_text()


def test_rate_limit(client, monkeypatch):
    from hardline import app as appmod
    monkeypatch.setattr(appmod, "RATE_LIMIT", 2)
    appmod._hits.clear()
    for _ in range(2):
        assert client.post("/api/scan", json={"export": load("hardened.rsc")}).status_code == 200
    assert client.post("/api/scan", json={"export": load("hardened.rsc")}).status_code == 429


def test_large_payload_rejected(client):
    r = client.post("/scan", data={"export_text": "/ip service\n" + "set telnet disabled=yes\n" * 120000, "ai": "0"})
    assert r.status_code == 400


def test_parse_speed():
    import time
    big = "/ip firewall filter\n" + "\n".join(
        f"add action=accept chain=forward comment=\"rule {i}\" dst-port={1000 + i} protocol=tcp" for i in range(5000))
    t = time.perf_counter()
    build_report(parse(big))
    assert time.perf_counter() - t < 1.0
