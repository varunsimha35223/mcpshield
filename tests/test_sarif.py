import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from mcpshield import __version__
from mcpshield.cli import app
from mcpshield.sarif import SARIF_VERSION, to_sarif
from conftest import plain

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EVIL = f"{sys.executable} {FIXTURES / 'evil_server.py'}"
runner = CliRunner()


def finding(rule, severity="WARNING", location="description", allowed=False):
    f = {"rule": rule, "severity": severity, "evidence": "ev", "location": location}
    if allowed:
        f["allowed"] = True
    return f


def server(name, tools, config="cfg.json", status="ok", error=None):
    return {"server": name, "config": config, "transport": "stdio", "status": status, "error": error, "tools": tools}


def item(name, findings, kind="tool", risk="WARNING"):
    return {"kind": kind, "name": name, "risk": risk, "description": "d", "fingerprint": "f", "findings": findings, "inputs": []}


# --- structure --------------------------------------------------------------


def test_envelope():
    log = to_sarif([], command_line="mcpshield scan x")
    assert log["version"] == SARIF_VERSION
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpshield"
    assert run["tool"]["driver"]["version"] == __version__
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []
    assert run["invocations"][0] == {"executionSuccessful": True, "commandLine": "mcpshield scan x"}


def test_levels_and_rule_dedupe():
    servers = [server("s", [
        item("a", [finding("exfiltration", "DANGEROUS"), finding("embedded_url")]),
        item("b", [finding("exfiltration", "DANGEROUS", location="input.q")], kind="prompt"),
    ])]
    run = to_sarif(servers)["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["exfiltration", "embedded_url"]
    assert [(r["ruleId"], r["ruleIndex"], r["level"]) for r in run["results"]] == [
        ("exfiltration", 0, "error"), ("embedded_url", 1, "warning"), ("exfiltration", 0, "error"),
    ]
    assert "in input.q" in run["results"][2]["message"]["text"]
    assert "prompt 'b'" in run["results"][2]["message"]["text"]
    assert "server 's'" in run["results"][2]["message"]["text"]


def test_locations():
    run = to_sarif([server("s", [item("a", [finding("x")], kind="resource")])])["runs"][0]
    loc = run["results"][0]["locations"][0]
    assert loc["logicalLocations"] == [{"name": "a", "fullyQualifiedName": "s/resource:a", "kind": "resource"}]
    assert loc["physicalLocation"] == {"artifactLocation": {"uri": "cfg.json"}}


def test_scan_without_config_has_no_physical_location():
    run = to_sarif([server("target", [item("a", [finding("x")])], config=None)])["runs"][0]
    loc = run["results"][0]["locations"][0]
    assert "physicalLocation" not in loc
    assert loc["logicalLocations"][0]["fullyQualifiedName"] == "target/tool:a"


def test_allowed_findings_are_notes_with_suppressions():
    run = to_sarif([server("s", [item("a", [finding("rug_pull", "DANGEROUS", allowed=True)])])])["runs"][0]
    r = run["results"][0]
    assert r["level"] == "note"
    assert r["suppressions"][0]["kind"] == "external"
    assert r["properties"]["allowed"] is True
    assert "[allowed by policy]" in r["message"]["text"]


def test_custom_rule_gets_generic_help():
    run = to_sarif([server("s", [item("a", [finding("company_policy")])])])["runs"][0]
    assert "Custom rule" in run["tool"]["driver"]["rules"][0]["shortDescription"]["text"]


def test_errors_and_skips_become_notifications():
    servers = [
        server("dead", [], status="error", error="boom"),
        server("ws", [], status="skipped", error="websocket transport not supported"),
        server("ok", [item("a", [finding("x")])]),
    ]
    run = to_sarif(servers)["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert [(n["level"], n["message"]["text"]) for n in notes] == [
        ("error", "server 'dead' error: boom"),
        ("note", "server 'ws' skipped: websocket transport not supported"),
    ]
    assert len(run["results"]) == 1


def test_fingerprints_are_stable_and_distinct():
    servers = [server("s", [item("a", [finding("x"), finding("x", location="input.q")])])]
    fps = [r["partialFingerprints"]["mcpshield/item"] for r in to_sarif(servers)["runs"][0]["results"]]
    assert len(set(fps)) == 2
    assert fps == [r["partialFingerprints"]["mcpshield/item"] for r in to_sarif(servers)["runs"][0]["results"]]


# --- CLI --------------------------------------------------------------------


def test_scan_sarif_to_stdout():
    result = runner.invoke(app, ["scan", EVIL, "--sarif"])
    assert result.exit_code == 1
    log = json.loads(result.stdout)
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpshield"
    assert any(r["level"] == "error" for r in run["results"])
    assert all("physicalLocation" not in r["locations"][0] for r in run["results"])
    # Under CliRunner the recorded command line is the test runner's own argv,
    # so only check that one was recorded.
    assert isinstance(run["invocations"][0]["commandLine"], str) and run["invocations"][0]["commandLine"]


def test_audit_sarif_to_file(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "evil": {"command": sys.executable, "args": [str(FIXTURES / "evil_server.py")]},
        "dead": {"command": "/definitely/not/a/real/binary"},
    }}))
    out = tmp_path / "report.sarif"
    result = runner.invoke(app, ["audit", str(cfg), "--sarif", "--output", str(out)])
    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    assert "Wrote" in plain(result.stderr)
    run = json.loads(out.read_text())["runs"][0]
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(cfg) for r in run["results"])
    assert run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"].startswith("server 'dead' error")


def test_json_to_file_keeps_scan_shape(tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["scan", EVIL, "--json", "-o", str(out)])
    assert result.exit_code == 1
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data[0]["kind"] == "tool"  # same list-of-items shape as stdout


def test_json_and_sarif_are_exclusive():
    result = runner.invoke(app, ["scan", EVIL, "--json", "--sarif"])
    assert result.exit_code == 2
    assert "mutually exclusive" in plain(result.output)


def test_output_requires_a_machine_format(tmp_path):
    result = runner.invoke(app, ["scan", EVIL, "--output", str(tmp_path / "x")])
    assert result.exit_code == 2
    assert "needs --json or --sarif" in plain(result.output)


def test_policy_allowed_show_as_notes_in_sarif(tmp_path):
    pol = tmp_path / "p.toml"
    pol.write_text('[allow]\nitems = ["*"]\n')
    result = runner.invoke(app, ["scan", EVIL, "--sarif", "--policy", str(pol)])
    assert result.exit_code == 0, result.output
    run = json.loads(result.stdout)["runs"][0]
    assert run["results"] and all(r["level"] == "note" and "suppressions" in r for r in run["results"])
