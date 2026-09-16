"""End-to-end: launch the poisoned fixture server over stdio and scan it."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner import app, collect_tools

ROOT = Path(__file__).resolve().parent.parent
EVIL = f"{sys.executable} {ROOT / 'evil_server.py'}"
CLEAN = f"{sys.executable} {ROOT / 'tests' / 'clean_server.py'}"

runner = CliRunner()


@pytest.fixture(scope="module")
def report():
    import asyncio

    return {entry["name"]: entry for entry in asyncio.run(collect_tools(EVIL))}


def test_fixture_exposes_all_tools(report):
    assert set(report) == {"add_numbers", "get_weather", "read_notes", "format_text", "lookup_zip"}


def test_clean_tool_is_safe(report):
    assert report["add_numbers"]["risk"] == "SAFE"
    assert report["add_numbers"]["findings"] == []
    assert report["add_numbers"]["inputs"] == ["a", "b"]


def test_poisoned_description(report):
    rules = {f["rule"] for f in report["get_weather"]["findings"]}
    assert report["get_weather"]["risk"] == "DANGEROUS"
    assert {"hidden_instruction", "exfiltration", "credential_reference", "embedded_url", "sensitive_path"} <= rules


def test_hidden_unicode(report):
    assert report["read_notes"]["risk"] == "DANGEROUS"
    assert any(f["rule"] == "invisible_unicode" for f in report["read_notes"]["findings"])


def test_tool_shadowing(report):
    assert report["format_text"]["risk"] == "DANGEROUS"
    assert any(f["rule"] == "tool_shadowing" for f in report["format_text"]["findings"])


def test_poisoned_parameter(report):
    findings = report["lookup_zip"]["findings"]
    assert report["lookup_zip"]["risk"] == "DANGEROUS"
    assert all(f["location"] == "input.zip_code" for f in findings)


def test_cli_json_output_and_exit_code():
    result = runner.invoke(app, [EVIL, "--json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert len(data) == 5


def test_cli_rejects_invalid_fail_on():
    result = runner.invoke(app, [EVIL, "--fail-on", "bogus"])
    assert result.exit_code == 2
    assert "must be one of" in result.output


def test_cli_clean_server_exits_zero():
    result = runner.invoke(app, [CLEAN, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert [d["risk"] for d in data] == ["SAFE"]


def test_cli_fail_on_warning_is_stricter():
    # The clean server has no findings at all, so even --fail-on safe passes...
    assert runner.invoke(app, [CLEAN, "--fail-on", "warning"]).exit_code == 0
    # ...while the poisoned one fails at any threshold.
    assert runner.invoke(app, [EVIL, "--fail-on", "warning"]).exit_code == 1


def test_cli_table_output_mentions_summary():
    result = runner.invoke(app, [EVIL])
    assert result.exit_code == 1
    assert "Summary:" in result.stdout
    assert "DANGEROUS 4" in result.stdout
    assert "SAFE 1" in result.stdout


# --- Snapshot / rug-pull end to end -----------------------------------------

MUTABLE = ROOT / "tests" / "mutable_server.py"


def mutable(desc_file, text):
    desc_file.write_text(text, encoding="utf-8")
    return f"{sys.executable} {MUTABLE} {desc_file}"


def test_snapshot_lifecycle(tmp_path):
    desc = tmp_path / "desc.txt"
    snap = tmp_path / "baseline.json"

    # First run: clean server, baseline is written, exit 0.
    result = runner.invoke(app, [mutable(desc, "Get the weather for a city."), "--json", "--snapshot", str(snap)])
    assert result.exit_code == 0, result.output
    assert snap.exists()
    assert "Baseline saved" in result.stderr

    # Second run, nothing changed: still exit 0, no snapshot findings.
    result = runner.invoke(app, [mutable(desc, "Get the weather for a city."), "--json", "--snapshot", str(snap)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data[0]["findings"] == []

    # Rug pull: description changes to something the static rules would
    # never flag. Snapshot still catches it.
    result = runner.invoke(app, [mutable(desc, "Get the weather for a city, updated."), "--json", "--snapshot", str(snap)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data[0]["risk"] == "DANGEROUS"
    assert [f["rule"] for f in data[0]["findings"]] == ["rug_pull"]

    # Accept the change: still reported this run, but the baseline moves.
    result = runner.invoke(
        app,
        [mutable(desc, "Get the weather for a city, updated."), "--json", "--snapshot", str(snap), "--update-snapshot"],
    )
    assert result.exit_code == 1
    assert "Baseline updated" in result.stderr

    # Next run is clean against the new baseline.
    result = runner.invoke(app, [mutable(desc, "Get the weather for a city, updated."), "--json", "--snapshot", str(snap)])
    assert result.exit_code == 0, result.output


def test_snapshot_table_shows_baseline_line(tmp_path):
    desc = tmp_path / "desc.txt"
    snap = tmp_path / "baseline.json"
    runner.invoke(app, [mutable(desc, "One."), "--snapshot", str(snap)])
    result = runner.invoke(app, [mutable(desc, "Two."), "--snapshot", str(snap)])
    assert result.exit_code == 1
    assert "rug_pull" in result.stdout
    assert "1 changed" in result.stdout


def test_update_snapshot_requires_snapshot():
    result = runner.invoke(app, [EVIL, "--update-snapshot"])
    assert result.exit_code == 2
    assert "requires --snapshot" in result.output
