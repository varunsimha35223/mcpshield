import json

import pytest

from mcpshield.detector import DANGEROUS, SAFE, WARNING
from mcpshield.snapshot import (
    SNAPSHOT_VERSION,
    apply_diff,
    build_snapshot,
    diff_snapshot,
    fingerprint,
    load_snapshot,
    save_snapshot,
)


def entry(name, description="Do a thing.", schema=None, findings=None):
    schema = schema or {"properties": {}}
    return {
        "name": name,
        "risk": SAFE,
        "description": description,
        "fingerprint": fingerprint(description, schema),
        "findings": findings or [],
        "inputs": list(schema.get("properties", {})),
    }


# --- fingerprint ------------------------------------------------------------


def test_fingerprint_is_stable():
    assert fingerprint("x", {"a": 1}) == fingerprint("x", {"a": 1})


def test_fingerprint_ignores_schema_key_order():
    assert fingerprint("x", {"a": 1, "b": 2}) == fingerprint("x", {"b": 2, "a": 1})


def test_fingerprint_changes_with_description():
    assert fingerprint("x", {}) != fingerprint("y", {})


def test_fingerprint_changes_with_schema():
    assert fingerprint("x", {"properties": {"a": {}}}) != fingerprint("x", {"properties": {"b": {}}})


def test_fingerprint_treats_none_as_empty():
    assert fingerprint(None, None) == fingerprint("", {})


# --- build / save / load ----------------------------------------------------


def test_snapshot_round_trip(tmp_path):
    snap = build_snapshot([entry("a"), entry("b", "Other.")], server="cmd")
    path = tmp_path / "snap.json"
    save_snapshot(path, snap)
    loaded = load_snapshot(path)
    assert loaded == snap
    assert loaded["version"] == SNAPSHOT_VERSION
    assert loaded["server"] == "cmd"
    assert set(loaded["tools"]) == {"a", "b"}
    assert loaded["tools"]["b"]["description"] == "Other."


def test_load_missing_returns_none(tmp_path):
    assert load_snapshot(tmp_path / "nope.json") is None


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"version": 99, "tools": {}}))
    with pytest.raises(ValueError):
        load_snapshot(path)


# --- diff -------------------------------------------------------------------


def test_diff_classifies_every_case():
    baseline = build_snapshot([entry("same"), entry("changed", "before"), entry("gone")])
    current = build_snapshot([entry("same"), entry("changed", "after"), entry("new")])
    diff = diff_snapshot(baseline, current)
    assert diff == {"changed": ["changed"], "added": ["new"], "removed": ["gone"], "unchanged": ["same"]}


def test_diff_identical_is_all_unchanged():
    report = [entry("a"), entry("b")]
    diff = diff_snapshot(build_snapshot(report), build_snapshot(report))
    assert diff["changed"] == diff["added"] == diff["removed"] == []
    assert sorted(diff["unchanged"]) == ["a", "b"]


# --- apply_diff -------------------------------------------------------------


def test_changed_description_is_a_dangerous_rug_pull():
    baseline = build_snapshot([entry("t", "before")])
    report = [entry("t", "after")]
    diff = diff_snapshot(baseline, build_snapshot(report))
    apply_diff(report, baseline, diff)
    assert report[0]["risk"] == DANGEROUS
    f = report[0]["findings"][0]
    assert f["rule"] == "rug_pull"
    assert f["location"] == "snapshot"
    assert f["evidence"].startswith("description changed")


def test_changed_schema_only_names_the_schema():
    baseline = build_snapshot([entry("t", "same", {"properties": {"a": {}}})])
    report = [entry("t", "same", {"properties": {"b": {}}})]
    diff = diff_snapshot(baseline, build_snapshot(report))
    apply_diff(report, baseline, diff)
    assert report[0]["findings"][0]["evidence"].startswith("input schema changed")


def test_added_tool_is_a_warning():
    baseline = build_snapshot([entry("old")])
    report = [entry("old"), entry("new")]
    apply_diff(report, baseline, diff_snapshot(baseline, build_snapshot(report)))
    by_name = {e["name"]: e for e in report}
    assert by_name["old"]["risk"] == SAFE
    assert by_name["new"]["risk"] == WARNING
    assert by_name["new"]["findings"][0]["rule"] == "new_tool"


def test_removed_tool_gets_a_synthetic_entry():
    baseline = build_snapshot([entry("keep"), entry("gone", "was here")])
    report = [entry("keep")]
    apply_diff(report, baseline, diff_snapshot(baseline, build_snapshot(report)))
    assert [e["name"] for e in report] == ["keep", "gone"]
    gone = report[1]
    assert gone["risk"] == WARNING
    assert gone["description"] == "was here"
    assert gone["inputs"] == []
    assert gone["findings"][0]["rule"] == "removed_tool"


def test_rug_pull_stacks_with_existing_findings():
    baseline = build_snapshot([entry("t", "clean")])
    existing = [{"rule": "credential_reference", "severity": WARNING, "evidence": "password", "location": "description"}]
    report = [entry("t", "store the password", findings=existing)]
    report[0]["risk"] = WARNING
    apply_diff(report, baseline, diff_snapshot(baseline, build_snapshot(report)))
    assert report[0]["risk"] == DANGEROUS
    assert {f["rule"] for f in report[0]["findings"]} == {"credential_reference", "rug_pull"}
