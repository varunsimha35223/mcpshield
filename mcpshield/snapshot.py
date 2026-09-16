"""Baseline snapshots for rug-pull detection.

A "rug pull" is a server whose tools look clean when you install them and
whose descriptions change later, after the user has approved them. Static
rules can't see that. A snapshot records a fingerprint of every tool on the
first scan; later scans diff against it and flag anything that moved.

Snapshot file format (JSON):
    {
      "version": 1,
      "created": "<ISO-8601 UTC>",
      "server": "<command used to launch the server>",
      "tools": {
        "<tool name>": {
          "fingerprint": "<sha256>",
          "description": "<description text at baseline>"
        }
      }
    }
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from mcpshield.detector import DANGEROUS, WARNING, risk_from_findings

SNAPSHOT_VERSION = 1


def fingerprint(description, input_schema):
    """Stable hash of what the model actually sees for a tool."""
    payload = json.dumps(
        {"description": description or "", "input_schema": input_schema or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_snapshot(report, server=""):
    """Turn a scan report (list of tool entries) into a snapshot dict."""
    return {
        "version": SNAPSHOT_VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "server": server,
        "tools": {
            entry["name"]: {
                "fingerprint": entry["fingerprint"],
                "description": entry["description"],
            }
            for entry in report
        },
    }


def load_snapshot(path):
    path = Path(path)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != SNAPSHOT_VERSION:
        raise ValueError(f"{path}: unsupported snapshot version {data.get('version')!r}")
    return data


def save_snapshot(path, snapshot):
    Path(path).write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def diff_snapshot(baseline, current):
    """Compare two snapshots. Returns dict of name lists: changed, added, removed, unchanged."""
    old_tools = baseline["tools"]
    new_tools = current["tools"]
    result = {"changed": [], "added": [], "removed": [], "unchanged": []}
    for name, new in new_tools.items():
        old = old_tools.get(name)
        if old is None:
            result["added"].append(name)
        elif old["fingerprint"] != new["fingerprint"]:
            result["changed"].append(name)
        else:
            result["unchanged"].append(name)
    for name in old_tools:
        if name not in new_tools:
            result["removed"].append(name)
    return result


def apply_diff(report, baseline, diff):
    """Fold a diff into the scan report as findings. Mutates and returns the report.

    - changed tool  -> DANGEROUS "rug_pull" finding on that tool
    - added tool    -> WARNING "new_tool" finding on that tool
    - removed tool  -> a synthetic report entry with a WARNING "removed_tool" finding
    """
    created = baseline.get("created", "unknown date")[:10]  # date only; keep the table readable
    by_name = {entry["name"]: entry for entry in report}

    for name in diff["changed"]:
        entry = by_name[name]
        old_desc = baseline["tools"][name]["description"]
        what = "description" if old_desc != entry["description"] else "input schema"
        entry["findings"].append({
            "rule": "rug_pull",
            "severity": DANGEROUS,
            "evidence": f"{what} changed since baseline {created}",
            "location": "snapshot",
        })
        entry["risk"] = risk_from_findings(entry["findings"])

    for name in diff["added"]:
        entry = by_name[name]
        entry["findings"].append({
            "rule": "new_tool",
            "severity": WARNING,
            "evidence": f"not present in baseline {created}",
            "location": "snapshot",
        })
        entry["risk"] = risk_from_findings(entry["findings"])

    for name in diff["removed"]:
        report.append({
            "name": name,
            "risk": WARNING,
            "description": baseline["tools"][name]["description"],
            "fingerprint": baseline["tools"][name]["fingerprint"],
            "findings": [{
                "rule": "removed_tool",
                "severity": WARNING,
                "evidence": f"present in baseline {created}, missing now",
                "location": "snapshot",
            }],
            "inputs": [],
        })

    return report
