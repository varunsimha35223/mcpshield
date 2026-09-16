"""Baseline snapshots for rug-pull detection.

A "rug pull" is a server whose tools look clean when you install them and
whose descriptions change later, after the user has approved them. Static
rules can't see that. A snapshot records a fingerprint of every item on the
first scan; later scans diff against it and flag anything that moved.

Snapshot file format (JSON, version 2):
    {
      "version": 2,
      "created": "<ISO-8601 UTC>",
      "server": "<how the server was reached>",
      "items": {
        "<kind>:<name>": {
          "kind": "tool" | "resource" | "resource_template" | "prompt",
          "name": "<name>",
          "fingerprint": "<sha256>",
          "description": "<description text at baseline>"
        }
      }
    }

Version 1 files (tools only, keyed by bare name under "tools") are read and
upgraded in memory.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from mcpshield.detector import DANGEROUS, WARNING, risk_from_findings

SNAPSHOT_VERSION = 2


def fingerprint(description, payload):
    """Stable hash of what the model actually sees for an item.

    `payload` is whatever else defines the item: a tool's input schema, a
    prompt's argument list, a resource's URI and MIME type.
    """
    blob = json.dumps(
        {"description": description or "", "payload": payload or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def item_key(entry):
    return f"{entry.get('kind', 'tool')}:{entry['name']}"


def build_snapshot(report, server=""):
    """Turn a scan report (list of item entries) into a snapshot dict."""
    return {
        "version": SNAPSHOT_VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "server": server,
        "items": {
            item_key(entry): {
                "kind": entry.get("kind", "tool"),
                "name": entry["name"],
                "fingerprint": entry["fingerprint"],
                "description": entry["description"],
            }
            for entry in report
        },
    }


def _upgrade_v1(data):
    return {
        "version": SNAPSHOT_VERSION,
        "created": data.get("created", ""),
        "server": data.get("server", ""),
        "items": {
            f"tool:{name}": {"kind": "tool", "name": name, **record}
            for name, record in data.get("tools", {}).items()
        },
    }


def load_snapshot(path):
    path = Path(path)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("version")
    if version == 1:
        return _upgrade_v1(data)
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"{path}: unsupported snapshot version {version!r}")
    return data


def save_snapshot(path, snapshot):
    Path(path).write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def diff_snapshot(baseline, current):
    """Compare two snapshots. Returns dict of item-key lists: changed, added, removed, unchanged."""
    old_items = baseline["items"]
    new_items = current["items"]
    result = {"changed": [], "added": [], "removed": [], "unchanged": []}
    for key, new in new_items.items():
        old = old_items.get(key)
        if old is None:
            result["added"].append(key)
        elif old["fingerprint"] != new["fingerprint"]:
            result["changed"].append(key)
        else:
            result["unchanged"].append(key)
    for key in old_items:
        if key not in new_items:
            result["removed"].append(key)
    return result


def apply_diff(report, baseline, diff):
    """Fold a diff into the scan report as findings. Mutates and returns the report.

    - changed item  -> DANGEROUS "rug_pull" finding on that item
    - added item    -> WARNING "new_item" finding on that item
    - removed item  -> a synthetic report entry with a WARNING "removed_item" finding
    """
    created = baseline.get("created", "unknown date")[:10]  # date only; keep the table readable
    by_key = {item_key(entry): entry for entry in report}

    for key in diff["changed"]:
        entry = by_key[key]
        old_desc = baseline["items"][key]["description"]
        what = "description" if old_desc != entry["description"] else "definition"
        entry["findings"].append({
            "rule": "rug_pull",
            "severity": DANGEROUS,
            "evidence": f"{what} changed since baseline {created}",
            "location": "snapshot",
        })
        entry["risk"] = risk_from_findings(entry["findings"])

    for key in diff["added"]:
        entry = by_key[key]
        entry["findings"].append({
            "rule": "new_item",
            "severity": WARNING,
            "evidence": f"not present in baseline {created}",
            "location": "snapshot",
        })
        entry["risk"] = risk_from_findings(entry["findings"])

    for key in diff["removed"]:
        old = baseline["items"][key]
        report.append({
            "kind": old.get("kind", "tool"),
            "name": old["name"],
            "risk": WARNING,
            "description": old["description"],
            "fingerprint": old["fingerprint"],
            "findings": [{
                "rule": "removed_item",
                "severity": WARNING,
                "evidence": f"present in baseline {created}, missing now",
                "location": "snapshot",
            }],
            "inputs": [],
        })

    return report
