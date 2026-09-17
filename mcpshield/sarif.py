"""SARIF 2.1.0 output, so findings can be uploaded to GitHub code scanning
(or any other SARIF consumer) and show up as annotations.

MCP servers are not source files, so each result carries a logical location
(the kind and name of the item) and, for audits, a physical location pointing
at the config file that defines the server. GitHub only annotates results
that have a physical location inside the repository.
"""

from mcpshield import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/varunsimha35223/mcpshield"

LEVELS = {"DANGEROUS": "error", "WARNING": "warning"}

RULE_HELP = {
    "hidden_instruction": "Description contains text that steers the model instead of describing the item.",
    "exfiltration": "Description instructs the model to send data somewhere.",
    "tool_shadowing": "Description tries to change how other tools behave.",
    "credential_reference": "Description mentions credentials, key files, or secret stores.",
    "embedded_url": "Description contains a URL, a common exfiltration target.",
    "encoded_payload": "Description contains a long base64-like blob.",
    "sensitive_path": "Description references a dotfile path under a home directory.",
    "invisible_unicode": "Text contains zero-width, bidi-control, or Unicode tag characters.",
    "missing_description": "Item has no description.",
    "rug_pull": "Item changed since the recorded baseline.",
    "new_item": "Item was not present in the recorded baseline.",
    "removed_item": "Item from the recorded baseline is no longer served.",
}


def _rule(rule_id):
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": RULE_HELP.get(rule_id, f"Custom rule '{rule_id}' from the policy file.")},
        "helpUri": f"{INFORMATION_URI}#risk-levels",
    }


def _message(server, entry, finding):
    kind = entry.get("kind", "tool")
    where = "" if finding["location"] == "description" else f" in {finding['location']}"
    text = f"{finding['rule']}: {finding['evidence']}{where} ({kind} '{entry['name']}'"
    if server:
        text += f" on server '{server}'"
    text += ")"
    if finding.get("allowed"):
        text += " [allowed by policy]"
    return text


def _result(server_entry, entry, finding, rule_index):
    server = server_entry.get("server")
    kind = entry.get("kind", "tool")
    result = {
        "ruleId": finding["rule"],
        "ruleIndex": rule_index,
        "level": "note" if finding.get("allowed") else LEVELS.get(finding["severity"], "warning"),
        "message": {"text": _message(server, entry, finding)},
        "locations": [{
            "logicalLocations": [{
                "name": entry["name"],
                "fullyQualifiedName": f"{server}/{kind}:{entry['name']}" if server else f"{kind}:{entry['name']}",
                "kind": kind,
            }],
        }],
        "partialFingerprints": {
            "mcpshield/item": f"{server or ''}|{kind}:{entry['name']}|{finding['rule']}|{finding['location']}",
        },
        "properties": {
            "server": server,
            "kind": kind,
            "item": entry["name"],
            "severity": finding["severity"],
            "location": finding["location"],
            "allowed": bool(finding.get("allowed")),
        },
    }
    config = server_entry.get("config")
    if config:
        result["locations"][0]["physicalLocation"] = {
            "artifactLocation": {"uri": str(config)},
        }
    if finding.get("allowed"):
        result["suppressions"] = [{"kind": "external", "justification": "allowed by mcpshield policy"}]
    return result


def to_sarif(servers, command_line=None):
    """Build a SARIF log from audit-style results.

    `servers` is a list of dicts with keys server, config (optional), status,
    error, tools (the item entries). A plain scan wraps its report as one
    server entry with config=None.
    """
    rules = []
    rule_index = {}
    results = []
    notifications = []

    for server_entry in servers:
        if server_entry.get("status") in ("error", "skipped"):
            notifications.append({
                "level": "error" if server_entry["status"] == "error" else "note",
                "message": {"text": f"server '{server_entry['server']}' {server_entry['status']}: {server_entry.get('error')}"},
            })
            continue
        for entry in server_entry.get("tools", []):
            for finding in entry.get("findings", []):
                rid = finding["rule"]
                if rid not in rule_index:
                    rule_index[rid] = len(rules)
                    rules.append(_rule(rid))
                results.append(_result(server_entry, entry, finding, rule_index[rid]))

    invocation = {"executionSuccessful": True}
    if command_line:
        invocation["commandLine"] = command_line
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcpshield",
                    "version": __version__,
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                },
            },
            "invocations": [invocation],
            "results": results,
        }],
    }
