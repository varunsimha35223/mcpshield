"""Static checks for MCP tool poisoning.

Every check returns a list of findings. A finding is a dict with:
    rule      - short machine-readable name of the check that fired
    severity  - "DANGEROUS" or "WARNING"
    evidence  - the phrase, pattern, or character that triggered it
    location  - where it was found: "description" or "input.<param>"

`assess_tool` aggregates the findings for a tool into a single risk level.
"""

import re

DANGEROUS = "DANGEROUS"
WARNING = "WARNING"
SAFE = "SAFE"

# Plain substring matches, case-insensitive.
PHRASE_RULES = [
    {
        # Text that tries to steer the model rather than describe the tool.
        "rule": "hidden_instruction",
        "severity": DANGEROUS,
        "phrases": [
            "ignore previous instructions",
            "ignore all previous",
            "disregard",
            "do not tell the user",
            "do not mention",
            "don't tell the user",
            "without telling the user",
            "do not inform",
            "system prompt",
            "you must always",
            "<important>",
            "<system>",
            "<instructions>",
        ],
    },
    {
        # Instructing the model to ship data somewhere is an active attack.
        "rule": "exfiltration",
        "severity": DANGEROUS,
        "phrases": [
            "send to",
            "send it to",
            "send the contents",
            "post to",
            "upload to",
            "forward to",
            "include its contents",
            "include the contents",
        ],
    },
    {
        # Descriptions that reference *other* tools are trying to hijack them
        # (tool shadowing / cross-tool poisoning).
        "rule": "tool_shadowing",
        "severity": DANGEROUS,
        "phrases": [
            "when the user calls",
            "whenever the user uses",
            "before calling any other tool",
            "before using any other tool",
            "instead of the",
            "override the behavior",
            "modify the behavior",
            "for all other tools",
        ],
    },
    {
        # A legitimate secrets/vault tool can mention these, so flag, don't condemn.
        "rule": "credential_reference",
        "severity": WARNING,
        "phrases": [
            ".ssh",
            "id_rsa",
            "api key",
            "api_key",
            "apikey",
            "password",
            "credentials",
            "secret key",
            "access token",
            "private key",
            ".env",
            ".aws",
            "/etc/passwd",
            "/etc/shadow",
            ".netrc",
            "keychain",
        ],
    },
]

# Regex matches on the raw (not lowercased) text.
PATTERN_RULES = [
    {
        # A URL in a description is often the exfiltration target. Legit
        # tools sometimes link docs, so this is only a warning on its own;
        # an accompanying "send to" phrase escalates the tool anyway.
        "rule": "embedded_url",
        "severity": WARNING,
        # Trailing sentence punctuation is excluded from the match.
        "pattern": re.compile(r"https?://[^\s\"'<>)]*[^\s\"'<>).,;:!?]", re.IGNORECASE),
        "label": "url",
    },
    {
        # Long base64-looking runs are a way to smuggle instructions past
        # a human reader.
        "rule": "encoded_payload",
        "severity": WARNING,
        "pattern": re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"),
        "label": "base64-like blob",
    },
    {
        # Home-directory or absolute paths into places a weather tool has no
        # business reading.
        "rule": "sensitive_path",
        "severity": WARNING,
        "pattern": re.compile(r"(~|\$HOME|/home/\w+|/Users/\w+)/\.[\w.-]+"),
        "label": "dotfile path",
    },
]

# Named single characters that are invisible when rendered.
INVISIBLE_CHARACTERS = {
    "­": "soft hyphen",
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "\u200E": "left-to-right mark",
    "\u200F": "right-to-left mark",
    "\u202A": "left-to-right embedding",
    "\u202B": "right-to-left embedding",
    "\u202C": "pop directional formatting",
    "\u202D": "left-to-right override",
    "\u202E": "right-to-left override",
    "⁠": "word joiner",
    "⁡": "function application",
    "⁢": "invisible times",
    "⁣": "invisible separator",
    "⁤": "invisible plus",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
    "\u2068": "first strong isolate",
    "\u2069": "pop directional isolate",
    "﻿": "zero-width no-break space",
}

# Unicode "tag" characters (U+E0000..U+E007F) mirror ASCII and are the basis
# of ASCII-smuggling attacks: an LLM tokenizer reads them as text, a human
# sees nothing.
TAG_CHAR_RANGE = (0xE0000, 0xE007F)


def _finding(rule, severity, evidence, location):
    return {"rule": rule, "severity": severity, "evidence": evidence, "location": location}


def check_phrases(text, location="description"):
    findings = []
    if not text:
        return findings
    lowered = text.lower()
    for rule in PHRASE_RULES:
        for phrase in rule["phrases"]:
            if phrase in lowered:
                findings.append(_finding(rule["rule"], rule["severity"], phrase, location))
    return findings


def check_patterns(text, location="description"):
    findings = []
    if not text:
        return findings
    for rule in PATTERN_RULES:
        match = rule["pattern"].search(text)
        if match:
            snippet = match.group(0)
            if len(snippet) > 60:
                snippet = snippet[:57] + "..."
            findings.append(_finding(rule["rule"], rule["severity"], f"{rule['label']}: {snippet}", location))
    return findings


def check_hidden_characters(text, location="description"):
    findings = []
    if not text:
        return findings
    for char, name in INVISIBLE_CHARACTERS.items():
        if char in text:
            # Zero-width and bidi-control characters have no legitimate use in
            # a tool description; they only exist to hide text from a reviewer.
            findings.append(_finding("invisible_unicode", DANGEROUS, name, location))
    lo, hi = TAG_CHAR_RANGE
    tag_count = sum(1 for ch in text if lo <= ord(ch) <= hi)
    if tag_count:
        findings.append(
            _finding("invisible_unicode", DANGEROUS, f"{tag_count} unicode tag characters", location)
        )
    return findings


# Backwards-compatible name used by earlier phases.
def check_description(text):
    if not text:
        return [_finding("missing_description", WARNING, "tool has no description", "description")]
    return check_phrases(text)


def check_text(text, location="description"):
    """Run every content check on one piece of text."""
    return check_phrases(text, location) + check_patterns(text, location) + check_hidden_characters(text, location)


def risk_from_findings(findings):
    severities = {f["severity"] for f in findings}
    if DANGEROUS in severities:
        return DANGEROUS
    if WARNING in severities:
        return WARNING
    return SAFE


def assess_description(text):
    """Assess a single description string. Returns (risk, findings)."""
    if not text:
        findings = check_description(text)
    else:
        findings = check_text(text)
    return risk_from_findings(findings), findings


def check_name(name):
    """Names are short identifiers; the only poisoning that fits is hidden characters."""
    return check_hidden_characters(name, location="name")


def assess_tool(description, input_schema=None, name=None):
    """Assess a tool's description and every parameter description.

    Parameter descriptions are shown to the model exactly like the tool
    description, so they are an equally good place to hide instructions.
    """
    _, findings = assess_description(description)
    findings += check_name(name)
    properties = (input_schema or {}).get("properties", {}) or {}
    for param, spec in properties.items():
        if isinstance(spec, dict):
            findings += check_text(spec.get("description"), location=f"input.{param}")
    return risk_from_findings(findings), findings


def assess_prompt(description, arguments=None, name=None):
    """Assess a prompt's description and each argument description.

    `arguments` is a list of dicts with at least "name" and "description".
    """
    _, findings = assess_description(description)
    findings += check_name(name)
    for arg in arguments or []:
        if isinstance(arg, dict):
            findings += check_text(arg.get("description"), location=f"argument.{arg.get('name', '?')}")
    return risk_from_findings(findings), findings


def assess_resource(description, uri=None, name=None):
    """Assess a resource or resource template.

    Resources often have no description, and that is normal, so a missing
    one is not a finding here. The URI is checked for hidden characters and
    for embedded instructions, since it is shown to the model verbatim.
    """
    findings = check_text(description) if description else []
    findings += check_name(name)
    if uri:
        findings += check_hidden_characters(uri, location="uri")
        findings += check_phrases(uri, location="uri")
    return risk_from_findings(findings), findings
