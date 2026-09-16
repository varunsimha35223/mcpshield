"""Policy files: tune the rules without editing the scanner.

A policy is a TOML file, by default `.mcpshield.toml` in the working
directory or the home directory, or any path given with --policy.

    [severity]                  # override any rule, built-in or snapshot
    credential_reference = "DANGEROUS"
    embedded_url = "IGNORE"     # IGNORE drops the rule entirely

    [phrases]                   # extra substrings, case-insensitive
    hidden_instruction = ["you are now", "act as"]
    company_policy = ["contact hr"]      # a new rule; WARNING unless [severity] says otherwise

    [patterns]                  # extra regexes, applied to the raw text
    internal_host = ['(?i)\\binternal\\.corp\\b']

    [allow]
    phrases = ["api key"]                # never flag these built-in phrases
    items = ["tool:get_secret", "prompt:*"]     # kind:name globs; findings kept but marked allowed
    servers = ["trusted-*"]              # server-name globs (audit) or scan targets
"""

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

from mcpshield.detector import DANGEROUS, PATTERN_RULES, PHRASE_RULES, WARNING

IGNORE = "IGNORE"
SEVERITIES = {DANGEROUS, WARNING, IGNORE}
SECTIONS = {"severity", "phrases", "patterns", "allow"}
ALLOW_KEYS = {"phrases", "items", "servers"}
DEFAULT_FILENAME = ".mcpshield.toml"

TEMPLATE = '''# MCPShield policy. Every section is optional. See `mcpshield policy --help`.

[severity]
# Override the severity of any rule: "DANGEROUS", "WARNING", or "IGNORE" to drop it.
# credential_reference = "DANGEROUS"
# embedded_url = "IGNORE"
# new_item = "IGNORE"          # snapshot rules can be tuned too

[phrases]
# Extra case-insensitive substrings for an existing rule, or a brand-new rule
# (new rules are WARNING unless [severity] says otherwise).
# hidden_instruction = ["you are now", "act as"]
# company_policy = ["contact hr before"]

[patterns]
# Extra regular expressions, matched against the raw text. Use (?i) for case-insensitive.
# internal_host = ['(?i)\\binternal\\.corp\\b']

[allow]
# Built-in phrases that should never fire.
# phrases = ["api key"]
# Items whose findings are kept in the report but do not affect the risk level.
# Globs on "kind:name" where kind is tool, resource, resource_template or prompt.
# items = ["tool:get_secret", "prompt:*"]
# Servers (audit) or scan targets whose findings are all allowed.
# servers = ["trusted-*"]
'''


class PolicyError(ValueError):
    """A policy file is malformed."""


def _str_list(value, where):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings")
    return [v for v in value if v]


@dataclass
class Policy:
    severity: dict = field(default_factory=dict)  # rule -> DANGEROUS | WARNING | IGNORE
    extra_phrases: dict = field(default_factory=dict)  # rule -> [phrase]
    extra_patterns: dict = field(default_factory=dict)  # rule -> [regex source]
    allow_phrases: list = field(default_factory=list)
    allow_items: list = field(default_factory=list)
    allow_servers: list = field(default_factory=list)
    source: str | None = None

    def __post_init__(self):
        self.phrase_rules = self._build_phrase_rules()
        self.pattern_rules = self._build_pattern_rules()

    # --- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, data, source=None):
        if not isinstance(data, dict):
            raise PolicyError("policy must be a table at the top level")
        unknown = set(data) - SECTIONS
        if unknown:
            raise PolicyError(f"unknown section(s): {', '.join(sorted(unknown))}; expected {', '.join(sorted(SECTIONS))}")

        severity = {}
        for rule, level in (data.get("severity") or {}).items():
            if not isinstance(level, str) or level.upper() not in SEVERITIES:
                raise PolicyError(f"[severity] {rule}: expected one of {', '.join(sorted(SEVERITIES))}, got {level!r}")
            severity[rule] = level.upper()

        extra_phrases = {}
        for rule, phrases in (data.get("phrases") or {}).items():
            extra_phrases[rule] = [p.lower() for p in _str_list(phrases, f"[phrases] {rule}")]

        extra_patterns = {}
        for rule, patterns in (data.get("patterns") or {}).items():
            sources = _str_list(patterns, f"[patterns] {rule}")
            for src in sources:
                try:
                    re.compile(src)
                except re.error as exc:
                    raise PolicyError(f"[patterns] {rule}: invalid regex {src!r}: {exc}") from exc
            extra_patterns[rule] = sources

        allow = data.get("allow") or {}
        if not isinstance(allow, dict):
            raise PolicyError("[allow] must be a table")
        unknown = set(allow) - ALLOW_KEYS
        if unknown:
            raise PolicyError(f"[allow] unknown key(s): {', '.join(sorted(unknown))}")

        return cls(
            severity=severity,
            extra_phrases=extra_phrases,
            extra_patterns=extra_patterns,
            allow_phrases=[p.lower() for p in _str_list(allow.get("phrases", []), "[allow] phrases")],
            allow_items=_str_list(allow.get("items", []), "[allow] items"),
            allow_servers=_str_list(allow.get("servers", []), "[allow] servers"),
            source=source,
        )

    @classmethod
    def load(cls, path):
        path = Path(path)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise PolicyError(f"{path}: {exc}") from exc
        try:
            return cls.from_dict(data, source=str(path))
        except PolicyError as exc:
            raise PolicyError(f"{path}: {exc}") from exc

    def _build_phrase_rules(self):
        rules = []
        seen = set()
        for rule in PHRASE_RULES:
            phrases = [p for p in rule["phrases"] if p not in self.allow_phrases]
            phrases += [p for p in self.extra_phrases.get(rule["rule"], []) if p not in phrases]
            rules.append({"rule": rule["rule"], "severity": rule["severity"], "phrases": phrases})
            seen.add(rule["rule"])
        for name, phrases in self.extra_phrases.items():
            if name not in seen:
                rules.append({"rule": name, "severity": self.severity.get(name, WARNING), "phrases": list(phrases)})
        return rules

    def _build_pattern_rules(self):
        rules = list(PATTERN_RULES)
        for name, sources in self.extra_patterns.items():
            for src in sources:
                rules.append({
                    "rule": name,
                    "severity": self.severity.get(name, WARNING),
                    "pattern": re.compile(src),
                    "label": "pattern",
                })
        return rules

    # --- application --------------------------------------------------------

    def server_allowed(self, server):
        return bool(server) and any(fnmatch.fnmatchcase(server, g) for g in self.allow_servers)

    def item_allowed(self, kind, name, server=None):
        if self.server_allowed(server):
            return True
        key = f"{kind}:{name}"
        return any(fnmatch.fnmatchcase(key, g) for g in self.allow_items)

    def filter_findings(self, findings, kind=None, name=None, server=None):
        """Apply severity overrides and allow-lists. Returns a new list."""
        allowed = self.item_allowed(kind, name, server) if kind and name else False
        out = []
        for f in findings:
            level = self.severity.get(f["rule"])
            if level == IGNORE:
                continue
            f = dict(f)
            if level:
                f["severity"] = level
            if allowed:
                f["allowed"] = True
            out.append(f)
        return out

    def is_empty(self):
        return not any([
            self.severity, self.extra_phrases, self.extra_patterns,
            self.allow_phrases, self.allow_items, self.allow_servers,
        ])


EMPTY = Policy()


def discover_policy(cwd=None, home=None):
    """First existing default policy file: ./.mcpshield.toml, then ~/.mcpshield.toml."""
    for base in (Path(cwd or Path.cwd()), Path(home or Path.home())):
        candidate = base / DEFAULT_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_policy(path=None):
    """Explicit path, else discovered file, else the empty policy."""
    if path is None:
        path = discover_policy()
    if path is None:
        return EMPTY
    return Policy.load(path)
