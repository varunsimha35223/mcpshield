import json

import pytest

from mcpshield.config import ServerSpec, candidate_config_paths, discover_configs, load_servers


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_claude_desktop_shape(tmp_path):
    cfg = write(tmp_path / "claude_desktop_config.json", {
        "mcpServers": {
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
            "gh": {"command": "docker", "args": ["run", "ghcr.io/x/y"], "env": {"GITHUB_TOKEN": "abc"}},
        }
    })
    specs = load_servers(cfg)
    assert [s.name for s in specs] == ["fs", "gh"]
    assert specs[0] == ServerSpec(
        name="fs", transport="stdio", command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], env={}, url=None, source=str(cfg),
    )
    assert specs[1].env == {"GITHUB_TOKEN": "abc"}


def test_vscode_servers_key(tmp_path):
    cfg = write(tmp_path / "mcp.json", {"servers": {"py": {"type": "stdio", "command": "python", "args": ["s.py"]}}})
    (spec,) = load_servers(cfg)
    assert spec.name == "py" and spec.transport == "stdio" and spec.command == "python"


@pytest.mark.parametrize(
    "entry,transport",
    [
        ({"url": "https://mcp.example.com/sse"}, "http"),
        ({"type": "http", "url": "https://mcp.example.com"}, "http"),
        ({"type": "sse", "url": "https://mcp.example.com/sse"}, "sse"),
        ({"type": "HTTP", "url": "https://x"}, "http"),
    ],
)
def test_remote_entries_keep_their_transport(tmp_path, entry, transport):
    cfg = write(tmp_path / "c.json", {"mcpServers": {"remote": entry}})
    (spec,) = load_servers(cfg)
    assert spec.transport == transport
    assert spec.url == entry["url"]
    assert spec.command is None


def test_claude_code_user_config_with_projects(tmp_path):
    cfg = write(tmp_path / ".claude.json", {
        "numStartups": 12,
        "mcpServers": {"global": {"command": "a"}},
        "projects": {
            "/Users/me/proj1": {"allowedTools": [], "mcpServers": {"local": {"command": "b"}}},
            "/Users/me/proj2": {"mcpServers": {"local": {"command": "c"}, "global": {"command": "a"}}},
        },
    })
    specs = {s.name: s for s in load_servers(cfg)}
    # "global" is identical in both places, so it is not duplicated.
    assert specs["global"].command == "a"
    # "local" differs between projects, so the second gets a scoped name.
    assert specs["local"].command == "b"
    assert specs["local [proj2]"].command == "c"
    assert len(specs) == 3


def test_args_and_env_are_coerced_to_strings(tmp_path):
    cfg = write(tmp_path / "c.json", {"mcpServers": {"s": {"command": "x", "args": [1, "two"], "env": {"N": 3}}}})
    (spec,) = load_servers(cfg)
    assert spec.args == ["1", "two"]
    assert spec.env == {"N": "3"}


def test_non_dict_entries_are_ignored(tmp_path):
    cfg = write(tmp_path / "c.json", {"mcpServers": {"bad": "nope", "ok": {"command": "x"}}})
    assert [s.name for s in load_servers(cfg)] == ["ok"]


def test_empty_config(tmp_path):
    assert load_servers(write(tmp_path / "c.json", {})) == []


def test_top_level_must_be_object(tmp_path):
    with pytest.raises(ValueError):
        load_servers(write(tmp_path / "c.json", [1, 2]))


def test_malformed_json_raises(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{not json")
    with pytest.raises(ValueError):  # json.JSONDecodeError subclasses ValueError
        load_servers(p)


def test_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        load_servers(tmp_path / "nope.json")


def test_discover_configs_only_returns_existing(tmp_path):
    home = tmp_path / "home"
    cwd = tmp_path / "proj"
    (home / ".cursor").mkdir(parents=True)
    (cwd / ".vscode").mkdir(parents=True)
    write(home / ".claude.json", {})
    write(home / ".cursor" / "mcp.json", {})
    write(cwd / ".vscode" / "mcp.json", {})
    write(cwd / ".mcp.json", {})

    found = discover_configs(home=home, cwd=cwd)
    assert set(found) == {home / ".claude.json", home / ".cursor" / "mcp.json", cwd / ".vscode" / "mcp.json", cwd / ".mcp.json"}
    # Order follows the candidate list, not filesystem order.
    assert found == [p for p in candidate_config_paths(home, cwd) if p in set(found)]


def test_discover_configs_empty_when_nothing_exists(tmp_path):
    assert discover_configs(home=tmp_path, cwd=tmp_path) == []
