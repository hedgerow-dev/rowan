"""Tests for the MCP deployment-config scanner (rowan/core/mcp_config.py).

Everything else that understands MCP looks at source code (mcp.run(),
@mcp.tool, tool-description poisoning). This scanner is the first thing that
opens the actual client config artifact (claude_desktop_config.json,
mcp.json) and checks it directly -- Agent Audit's "structured config
parsing" + "privilege-risk checks" categories, which this project had zero
equivalent of before.
"""

from __future__ import annotations

import json

import pytest

from rowan.core.mcp_config import (
    find_mcp_config_files,
    scan_directory,
    scan_mcp_config_file,
)


def _write_config(tmp_path, name, data):
    fp = tmp_path / name
    fp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return fp


class TestFindMcpConfigFiles:
    def test_finds_claude_desktop_config(self, tmp_path):
        _write_config(tmp_path, "claude_desktop_config.json", {"mcpServers": {}})
        found = find_mcp_config_files(tmp_path)
        assert len(found) == 1
        assert found[0].name == "claude_desktop_config.json"

    def test_finds_mcp_json_variants(self, tmp_path):
        _write_config(tmp_path, "mcp.json", {"mcpServers": {}})
        (tmp_path / "sub").mkdir()
        _write_config(tmp_path / "sub", ".mcp.json", {"mcpServers": {}})
        found = {p.name for p in find_mcp_config_files(tmp_path)}
        assert found == {"mcp.json", ".mcp.json"}

    def test_ignores_unrelated_json(self, tmp_path):
        _write_config(tmp_path, "package.json", {"name": "x"})
        assert find_mcp_config_files(tmp_path) == []

    def test_skips_node_modules(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        _write_config(tmp_path / "node_modules", "mcp.json", {"mcpServers": {}})
        assert find_mcp_config_files(tmp_path) == []


class TestHardcodedSecretDetection:
    def test_literal_secret_in_env_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_aB3xK9mQ7pL2vN8sT4wY6zR1cU5jH0dF"},
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-001" for f in findings)

    def test_env_var_reference_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-001" for f in findings)

    def test_placeholder_value_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "example": {
                    "command": "npx",
                    "args": ["-y", "some-server"],
                    "env": {"API_KEY": "your_api_key_here_changeme"},
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-001" for f in findings)

    def test_short_value_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"x": {"command": "npx", "env": {"DEBUG": "true"}}}
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-001" for f in findings)


    # Shapes that were all reported as hardcoded secrets in a sample of MCP
    # server repositories, and none of which is a credential.
    @pytest.mark.parametrize("value", [
        "https://api.acmeworks.com",
        "https://your-pbx-host/api",
        "your-apify-token",
        "${user_config.crm_token}",
        "postgresql://readonly:password@127.0.0.1:5432/app?sslmode=require",
        ".claude/world-model",
    ])
    def test_non_secret_shapes_not_flagged(self, tmp_path, value):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"x": {"command": "npx", "env": {"SETTING": value}}}
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-001" for f in findings)

    @pytest.mark.parametrize("value", [
        "postgresql://app:Xk9mQ2vL7pR4tW8@db.internal:5432/app",
        "https://hooks.acmeworks.com/services/T0A1B2C3D/B4E5F6G7H/aB3xK9mQ7pL2vN8s",
        "ghp_aB3xK9mQ7pL2vN8sT4wY6zR1cU5jH0dF",
        "${HOST}/v1?key=AKIAQ3EGX7MZ2KPWN4TB",
        "postgresql://app:admin@prod-db.acmeworks.com/app",
    ])
    def test_credentials_in_urls_still_flagged(self, tmp_path, value):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"x": {"command": "npx", "env": {"SETTING": value}}}
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-001" for f in findings)

class TestPrivilegeFlagDetection:
    def test_dangerous_flag_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "shell": {
                    "command": "npx",
                    "args": ["-y", "some-shell-server", "--dangerously-skip-permissions"],
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-002" for f in findings)

    def test_scoped_invocation_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-002" for f in findings)

    def test_filesystem_server_scoped_to_root_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-002" for f in findings)

    def test_filesystem_server_scoped_to_project_dir_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": [
                        "-y", "@modelcontextprotocol/server-filesystem",
                        "/Users/dev/myproject",
                    ],
                }
            }
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-002" for f in findings)


class TestUnencryptedTransport:
    def test_http_url_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"remote": {"url": "http://internal-mcp.example.com/sse"}}
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-003" for f in findings)

    def test_https_url_not_flagged(self, tmp_path):
        fp = _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"remote": {"url": "https://internal-mcp.example.com/sse"}}
        })
        findings = scan_mcp_config_file(fp)
        assert not any(f.rule_id == "MCP-CONFIG-003" for f in findings)


class TestMalformedAndBareTopLevel:
    def test_malformed_json_returns_no_findings(self, tmp_path):
        fp = tmp_path / "mcp.json"
        fp.write_text("{not valid json", encoding="utf-8")
        assert scan_mcp_config_file(fp) == []

    def test_bare_top_level_server_map_supported(self, tmp_path):
        """Some hosts use a bare {serverName: {...}} map with no mcpServers
        wrapper key."""
        fp = _write_config(tmp_path, "mcp.json", {
            "github": {
                "command": "npx",
                "args": ["-y", "server", "--yolo"],
            }
        })
        findings = scan_mcp_config_file(fp)
        assert any(f.rule_id == "MCP-CONFIG-002" for f in findings)


class TestScanDirectory:
    def test_aggregates_across_files(self, tmp_path):
        _write_config(tmp_path, "mcp.json", {
            "mcpServers": {"a": {"command": "npx", "args": ["--yolo"]}}
        })
        (tmp_path / "sub").mkdir()
        _write_config(tmp_path / "sub", "claude_desktop_config.json", {
            "mcpServers": {"b": {"url": "http://example.com"}}
        })
        findings = scan_directory(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"MCP-CONFIG-002", "MCP-CONFIG-003"}
