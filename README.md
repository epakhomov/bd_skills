# bd-skill — Black Duck SCA Skill for Claude Code

An MCP (Model Context Protocol) server that gives Claude Code access to your Black Duck instance. Ask natural-language questions about vulnerabilities, licenses, policy violations, and component risks — Claude handles the multi-step API navigation automatically.

## Prerequisites

- Python 3.11+
- A Black Duck server with API access
- A Black Duck API token
- Claude Code CLI

## Installation

```bash
cd bd_skill
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `bd-skill` command into the virtualenv.

## Registering with Claude Code

Register the MCP server so Claude Code can use the skill:

```bash
claude mcp add -s project \
  -e BLACKDUCK_URL=https://your-blackduck-server.com \
  -e BLACKDUCK_TOKEN=your-api-token \
  blackduck \
  -- /path/to/bd_skill/.venv/bin/bd-skill
```

**Scope options:**

| Flag | Scope | Stored in |
|------|-------|-----------|
| `-s local` | This machine + project (default) | `.claude/settings.local.json` |
| `-s project` | Shared with team via git | `.claude/settings.json` |
| `-s user` | All your projects | `~/.claude/settings.json` |

### Verify

```bash
claude mcp list
```

You should see `blackduck` listed. Start a new Claude Code session and the 16 tools will be available.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BLACKDUCK_URL` | Yes | — | Black Duck server URL |
| `BLACKDUCK_TOKEN` | Yes | — | API bearer token |
| `BLACKDUCK_TLS_VERIFY` | No | `true` | Verify TLS certificates |
| `BD_TIMEOUT_SECONDS` | No | `30` | Request timeout |
| `CACHE_TTL_SECONDS` | No | `300` | Name/response cache TTL |

## Available Tools

### Navigation
| Tool | Description |
|------|-------------|
| `list_projects` | List/search all projects |
| `search_projects` | Search projects by name with relevance scoring |
| `get_project` | Get project details and version count |
| `list_project_versions` | List versions (newest first) |

### Security & Compliance
| Tool | Description |
|------|-------------|
| `get_risk_profile` | 5-dimensional risk summary (vulnerability, license, operational, activity, version) |
| `get_policy_status` | Policy compliance status and violation count |
| `list_vulnerable_components` | Vulnerable components with severity/remediation filters |
| `count_vulnerabilities` | Vulnerability counts by severity |

### Investigation
| Tool | Description |
|------|-------------|
| `list_bom_components` | BOM inventory with licenses and vuln counts |
| `get_vulnerability_detail` | Full CVE/BDSA details (CVSS, CWE, remediation) |
| `list_licenses` | Licenses grouped by risk level |
| `list_policy_violations` | Components violating policy rules |

### Advanced
| Tool | Description |
|------|-------------|
| `search_vulnerability_across_projects` | Find which projects are affected by a CVE/BDSA |
| `list_code_locations` | Scan history for a project version |
| `get_component_upgrade_guidance` | Upgrade paths and vulnerability fixes |
| `compare_versions` | BOM diff between two project versions |

## Usage Examples

Once registered, just ask Claude naturally:

- "What critical vulnerabilities are in my-app?"
- "Show me the risk profile for payment-service"
- "Which projects are affected by CVE-2021-44228?"
- "Compare v2.0 and v3.0 of api-gateway"
- "What GPL-licensed components are in my-app?"

Claude will automatically resolve project names (with fuzzy matching), navigate to the right version, and call the appropriate tools.

## Project Structure

```
bd_skill/
├── .mcp.json                  # MCP server definition
├── pyproject.toml              # Package metadata and entry point
├── skills/
│   └── blackduck/
│       └── SKILL.md            # Skill instructions and domain knowledge
└── src/
    └── bd_skill/
        ├── server.py           # MCP server + 16 tool definitions
        ├── client.py           # Async Black Duck API wrapper
        ├── models.py           # Pydantic response models
        ├── cache.py            # Name and response caching
        ├── resolver.py         # Fuzzy project/version name matching
        └── throttle.py         # Rate limiting (5 RPS default)
```

## Removing

```bash
claude mcp remove blackduck
```
