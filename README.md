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

## Multi-Server Profiles

If you work with multiple Black Duck instances (e.g. production and staging), you can configure named profiles instead of using environment variables.

### Setup

Create `~/.blackduck/profiles.yaml`:

```yaml
profiles:
  prod:
    url: https://bd-prod.example.com
    token: "your-prod-api-token"
    tls_verify: true       # optional, default: true
    timeout: 30            # optional, default: 30
    cache_ttl: 300         # optional, default: 300
  staging:
    url: https://bd-staging.example.com
    token: "your-staging-api-token"

default: prod   # optional — first profile is used if omitted
```

When a profiles file is present, environment variables are ignored. If no profiles file exists, the server falls back to `BLACKDUCK_URL` / `BLACKDUCK_TOKEN` environment variables (full backward compatibility).

### Registration with Profiles

When using profiles, you don't need to pass credentials via `-e` flags:

```bash
claude mcp add -s project \
  blackduck \
  -- /path/to/bd_skill/.venv/bin/blackduck-assist
```

### Profile Management Tools

| Tool | Description |
|------|-------------|
| `list_profiles` | List all configured profiles with server URLs and active status |
| `switch_profile` | Switch the active profile — subsequent tool calls use the new connection |
| `get_active_profile` | Show the currently active profile name and server URL |

### Switching Profiles

Ask Claude naturally:

- "Switch to the staging profile"
- "Which Black Duck profile am I connected to?"
- "List my Black Duck profiles"

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

## Slash Commands

Quick-access commands for common operations. Type these directly in Claude Code:

| Command | Usage | Description |
|---------|-------|-------------|
| `/list_projects` | `/list_projects [query]` | List all projects on the server. Add a search term to filter by name. Paginates automatically if there are too many to display. |
| `/project_risk` | `/project_risk <project>` | Show the 5-dimensional risk profile (vulnerability, license, operational, activity, version) for a project. |
| `/project_vulns` | `/project_vulns <project> [severity]` | List vulnerable components with a severity summary. Optionally filter by `critical`, `high`, `medium`, or `low`. |
| `/policy_violations` | `/policy_violations <project>` | List all policy violations grouped by policy rule, ordered by severity. |

### Slash Command Examples

```
/list_projects              # show first 20 projects, with option to page through more
/list_projects payment       # search for projects matching "payment"
/project_risk my-app         # risk profile for my-app (auto-resolves latest version)
/project_vulns my-app critical  # only critical vulnerabilities
/policy_violations my-app    # policy violations grouped by rule
```

### Installation

Copy the skill files to your Claude Code skills directory:

```bash
cp -r skills/list_projects  ~/.claude/skills/
cp -r skills/project_risk   ~/.claude/skills/
cp -r skills/project_vulns  ~/.claude/skills/
cp -r skills/policy_violations ~/.claude/skills/
```

Restart Claude Code for the commands to appear in `/help`.

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
│   ├── blackduck/
│   │   └── SKILL.md            # Skill instructions and domain knowledge
│   ├── list_projects/
│   │   └── SKILL.md            # /list_projects slash command
│   ├── project_risk/
│   │   └── SKILL.md            # /project_risk slash command
│   ├── project_vulns/
│   │   └── SKILL.md            # /project_vulns slash command
│   └── policy_violations/
│       └── SKILL.md            # /policy_violations slash command
└── src/
    └── bd_skill/
        ├── server.py           # MCP server + tool definitions
        ├── client.py           # Async Black Duck API wrapper
        ├── profiles.py         # Multi-profile configuration and registry
        ├── models.py           # Pydantic response models
        ├── cache.py            # Name and response caching
        ├── resolver.py         # Fuzzy project/version name matching
        └── throttle.py         # Rate limiting (5 RPS default)
```

## Removing

```bash
claude mcp remove blackduck
```
