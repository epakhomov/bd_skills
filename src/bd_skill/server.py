from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from .client import (
    BlackDuckClient,
    ComponentNotFoundError,
    ProjectNotFoundError,
    VersionNotFoundError,
    VulnerabilityNotFoundError,
)

mcp = FastMCP("Black Duck SCA")

_client: BlackDuckClient | None = None


def _get_client() -> BlackDuckClient:
    global _client
    if _client is None:
        url = os.environ.get("BLACKDUCK_URL", "")
        token = os.environ.get("BLACKDUCK_TOKEN", "")
        if not url or not token:
            raise RuntimeError(
                "BLACKDUCK_URL and BLACKDUCK_TOKEN environment variables are required"
            )
        _client = BlackDuckClient(
            url=url,
            token=token,
            verify_ssl=os.environ.get("BLACKDUCK_TLS_VERIFY", "true").lower() == "true",
            timeout=int(os.environ.get("BD_TIMEOUT_SECONDS", "30")),
            cache_ttl=int(os.environ.get("CACHE_TTL_SECONDS", "300")),
        )
    return _client


def _error_response(message: str, suggestions: list[str] | None = None) -> str:
    result: dict = {"error": message}
    if suggestions:
        result["suggestions"] = suggestions
        result["hint"] = f"Did you mean: {', '.join(suggestions)}?"
    return json.dumps(result, indent=2)


# ── Tools ─────────────────────────────────────────────────────


@mcp.tool()
async def list_projects(
    query: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List Black Duck projects. Optionally filter by name substring."""
    try:
        result = await _get_client().list_projects(query=query, limit=limit, offset=offset)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def search_projects(query: str, limit: int = 20) -> str:
    """Search Black Duck projects by name."""
    try:
        result = await _get_client().list_projects(query=query, limit=limit)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_project(project_name: str) -> str:
    """Get details for a specific Black Duck project, including version count."""
    try:
        result = await _get_client().get_project(project_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_project_versions(
    project_name: str,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List versions of a Black Duck project, sorted by creation date (newest first)."""
    try:
        result = await _get_client().list_versions(project_name, limit=limit, offset=offset)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_risk_profile(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """Get the 5-dimensional risk profile (vulnerability, license, operational, activity, version) for a project version. Defaults to the latest version if not specified."""
    try:
        result = await _get_client().get_risk_profile(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_policy_status(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """Get policy compliance status for a project version. Shows overall status and violation count."""
    try:
        result = await _get_client().get_policy_status(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_vulnerable_components(
    project_name: str,
    version_name: str | None = None,
    severity: list[str] | None = None,
    remediation_status: list[str] | None = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List vulnerable components in a project version. Filter by severity (CRITICAL, HIGH, MEDIUM, LOW) and/or remediation status (NEW, NEEDS_REVIEW, REMEDIATION_REQUIRED, etc.)."""
    try:
        result = await _get_client().get_vulnerable_components(
            project_name, version_name,
            severity=severity, remediation_status=remediation_status,
            limit=limit, offset=offset,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def count_vulnerabilities(
    project_name: str,
    version_name: str | None = None,
    severity: list[str] | None = None,
) -> str:
    """Count vulnerabilities in a project version, broken down by severity. Optionally filter to specific severity levels."""
    try:
        result = await _get_client().get_vulnerability_counts(
            project_name, version_name, severity=severity,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_bom_components(
    project_name: str,
    version_name: str | None = None,
    query: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List Bill of Materials (BOM) components for a project version. Shows component name, version, licenses, and vulnerability count. Optionally search by component name."""
    try:
        result = await _get_client().get_bom_components(
            project_name, version_name,
            query=query, limit=limit, offset=offset,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_vulnerability_detail(vulnerability_id: str) -> str:
    """Get detailed information about a specific vulnerability by its CVE or BDSA identifier. Includes CVSS scores, description, CWE, and remediation guidance."""
    try:
        result = await _get_client().get_vulnerability_detail(vulnerability_id)
        return json.dumps(result, indent=2)
    except VulnerabilityNotFoundError as e:
        return _error_response(str(e))
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_licenses(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """List all licenses used in a project version, grouped by risk level (HIGH, MEDIUM, LOW). Shows which components use each license."""
    try:
        result = await _get_client().get_licenses(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_policy_violations(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """List policy violations for a project version. Shows which components violate which policies and their severity."""
    try:
        result = await _get_client().get_policy_violations(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def search_vulnerability_across_projects(
    vulnerability_id: str,
    limit: int = 50,
) -> str:
    """Search for a vulnerability (CVE/BDSA) across all projects. Returns which projects and components are affected."""
    try:
        result = await _get_client().get_affected_projects(vulnerability_id, limit=limit)
        return json.dumps(result, indent=2)
    except VulnerabilityNotFoundError as e:
        return _error_response(str(e))
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_code_locations(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """List code locations (scans) associated with a project version. Shows scan type, last scan date, and status."""
    try:
        result = await _get_client().get_scans(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_component_upgrade_guidance(
    project_name: str,
    version_name: str,
    component_name: str,
) -> str:
    """Get upgrade guidance for a specific component. Shows current version, latest version, latest safe version, and number of vulnerabilities fixed by upgrading."""
    try:
        result = await _get_client().get_upgrade_guidance(
            project_name, version_name, component_name,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except ComponentNotFoundError as e:
        return _error_response(str(e))
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def compare_versions(
    project_name: str,
    version_name_1: str,
    version_name_2: str,
) -> str:
    """Compare the BOM of two project versions. Shows components added, removed, and changed between versions."""
    try:
        result = await _get_client().compare_versions(
            project_name, version_name_1, version_name_2,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
