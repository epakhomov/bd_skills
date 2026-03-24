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
from .profiles import ProfileRegistry

mcp = FastMCP("blackduck-assist")

_registry: ProfileRegistry | None = None


def _get_registry() -> ProfileRegistry:
    global _registry
    if _registry is None:
        _registry = ProfileRegistry()
    return _registry


def _get_client() -> BlackDuckClient:
    return _get_registry().get_client()


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


@mcp.tool()
async def list_project_tags(
    project_name: str,
) -> str:
    """List tags for a project. Shows all tags associated with a Black Duck project."""
    try:
        result = await _get_client().get_project_tags(project_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_policy_rules(
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List all policy rules configured in the Black Duck system. Shows rule name, severity, category, and enabled status."""
    try:
        result = await _get_client().list_policy_rules(limit=limit, offset=offset)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def search_kb_components(
    query: str,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """Search the Black Duck Knowledge Base for components outside of a project context. Supports queries like 'name:log4j', 'maven:org.apache.logging.log4j:log4j-core:2.4.1', or 'id:maven|org.apache.logging.log4j|log4j-core|2.4.1'."""
    try:
        result = await _get_client().search_kb_components(
            query=query, limit=limit, offset=offset,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_matched_files(
    project_name: str,
    version_name: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List files that matched to components during scanning. Shows file path, component name, match type, and usage for a project version."""
    try:
        result = await _get_client().get_matched_files(
            project_name, version_name,
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
async def list_hierarchical_components(
    project_name: str,
    version_name: str | None = None,
    filter_direct: bool | None = None,
    query: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """List BOM components with dependency hierarchy details. Shows origin information, match types, and whether each component is a direct or transitive dependency. Use filter_direct=true for only direct dependencies, filter_direct=false for only transitive."""
    try:
        result = await _get_client().get_hierarchical_components(
            project_name, version_name,
            filter_direct=filter_direct, query=query,
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
async def generate_report(
    project_name: str,
    version_name: str | None = None,
    report_type: str = "SBOM",
    report_format: str = "JSON",
    categories: list[str] | None = None,
) -> str:
    """Generate a report for a project version. report_type can be 'SBOM' for SPDX SBOM, or 'VERSION' for a standard version report. report_format can be 'JSON' or 'CSV'. For VERSION reports, categories can include: VERSION, CODE_LOCATIONS, COMPONENTS, SECURITY, FILES, CRYPTO_ALGORITHMS, UPGRADE_GUIDANCE. Returns a report_url to poll for status using get_report_status."""
    try:
        result = await _get_client().generate_report(
            project_name, version_name,
            report_type=report_type, report_format=report_format,
            categories=categories,
        )
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_report_status(
    report_url: str,
) -> str:
    """Check the status of a previously generated report. Pass the report_url returned by generate_report. Returns status (IN_PROGRESS, COMPLETED, FAILED) and download_url when completed."""
    try:
        result = await _get_client().get_report_status(report_url)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def list_reports(
    project_name: str,
    version_name: str | None = None,
) -> str:
    """List all reports generated for a project version. Shows report type, format, status, and creation date."""
    try:
        result = await _get_client().list_reports(project_name, version_name)
        return json.dumps(result, indent=2)
    except ProjectNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except VersionNotFoundError as e:
        return _error_response(str(e), e.suggestions)
    except Exception as e:
        return _error_response(str(e))


# ── Profile management ─────────────────────────────────────────


@mcp.tool()
async def list_profiles() -> str:
    """List all configured Black Duck profiles. Shows profile name, server URL, and which profile is currently active."""
    try:
        profiles = _get_registry().list_profiles()
        return json.dumps(profiles, indent=2)
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def switch_profile(profile_name: str) -> str:
    """Switch the active Black Duck profile. All subsequent tool calls will use this profile's connection."""
    try:
        _get_registry().switch(profile_name)
        url = _get_registry().active_url
        return json.dumps({
            "status": "switched",
            "active_profile": profile_name,
            "url": url,
        }, indent=2)
    except ValueError as e:
        return _error_response(str(e))
    except Exception as e:
        return _error_response(str(e))


@mcp.tool()
async def get_active_profile() -> str:
    """Get the currently active Black Duck profile name and server URL."""
    try:
        registry = _get_registry()
        return json.dumps({
            "profile": registry.active_profile,
            "url": registry.active_url,
        }, indent=2)
    except Exception as e:
        return _error_response(str(e))


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
