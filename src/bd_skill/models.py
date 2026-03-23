"""
Pydantic data models for Black Duck MCP tool responses.

This module defines:
- Literal type aliases that mirror Black Duck's fixed enumeration values
  (severity levels, remediation statuses, policy states, etc.).
- Pydantic ``BaseModel`` subclasses that serve as the structured response
  schemas returned by the ``BlackDuckClient`` methods.  Each model normalizes
  raw API JSON into a clean, typed shape that the MCP tool layer can
  serialize directly.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


# ── Type aliases ──────────────────────────────────────────────
# These Literal types constrain field values to the discrete sets that
# Black Duck uses, providing validation and editor auto-complete.

VulnSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK"]

RemediationStatus = Literal[
    "NEW", "NEEDS_REVIEW", "REMEDIATION_REQUIRED", "REMEDIATION_COMPLETE",
    "MITIGATED", "PATCHED", "IGNORED", "DUPLICATE",
]

VersionPhase = Literal[
    "PLANNING", "DEVELOPMENT", "PRERELEASE", "RELEASED", "DEPRECATED", "ARCHIVED",
]

PolicySeverity = Literal[
    "BLOCKER", "CRITICAL", "MAJOR", "MINOR", "TRIVIAL", "UNSPECIFIED",
]

PolicyStatusType = Literal[
    "IN_VIOLATION", "NOT_IN_VIOLATION", "IN_VIOLATION_OVERRIDDEN",
]

LicenseRisk = Literal["HIGH", "MEDIUM", "LOW", "OK", "UNKNOWN"]

RiskCategory = Literal[
    "VULNERABILITY", "LICENSE", "OPERATIONAL", "ACTIVITY", "VERSION",
]

# Application-level error codes used in error responses to the MCP caller.
ErrorCode = Literal[
    "BD_AUTH_FAILED", "BD_TIMEOUT", "BD_NOT_FOUND", "BD_API_ERROR",
    "BD_RATE_LIMITED", "PROJECT_NOT_FOUND", "VERSION_NOT_FOUND",
    "COMPONENT_NOT_FOUND", "VULN_NOT_FOUND", "INTERNAL_ERROR",
]


# ── Response models ──────────────────────────────────────────

class ProjectSummary(BaseModel):
    """High-level metadata for a single Black Duck project."""
    name: str
    description: str | None = None
    created_at: str
    updated_at: str
    version_count: int | None = None


class VersionSummary(BaseModel):
    """Metadata for a single version within a project."""
    name: str
    phase: VersionPhase
    distribution: str
    created_at: str
    is_latest: bool


class RiskCounts(BaseModel):
    """Breakdown of component counts by risk severity within a single category."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    ok: int = 0


class RiskProfile(BaseModel):
    """Five-dimensional risk profile for a project version."""
    project_name: str
    version_name: str
    categories: dict[str, RiskCounts]  # keys are RiskCategory values


class PolicyStatusSummary(BaseModel):
    """Overall policy compliance status for a project version."""
    project_name: str
    version_name: str
    overall_status: PolicyStatusType
    violation_count: int


class AppliedFilters(BaseModel):
    """Records the filter parameters that were applied to a query."""
    severity: list[VulnSeverity] | None = None
    remediation_status: list[RemediationStatus] | None = None
    limit: int | None = None
    offset: int | None = None


class VulnerableComponentSummary(BaseModel):
    """A single component + vulnerability pairing."""
    component_name: str
    component_version: str
    vulnerability_id: str
    vulnerability_name: str
    severity: VulnSeverity
    cvss_score: float | None = None
    remediation_status: RemediationStatus
    description: str | None = None  # truncated to 500 chars


class VulnerableComponentsResponse(BaseModel):
    """Paginated list of vulnerable components for a project version."""
    project_name: str
    version_name: str
    total_available: int
    total_returned: int
    filters: AppliedFilters
    items: list[VulnerableComponentSummary]


class VulnCountResponse(BaseModel):
    """Vulnerability count breakdown by severity for a project version."""
    project_name: str
    version_name: str
    total: int
    by_severity: dict[str, int]
    filters: AppliedFilters


class BomComponentSummary(BaseModel):
    """A single entry from the Bill of Materials (BOM)."""
    component_name: str
    component_version: str
    origin_name: str | None = None
    license_names: list[str]
    license_risk: LicenseRisk
    vulnerability_count: int
    policy_status: PolicyStatusType | None = None
    match_type: str | None = None  # e.g. FILE_EXACT, MANUAL


class BomComponentsResponse(BaseModel):
    """Paginated BOM component listing for a project version."""
    project_name: str
    version_name: str
    total_available: int
    total_returned: int
    items: list[BomComponentSummary]


class VulnerabilityDetail(BaseModel):
    """Full detail for a single CVE or BDSA vulnerability."""
    id: str
    title: str
    description: str
    severity: VulnSeverity
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v2_score: float | None = None
    cwe_id: str | None = None
    published_date: str | None = None
    updated_date: str | None = None
    source: str  # e.g. "NVD", "BDSA"
    workaround: str | None = None
    solution: str | None = None


class AffectedProjectSummary(BaseModel):
    """A project/version affected by a specific vulnerability."""
    project_name: str
    version_name: str
    component_name: str
    component_version: str
    remediation_status: RemediationStatus


class LicenseEntry(BaseModel):
    """A license found in the BOM, along with the components that use it."""
    license_name: str
    license_family: str | None = None
    risk: LicenseRisk
    component_count: int
    components: list[str]


class LicenseInventory(BaseModel):
    """All licenses in a project version, grouped by risk level."""
    project_name: str
    version_name: str
    total_licenses: int
    by_risk: dict[str, list[LicenseEntry]]


class PolicyViolationSummary(BaseModel):
    """A single policy violation tied to a BOM component."""
    component_name: str
    component_version: str
    policy_name: str
    policy_severity: PolicySeverity
    violation_type: str
    description: str | None = None


class CodeLocationSummary(BaseModel):
    """Metadata for a scan (code location) mapped to a project version."""
    name: str
    scan_type: str | None = None
    last_scan_date: str | None = None
    status: str | None = None
    component_count: int | None = None


class UpgradeGuidance(BaseModel):
    """Upgrade recommendation for a BOM component."""
    component_name: str
    current_version: str
    latest_version: str | None = None
    latest_safe_version: str | None = None  # latest version with no known vulns
    vulnerabilities_fixed: int | None = None


class ComponentDiff(BaseModel):
    """A component whose version changed between two project versions."""
    component_name: str
    version_in_v1: str
    version_in_v2: str


class VersionComparisonResponse(BaseModel):
    """Result of diffing two project version BOMs."""
    project_name: str
    version_1: str
    version_2: str
    added: list[str]    # components present in v2 but not v1
    removed: list[str]  # components present in v1 but not v2
    changed: list[ComponentDiff]  # components present in both but with different versions
