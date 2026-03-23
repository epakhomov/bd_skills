from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


# ── Type aliases ──────────────────────────────────────────────

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

ErrorCode = Literal[
    "BD_AUTH_FAILED", "BD_TIMEOUT", "BD_NOT_FOUND", "BD_API_ERROR",
    "BD_RATE_LIMITED", "PROJECT_NOT_FOUND", "VERSION_NOT_FOUND",
    "COMPONENT_NOT_FOUND", "VULN_NOT_FOUND", "INTERNAL_ERROR",
]


# ── Response models ──────────────────────────────────────────

class ProjectSummary(BaseModel):
    name: str
    description: str | None = None
    created_at: str
    updated_at: str
    version_count: int | None = None


class VersionSummary(BaseModel):
    name: str
    phase: VersionPhase
    distribution: str
    created_at: str
    is_latest: bool


class RiskCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    ok: int = 0


class RiskProfile(BaseModel):
    project_name: str
    version_name: str
    categories: dict[str, RiskCounts]


class PolicyStatusSummary(BaseModel):
    project_name: str
    version_name: str
    overall_status: PolicyStatusType
    violation_count: int


class AppliedFilters(BaseModel):
    severity: list[VulnSeverity] | None = None
    remediation_status: list[RemediationStatus] | None = None
    limit: int | None = None
    offset: int | None = None


class VulnerableComponentSummary(BaseModel):
    component_name: str
    component_version: str
    vulnerability_id: str
    vulnerability_name: str
    severity: VulnSeverity
    cvss_score: float | None = None
    remediation_status: RemediationStatus
    description: str | None = None


class VulnerableComponentsResponse(BaseModel):
    project_name: str
    version_name: str
    total_available: int
    total_returned: int
    filters: AppliedFilters
    items: list[VulnerableComponentSummary]


class VulnCountResponse(BaseModel):
    project_name: str
    version_name: str
    total: int
    by_severity: dict[str, int]
    filters: AppliedFilters


class BomComponentSummary(BaseModel):
    component_name: str
    component_version: str
    origin_name: str | None = None
    license_names: list[str]
    license_risk: LicenseRisk
    vulnerability_count: int
    policy_status: PolicyStatusType | None = None
    match_type: str | None = None


class BomComponentsResponse(BaseModel):
    project_name: str
    version_name: str
    total_available: int
    total_returned: int
    items: list[BomComponentSummary]


class VulnerabilityDetail(BaseModel):
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
    source: str
    workaround: str | None = None
    solution: str | None = None


class AffectedProjectSummary(BaseModel):
    project_name: str
    version_name: str
    component_name: str
    component_version: str
    remediation_status: RemediationStatus


class LicenseEntry(BaseModel):
    license_name: str
    license_family: str | None = None
    risk: LicenseRisk
    component_count: int
    components: list[str]


class LicenseInventory(BaseModel):
    project_name: str
    version_name: str
    total_licenses: int
    by_risk: dict[str, list[LicenseEntry]]


class PolicyViolationSummary(BaseModel):
    component_name: str
    component_version: str
    policy_name: str
    policy_severity: PolicySeverity
    violation_type: str
    description: str | None = None


class CodeLocationSummary(BaseModel):
    name: str
    scan_type: str | None = None
    last_scan_date: str | None = None
    status: str | None = None
    component_count: int | None = None


class UpgradeGuidance(BaseModel):
    component_name: str
    current_version: str
    latest_version: str | None = None
    latest_safe_version: str | None = None
    vulnerabilities_fixed: int | None = None


class ComponentDiff(BaseModel):
    component_name: str
    version_in_v1: str
    version_in_v2: str


class VersionComparisonResponse(BaseModel):
    project_name: str
    version_1: str
    version_2: str
    added: list[str]
    removed: list[str]
    changed: list[ComponentDiff]
