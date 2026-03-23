"""
Async client wrapper around the Black Duck REST API.

``BlackDuckClient`` is the central service class.  It wraps the synchronous
``blackduck`` SDK library, running every SDK call in a thread pool so the
MCP tool server stays non-blocking.  Key responsibilities:

- **Name resolution**: translates user-supplied project/version names into
  Black Duck resource dicts (with fuzzy "did you mean?" suggestions on
  mismatch).
- **Caching**: two-layer cache (name lookups + full response dicts) avoids
  redundant API calls within a configurable TTL window.
- **Rate limiting**: a token-bucket throttle caps outbound request rate to
  stay within server-side limits.
- **Normalization**: raw JSON payloads from the API are converted into typed
  Pydantic models before being returned to the caller.
"""

from __future__ import annotations

import asyncio
import logging

from blackduck import Client

from .cache import NameCache, ResponseCache, _SENTINEL
from .models import (
    AffectedProjectSummary,
    AppliedFilters,
    BomComponentSummary,
    BomComponentsResponse,
    CodeLocationSummary,
    ComponentDiff,
    HierarchicalBomComponentSummary,
    HierarchicalBomResponse,
    KBComponentSummary,
    LicenseEntry,
    LicenseInventory,
    MatchedFileSummary,
    MatchedFilesResponse,
    PolicyRuleSummary,
    PolicyStatusSummary,
    PolicyViolationSummary,
    ProjectSummary,
    ProjectTagSummary,
    ReportGenerationResponse,
    ReportSummary,
    RiskCounts,
    RiskProfile,
    UpgradeGuidance,
    VersionComparisonResponse,
    VersionSummary,
    VulnCountResponse,
    VulnerabilityDetail,
    VulnerableComponentSummary,
    VulnerableComponentsResponse,
)
from .resolver import fuzzy_match
from .throttle import RequestThrottle

logger = logging.getLogger(__name__)


# ── Custom exceptions ─────────────────────────────────────────
# Each exception carries enough context for the MCP tool layer to return
# a helpful error message, including fuzzy-match suggestions where applicable.


class ProjectNotFoundError(Exception):
    """Raised when no project matches the user-supplied name."""
    def __init__(self, name: str, suggestions: list[str] | None = None):
        self.name = name
        self.suggestions = suggestions or []
        super().__init__(f"Project not found: {name}")


class VersionNotFoundError(Exception):
    """Raised when no version matches within a resolved project."""
    def __init__(self, name: str, suggestions: list[str] | None = None):
        self.name = name
        self.suggestions = suggestions or []
        super().__init__(f"Version not found: {name}")


class ComponentNotFoundError(Exception):
    """Raised when a BOM component name cannot be found in a version."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Component not found: {name}")


class VulnerabilityNotFoundError(Exception):
    """Raised when a CVE/BDSA ID does not exist in Black Duck."""
    def __init__(self, vuln_id: str):
        self.vuln_id = vuln_id
        super().__init__(f"Vulnerability not found: {vuln_id}")


class BlackDuckClient:
    """High-level async wrapper around the Black Duck REST API.

    All public methods return plain dicts (Pydantic model_dump output) that
    are ready for JSON serialization by the MCP tool layer.

    Args:
        url: Base URL of the Black Duck server (e.g. ``https://bd.example.com``).
        token: API bearer token for authentication.
        verify_ssl: Whether to verify TLS certificates.
        timeout: HTTP request timeout in seconds.
        cache_ttl: Time-to-live in seconds for cached responses and name lookups.
        max_rps: Maximum outbound requests per second (rate-limiter ceiling).
    """

    def __init__(
        self,
        url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 30,
        cache_ttl: int = 300,
        max_rps: int = 5,
    ):
        self.base_url = url.rstrip("/")
        self.client = Client(
            token=token,
            base_url=self.base_url,
            verify=verify_ssl,
            timeout=timeout,
        )
        self.cache = NameCache(ttl=cache_ttl)
        self.response_cache = ResponseCache(ttl=cache_ttl)
        self.throttle = RequestThrottle(max_rps=max_rps)

    # ── Helpers ───────────────────────────────────────────────

    async def _bd_call(self, fn, *args, **kwargs):
        """Run a synchronous blackduck library call in a thread with throttling."""
        await self.throttle.acquire()
        return await asyncio.to_thread(fn, *args, **kwargs)

    async def _get_items_direct(self, url: str, limit: int = 1000) -> list:
        """Fetch all items from a paginated BD endpoint using the session directly.

        Iterates through pages until every item has been collected.  This is
        used for endpoints where the SDK's ``get_resource`` helper doesn't
        provide the raw response (e.g. vulnerable-bom-components).
        """
        all_items: list = []
        offset = 0
        while True:
            resp = await self._bd_call(
                self.client.session.get, url,
                params={"limit": limit, "offset": offset},
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("items", [])
            all_items.extend(items)
            # Stop when we've collected everything or no more items arrived.
            if len(all_items) >= data.get("totalCount", len(all_items)):
                break
            if not items:
                break
            offset += len(items)
        return all_items

    async def _resolve_project(self, project_name: str) -> dict:
        """Resolve a project name to its full BD resource dict.

        Checks the name cache first, then queries the API with an exact-name
        filter.  If no match is found, falls back to fetching all projects
        and raises ``ProjectNotFoundError`` with fuzzy suggestions.
        """
        cached = self.cache.get_project(project_name.lower())
        if cached:
            return cached

        # Ask BD to filter server-side by name for an efficient lookup.
        projects = await self._bd_call(
            self.client.get_resource, "projects",
            params={"q": f"name:{project_name}"},
        )
        for project in projects:
            if project["name"].lower() == project_name.lower():
                self.cache.put_project(project_name.lower(), project)
                return project

        # No exact match — fetch all project names for fuzzy suggestions.
        all_projects = await self._bd_call(self.client.get_resource, "projects")
        all_names = [p["name"] for p in all_projects]
        suggestions = fuzzy_match(project_name, all_names, max_results=3)
        raise ProjectNotFoundError(project_name, suggestions)

    async def _resolve_version(self, project: dict, version_name: str | None) -> dict:
        """Resolve a version name within a project to its BD resource dict.

        If *version_name* is ``None`` or ``"_latest"``, returns the version
        with the most recent ``createdAt`` timestamp.  Otherwise performs a
        case-insensitive match against all versions in the project.
        """
        project_lower = project["name"].lower()

        if version_name and version_name != "_latest":
            cached = self.cache.get_version(project_lower, version_name.lower())
            if cached:
                return cached

        versions = list(await self._bd_call(
            self.client.get_resource, "versions", project,
        ))

        if not versions:
            raise VersionNotFoundError(version_name or "_latest", [])

        # When no specific version is requested, pick the newest one.
        if version_name is None or version_name == "_latest":
            latest = max(versions, key=lambda v: v.get("createdAt", ""))
            return latest

        for version in versions:
            if version["versionName"].lower() == version_name.lower():
                self.cache.put_version(project_lower, version_name.lower(), version)
                return version

        # No match — provide fuzzy suggestions.
        suggestions = fuzzy_match(
            version_name,
            [v["versionName"] for v in versions],
            max_results=3,
        )
        raise VersionNotFoundError(version_name, suggestions)

    def _is_latest(self, version: dict, all_versions: list[dict] | None = None) -> bool:
        """Check whether *version* is the most recently created in *all_versions*."""
        if all_versions is None:
            return False
        if not all_versions:
            return True
        latest = max(all_versions, key=lambda v: v.get("createdAt", ""))
        return version.get("_meta", {}).get("href") == latest.get("_meta", {}).get("href")

    # ── Normalization helpers ─────────────────────────────────

    @staticmethod
    def _normalize_vuln_component(vc: dict) -> VulnerableComponentSummary:
        """Convert a raw vulnerable-bom-component JSON object into a typed model."""
        vr = vc.get("vulnerabilityWithRemediation", {})
        desc = vr.get("description", "")
        return VulnerableComponentSummary(
            component_name=vc.get("componentName", ""),
            component_version=vc.get("componentVersionName", ""),
            vulnerability_id=vr.get("vulnerabilityName", ""),
            vulnerability_name=vr.get("vulnerabilityName", ""),
            severity=vr.get("severity", "OK"),
            cvss_score=vr.get("baseScore"),
            remediation_status=vr.get("remediationStatus", "NEW"),
            description=desc[:500] if desc else None,
        )

    @staticmethod
    def _normalize_bom_component(comp: dict) -> BomComponentSummary:
        """Convert a raw BOM component JSON object into a typed model."""
        licenses = []
        license_risk = "UNKNOWN"
        for lic in comp.get("licenses", []):
            name = lic.get("licenseDisplay", lic.get("spdxId", "Unknown"))
            licenses.append(name)
            risk = lic.get("licenseRiskProfile", {}).get("riskType", "UNKNOWN")
            if risk != "UNKNOWN":
                license_risk = risk

        return BomComponentSummary(
            component_name=comp.get("componentName", ""),
            component_version=comp.get("componentVersionName", ""),
            origin_name=comp.get("originName"),
            license_names=licenses,
            license_risk=license_risk,
            vulnerability_count=comp.get("securityRiskProfile", {}).get(
                "counts", [{}]
            ).__len__(),
            policy_status=comp.get("policyStatus"),
            match_type=comp.get("matchTypes", [None])[0] if comp.get("matchTypes") else None,
        )

    # ── Public API ────────────────────────────────────────────

    async def list_projects(
        self,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List projects, optionally filtered by a name substring."""
        cached = self.response_cache.get("list_projects",
            query=(query or "").lower(), limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        params: dict = {"limit": limit, "offset": offset}
        if query:
            params["q"] = f"name:{query}"

        resp = await self._bd_call(
            self.client.session.get,
            f"{self.base_url}/api/projects",
            params=params,
        )
        resp.raise_for_status()
        data = resp.json()

        items = []
        for p in data.get("items", []):
            items.append(ProjectSummary(
                name=p["name"],
                description=p.get("description"),
                created_at=p.get("createdAt", ""),
                updated_at=p.get("updatedAt", ""),
            ))

        result = {
            "projects": [i.model_dump() for i in items],
            "total_available": data.get("totalCount", len(items)),
            "total_returned": len(items),
        }
        self.response_cache.put(result, "list_projects",
            query=(query or "").lower(), limit=limit, offset=offset)
        return result

    async def get_project(self, project_name: str) -> dict:
        """Get details for a single project, including its version count."""
        cached = self.response_cache.get("get_project",
            project_name=project_name.lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version_count = 0
        try:
            versions = list(await self._bd_call(
                self.client.get_resource, "versions", project,
            ))
            version_count = len(versions)
        except Exception:
            pass

        result = ProjectSummary(
            name=project["name"],
            description=project.get("description"),
            created_at=project.get("createdAt", ""),
            updated_at=project.get("updatedAt", ""),
            version_count=version_count,
        ).model_dump()
        self.response_cache.put(result, "get_project",
            project_name=project_name.lower())
        return result

    async def list_versions(
        self,
        project_name: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List versions of a project, sorted newest-first."""
        cached = self.response_cache.get("list_versions",
            project_name=project_name.lower(), limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        versions = list(await self._bd_call(
            self.client.get_resource, "versions", project,
        ))
        versions.sort(key=lambda v: v.get("createdAt", ""), reverse=True)

        latest_created = versions[0].get("createdAt", "") if versions else ""
        page = versions[offset:offset + limit]

        items = [
            VersionSummary(
                name=v["versionName"],
                phase=v.get("phase", "PLANNING"),
                distribution=v.get("distribution", "EXTERNAL"),
                created_at=v.get("createdAt", ""),
                is_latest=(v.get("createdAt", "") == latest_created),
            )
            for v in page
        ]

        result = {
            "versions": [i.model_dump() for i in items],
            "total_available": len(versions),
            "total_returned": len(items),
        }
        self.response_cache.put(result, "list_versions",
            project_name=project_name.lower(), limit=limit, offset=offset)
        return result

    async def get_risk_profile(
        self, project_name: str, version_name: str | None,
    ) -> dict:
        """Get the 5-dimensional risk profile for a project version."""
        cached = self.response_cache.get("get_risk_profile",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        rp = await self._bd_call(
            self.client.get_resource, "riskProfile", version, items=False,
        )

        categories: dict[str, RiskCounts] = {}
        for cat_name in ("VULNERABILITY", "LICENSE", "OPERATIONAL", "ACTIVITY", "VERSION"):
            cat_data = rp.get("categories", {}).get(cat_name, {})
            if not isinstance(cat_data, dict):
                cat_data = {}
            categories[cat_name] = RiskCounts(
                critical=cat_data.get("CRITICAL", 0),
                high=cat_data.get("HIGH", 0),
                medium=cat_data.get("MEDIUM", 0),
                low=cat_data.get("LOW", 0),
                ok=cat_data.get("OK", 0),
            )

        result = RiskProfile(
            project_name=project["name"],
            version_name=version["versionName"],
            categories={k: v.model_dump() for k, v in categories.items()},
        ).model_dump()
        self.response_cache.put(result, "get_risk_profile",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        return result

    async def get_policy_status(
        self, project_name: str, version_name: str | None,
    ) -> dict:
        """Get overall policy compliance status and violation count."""
        cached = self.response_cache.get("get_policy_status",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        ps = await self._bd_call(
            self.client.get_resource, "policy-status", version, items=False,
        )

        overall = ps.get("overallStatus", "NOT_IN_VIOLATION")
        component_violations = 0
        for status_count in ps.get("componentVersionStatusCounts", []):
            if status_count.get("name") == "IN_VIOLATION":
                component_violations = status_count.get("value", 0)

        result = PolicyStatusSummary(
            project_name=project["name"],
            version_name=version["versionName"],
            overall_status=overall,
            violation_count=component_violations,
        ).model_dump()
        self.response_cache.put(result, "get_policy_status",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        return result

    async def get_vulnerable_components(
        self,
        project_name: str,
        version_name: str | None,
        severity: list[str] | None = None,
        remediation_status: list[str] | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List vulnerable BOM components with optional severity/status filters."""
        cached = self.response_cache.get("get_vulnerable_components",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            severity=sorted(severity) if severity else None,
            remediation_status=sorted(remediation_status) if remediation_status else None,
            limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        version_url = version["_meta"]["href"]
        vuln_components = await self._get_items_direct(
            f"{version_url}/vulnerable-bom-components",
        )

        # Filter client-side and apply manual pagination because the
        # vulnerable-bom-components endpoint doesn't support server-side
        # filtering by severity or remediation status.
        results = []
        total = 0
        for vc in vuln_components:
            vr = vc.get("vulnerabilityWithRemediation", {})
            sev = vr.get("severity", "OK")
            rem = vr.get("remediationStatus", "NEW")

            if severity and sev not in severity:
                continue
            if remediation_status and rem not in remediation_status:
                continue

            total += 1
            if total > offset and len(results) < limit:
                results.append(self._normalize_vuln_component(vc))

        result = VulnerableComponentsResponse(
            project_name=project["name"],
            version_name=version["versionName"],
            total_available=total,
            total_returned=len(results),
            filters=AppliedFilters(
                severity=severity,
                remediation_status=remediation_status,
                limit=limit,
                offset=offset,
            ),
            items=results,
        ).model_dump()
        self.response_cache.put(result, "get_vulnerable_components",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            severity=sorted(severity) if severity else None,
            remediation_status=sorted(remediation_status) if remediation_status else None,
            limit=limit, offset=offset)
        return result

    async def get_vulnerability_counts(
        self,
        project_name: str,
        version_name: str | None,
        severity: list[str] | None = None,
    ) -> dict:
        """Count vulnerabilities in a project version, broken down by severity."""
        cached = self.response_cache.get("get_vulnerability_counts",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            severity=sorted(severity) if severity else None)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        version_url = version["_meta"]["href"]
        vuln_components = await self._get_items_direct(
            f"{version_url}/vulnerable-bom-components",
        )

        by_severity: dict[str, int] = {}
        total = 0
        for vc in vuln_components:
            vr = vc.get("vulnerabilityWithRemediation", {})
            sev = vr.get("severity", "OK")
            if severity and sev not in severity:
                continue
            total += 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

        result = VulnCountResponse(
            project_name=project["name"],
            version_name=version["versionName"],
            total=total,
            by_severity=by_severity,
            filters=AppliedFilters(severity=severity),
        ).model_dump()
        self.response_cache.put(result, "get_vulnerability_counts",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            severity=sorted(severity) if severity else None)
        return result

    async def get_bom_components(
        self,
        project_name: str,
        version_name: str | None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List BOM components, optionally searching by component name."""
        cached = self.response_cache.get("get_bom_components",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            query=(query or "").lower(), limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        params: dict = {}
        if query:
            params["q"] = f"componentName:{query}"

        components = await self._bd_call(
            self.client.get_resource,
            "components", version, items=True, params=params,
        )

        results = []
        total = 0
        for comp in components:
            total += 1
            if total > offset and len(results) < limit:
                results.append(self._normalize_bom_component(comp))

        result = BomComponentsResponse(
            project_name=project["name"],
            version_name=version["versionName"],
            total_available=total,
            total_returned=len(results),
            items=results,
        ).model_dump()
        self.response_cache.put(result, "get_bom_components",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            query=(query or "").lower(), limit=limit, offset=offset)
        return result

    async def get_vulnerability_detail(self, vuln_id: str) -> dict:
        """Get full detail for a CVE or BDSA vulnerability by its ID."""
        cached = self.response_cache.get("get_vulnerability_detail",
            vuln_id=vuln_id.lower())
        if cached is not _SENTINEL:
            return cached

        try:
            vuln = await self._bd_call(
                self.client.session.get,
                f"{self.base_url}/api/vulnerabilities/{vuln_id}",
            )
            vuln.raise_for_status()
            data = vuln.json()
        except Exception as e:
            if hasattr(e, "response") and getattr(e.response, "status_code", 0) == 404:
                raise VulnerabilityNotFoundError(vuln_id)
            raise

        related = data.get("relatedVulnerability") or {}
        result = VulnerabilityDetail(
            id=data.get("name", vuln_id),
            title=data.get("title", data.get("name", "")),
            description=data.get("description", ""),
            severity=data.get("severity", "OK"),
            cvss_v3_score=data.get("cvss3", {}).get("baseScore") if data.get("cvss3") else None,
            cvss_v3_vector=data.get("cvss3", {}).get("vector") if data.get("cvss3") else None,
            cvss_v2_score=data.get("cvss2", {}).get("baseScore") if data.get("cvss2") else None,
            cwe_id=data.get("cweId"),
            published_date=data.get("publishedDate"),
            updated_date=data.get("updatedDate"),
            source=data.get("source", "NVD"),
            workaround=data.get("workaround"),
            solution=data.get("solution"),
            related_vulnerability_id=related.get("name"),
            related_vulnerability_source=related.get("source"),
        ).model_dump()
        self.response_cache.put(result, "get_vulnerability_detail",
            vuln_id=vuln_id.lower())
        return result

    async def get_affected_projects(
        self, vuln_id: str, limit: int = 50,
    ) -> dict:
        """Find which projects/versions are affected by a given vulnerability."""
        cached = self.response_cache.get("get_affected_projects",
            vuln_id=vuln_id.lower(), limit=limit)
        if cached is not _SENTINEL:
            return cached

        try:
            resp = await self._bd_call(
                self.client.session.get,
                f"{self.base_url}/api/vulnerabilities/{vuln_id}/affected-projects",
                params={"limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            if hasattr(e, "response") and getattr(e.response, "status_code", 0) == 404:
                raise VulnerabilityNotFoundError(vuln_id)
            raise

        items = []
        for item in data.get("items", []):
            items.append(AffectedProjectSummary(
                project_name=item.get("projectName", ""),
                version_name=item.get("versionName", ""),
                component_name=item.get("componentName", ""),
                component_version=item.get("componentVersionName", ""),
                remediation_status=item.get("remediationStatus", "NEW"),
            ).model_dump())

        result = {
            "vulnerability_id": vuln_id,
            "affected": items,
            "total_projects_scanned": data.get("totalCount", len(items)),
        }
        self.response_cache.put(result, "get_affected_projects",
            vuln_id=vuln_id.lower(), limit=limit)
        return result

    async def get_licenses(
        self, project_name: str, version_name: str | None,
    ) -> dict:
        """List all licenses in a project version, grouped by risk level."""
        cached = self.response_cache.get("get_licenses",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        components = await self._bd_call(
            self.client.get_resource,
            "components", version, items=True,
        )

        license_map: dict[str, dict] = {}
        for comp in components:
            comp_name = comp.get("componentName", "")
            for lic in comp.get("licenses", []):
                lic_name = lic.get("licenseDisplay", lic.get("spdxId", "Unknown"))
                risk = lic.get("licenseRiskProfile", {}).get("riskType", "UNKNOWN")
                family = lic.get("licenseFamily", {}).get("name") if lic.get("licenseFamily") else None

                if lic_name not in license_map:
                    license_map[lic_name] = {
                        "license_name": lic_name,
                        "license_family": family,
                        "risk": risk,
                        "components": [],
                    }
                license_map[lic_name]["components"].append(comp_name)

        by_risk: dict[str, list] = {}
        for lic_data in license_map.values():
            entry = LicenseEntry(
                license_name=lic_data["license_name"],
                license_family=lic_data["license_family"],
                risk=lic_data["risk"],
                component_count=len(lic_data["components"]),
                components=lic_data["components"],
            )
            risk_key = lic_data["risk"]
            if risk_key not in by_risk:
                by_risk[risk_key] = []
            by_risk[risk_key].append(entry.model_dump())

        result = LicenseInventory(
            project_name=project["name"],
            version_name=version["versionName"],
            total_licenses=len(license_map),
            by_risk=by_risk,
        ).model_dump()
        self.response_cache.put(result, "get_licenses",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        return result

    async def get_policy_violations(
        self, project_name: str, version_name: str | None,
    ) -> dict:
        """List policy violations for a project version."""
        cached = self.response_cache.get("get_policy_violations",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        components = await self._bd_call(
            self.client.get_resource,
            "components", version, items=True,
        )

        violations = []
        for comp in components:
            if comp.get("policyStatus") != "IN_VIOLATION":
                continue

            rules = comp.get("policyRules", [])

            # If policyRules not embedded (common with binary scans),
            # fetch from the component's policy-rules endpoint directly.
            if not rules:
                comp_href = comp.get("_meta", {}).get("href", "")
                if comp_href:
                    try:
                        resp = await self._bd_call(
                            self.client.session.get,
                            f"{comp_href}/policy-rules",
                        )
                        resp.raise_for_status()
                        data = resp.json()
                        rules = data.get("items", [])
                    except Exception:
                        pass  # Fall through with empty rules

            for rule in rules:
                violations.append(PolicyViolationSummary(
                    component_name=comp.get("componentName", ""),
                    component_version=comp.get("componentVersionName", ""),
                    policy_name=rule.get("name", ""),
                    policy_severity=rule.get("severity", "UNSPECIFIED"),
                    violation_type=rule.get("category", "COMPONENT"),
                    description=rule.get("description"),
                ).model_dump())

        result = {
            "project_name": project["name"],
            "version_name": version["versionName"],
            "violations": violations,
            "total": len(violations),
        }
        self.response_cache.put(result, "get_policy_violations",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        return result

    async def get_scans(
        self, project_name: str, version_name: str | None,
    ) -> dict:
        """List code locations (scans) associated with a project version."""
        cached = self.response_cache.get("get_scans",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        codelocations = await self._bd_call(
            self.client.get_resource,
            "codelocations", version, items=True,
        )

        scans = []
        for cl in codelocations:
            scans.append(CodeLocationSummary(
                name=cl.get("name", ""),
                scan_type=cl.get("type"),
                last_scan_date=cl.get("updatedAt"),
                status=cl.get("status"),
                component_count=cl.get("componentCount"),
            ).model_dump())

        result = {
            "project_name": project["name"],
            "version_name": version["versionName"],
            "scans": scans,
        }
        self.response_cache.put(result, "get_scans",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower())
        return result

    async def get_upgrade_guidance(
        self,
        project_name: str,
        version_name: str | None,
        component_name: str,
    ) -> dict:
        """Get upgrade recommendation for a specific BOM component."""
        cached = self.response_cache.get("get_upgrade_guidance",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            component_name=component_name.lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        components = await self._bd_call(
            self.client.get_resource,
            "components", version, items=True,
        )

        target_comp = None
        for comp in components:
            if comp.get("componentName", "").lower() == component_name.lower():
                target_comp = comp
                break

        if target_comp is None:
            raise ComponentNotFoundError(component_name)

        guidance = UpgradeGuidance(
            component_name=target_comp.get("componentName", ""),
            current_version=target_comp.get("componentVersionName", ""),
        )

        try:
            remediating = await self._bd_call(
                self.client.get_resource, "remediating", target_comp,
            )
            if remediating:
                guidance.latest_version = remediating.get("latestAfterCurrent", {}).get("name")
                guidance.latest_safe_version = remediating.get("noVulnerabilities", {}).get("name")
                guidance.vulnerabilities_fixed = remediating.get("fixesPreviousVulnerabilities", {}).get("count")
        except Exception:
            logger.debug("No remediation info available for %s", component_name)

        result = guidance.model_dump()
        self.response_cache.put(result, "get_upgrade_guidance",
            project_name=project_name.lower(), version_name=(version_name or "_latest").lower(),
            component_name=component_name.lower())
        return result

    async def compare_versions(
        self,
        project_name: str,
        version_name_1: str,
        version_name_2: str,
    ) -> dict:
        """Diff the BOMs of two project versions (added/removed/changed components)."""
        cached = self.response_cache.get("compare_versions",
            project_name=project_name.lower(),
            version_name_1=version_name_1.lower(),
            version_name_2=version_name_2.lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version1 = await self._resolve_version(project, version_name_1)
        version2 = await self._resolve_version(project, version_name_2)

        bom1_raw = await self._bd_call(
            self.client.get_resource,
            "components", version1, items=True,
        )
        bom2_raw = await self._bd_call(
            self.client.get_resource,
            "components", version2, items=True,
        )

        # Index each BOM as {component_name: version_string} for set-based diffing.
        bom1 = {
            c.get("componentName", ""): c.get("componentVersionName", "")
            for c in bom1_raw
        }
        bom2 = {
            c.get("componentName", ""): c.get("componentVersionName", "")
            for c in bom2_raw
        }

        added = [name for name in bom2 if name not in bom1]
        removed = [name for name in bom1 if name not in bom2]
        changed = []
        for name in bom1:
            if name in bom2 and bom1[name] != bom2[name]:
                changed.append(ComponentDiff(
                    component_name=name,
                    version_in_v1=bom1[name],
                    version_in_v2=bom2[name],
                ))

        result = VersionComparisonResponse(
            project_name=project["name"],
            version_1=version1["versionName"],
            version_2=version2["versionName"],
            added=added,
            removed=removed,
            changed=changed,
        ).model_dump()
        self.response_cache.put(result, "compare_versions",
            project_name=project_name.lower(),
            version_name_1=version_name_1.lower(),
            version_name_2=version_name_2.lower())
        return result

    # ── Project Tags ─────────────────────────────────────────

    async def get_project_tags(
        self,
        project_name: str,
    ) -> dict:
        """List tags associated with a project."""
        cached = self.response_cache.get("get_project_tags",
            project_name=project_name.lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        project_url = project["_meta"]["href"]

        # Tags are a sub-resource of the project; use the session directly
        # because the SDK does not expose a "tags" named resource.
        resp = await self._bd_call(
            self.client.session.get,
            f"{project_url}/tags",
        )
        resp.raise_for_status()
        data = resp.json()

        tags = []
        for tag in data.get("items", []):
            tags.append(ProjectTagSummary(
                name=tag.get("name", ""),
            ).model_dump())

        result = {
            "project_name": project["name"],
            "tags": tags,
            "total": len(tags),
        }
        self.response_cache.put(result, "get_project_tags",
            project_name=project_name.lower())
        return result

    # ── Policy Rules ─────────────────────────────────────────

    async def list_policy_rules(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List all policy rules configured in the system.

        This is a system-level resource, so no project/version resolution
        is needed.
        """
        cached = self.response_cache.get("list_policy_rules",
            limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        # Policy rules live at the top-level API path, not under a project.
        resp = await self._bd_call(
            self.client.session.get,
            f"{self.base_url}/api/policy-rules",
            params={"limit": limit, "offset": offset},
        )
        resp.raise_for_status()
        data = resp.json()

        items = []
        for rule in data.get("items", []):
            items.append(PolicyRuleSummary(
                name=rule.get("name", ""),
                description=rule.get("description"),
                enabled=rule.get("enabled", True),
                severity=rule.get("severity", "UNSPECIFIED"),
                category=rule.get("category"),
                created_at=rule.get("createdAt"),
                updated_at=rule.get("updatedAt"),
            ).model_dump())

        result = {
            "policy_rules": items,
            "total_available": data.get("totalCount", len(items)),
            "total_returned": len(items),
        }
        self.response_cache.put(result, "list_policy_rules",
            limit=limit, offset=offset)
        return result

    # ── KB Component Search ──────────────────────────────────

    async def search_kb_components(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """Search the Black Duck Knowledge Base for components.

        The query string is passed directly to the BD API and supports
        several formats:
        - ``name:log4j`` — name substring search
        - ``maven:org.apache.logging.log4j:log4j-core:2.4.1`` — coordinate search
        - ``id:maven|org.apache.logging.log4j|log4j-core|2.4.1`` — exact ID lookup
        """
        cached = self.response_cache.get("search_kb_components",
            query=query.lower(), limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        # KB component search is a global resource, not project-scoped.
        resp = await self._bd_call(
            self.client.session.get,
            f"{self.base_url}/api/components",
            params={"q": query, "limit": limit, "offset": offset},
        )
        resp.raise_for_status()
        data = resp.json()

        items = []
        for comp in data.get("items", []):
            licenses = []
            for lic in comp.get("licenses", []):
                licenses.append(
                    lic.get("licenseDisplay", lic.get("spdxId", "Unknown"))
                )

            # KB endpoint uses "name" for component name (BOM uses "componentName").
            items.append(KBComponentSummary(
                component_name=comp.get("name", comp.get("componentName", "")),
                version=comp.get("versionName"),
                description=(comp.get("description", "") or "")[:500] or None,
                origin_id=comp.get("originId"),
                href=comp.get("_meta", {}).get("href"),
                license_names=licenses if licenses else None,
            ).model_dump())

        result = {
            "query": query,
            "components": items,
            "total_available": data.get("totalCount", len(items)),
            "total_returned": len(items),
        }
        self.response_cache.put(result, "search_kb_components",
            query=query.lower(), limit=limit, offset=offset)
        return result

    # ── Matched Files ────────────────────────────────────────

    @staticmethod
    def _normalize_matched_file(mf: dict) -> MatchedFileSummary:
        """Convert a raw matched-file JSON object into a typed model."""
        # filePath may be a plain string or a structured object with
        # compositePathContext / path / archiveContext sub-fields.
        file_path_obj = mf.get("filePath", {})
        if isinstance(file_path_obj, str):
            path = file_path_obj
            archive = None
        else:
            path = file_path_obj.get("compositePathContext",
                                     file_path_obj.get("path", ""))
            archive = file_path_obj.get("archiveContext")

        # Only the first usage entry is surfaced; most files have exactly one.
        usages = mf.get("usages", [])
        first_usage = usages[0] if usages else {}

        return MatchedFileSummary(
            file_path=path,
            archive_context=archive,
            component_name=mf.get("componentName", ""),
            component_version=mf.get("componentVersionName"),
            match_type=first_usage.get("matchType") if first_usage else None,
            usage=first_usage.get("usage") if first_usage else None,
        )

    async def get_matched_files(
        self,
        project_name: str,
        version_name: str | None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List files that matched to components during scanning."""
        cached = self.response_cache.get("get_matched_files",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower(),
            limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        # Matched files are a sub-resource of the version; use the session
        # directly with server-side pagination (unlike vulnerable-bom-components).
        version_url = version["_meta"]["href"]
        resp = await self._bd_call(
            self.client.session.get,
            f"{version_url}/matched-files",
            params={"limit": limit, "offset": offset},
        )
        resp.raise_for_status()
        data = resp.json()

        items = [self._normalize_matched_file(mf)
                 for mf in data.get("items", [])]

        result = MatchedFilesResponse(
            project_name=project["name"],
            version_name=version["versionName"],
            total_available=data.get("totalCount", len(items)),
            total_returned=len(items),
            items=items,
        ).model_dump()
        self.response_cache.put(result, "get_matched_files",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower(),
            limit=limit, offset=offset)
        return result

    # ── Hierarchical BOM Components ──────────────────────────

    @staticmethod
    def _normalize_hierarchical_component(
        comp: dict,
    ) -> HierarchicalBomComponentSummary:
        """Convert a raw BOM component with origin details into a hierarchical model."""
        licenses = []
        license_risk = "UNKNOWN"
        for lic in comp.get("licenses", []):
            name = lic.get("licenseDisplay", lic.get("spdxId", "Unknown"))
            licenses.append(name)
            risk = lic.get("licenseRiskProfile", {}).get("riskType", "UNKNOWN")
            if risk != "UNKNOWN":
                license_risk = risk

        # Classify dependency type from matchTypes.  BD uses values like
        # FILE_DEPENDENCY_DIRECT, FILE_DEPENDENCY_TRANSITIVE, MANUAL, etc.
        match_types = comp.get("matchTypes", [])
        is_direct = None
        is_transitive = None
        if match_types:
            is_direct = any("DIRECT" in mt or mt == "MANUAL" for mt in match_types)
            is_transitive = any("TRANSITIVE" in mt for mt in match_types)

        # Extract the first origin entry for namespace/ID details.
        origins = comp.get("origins", [])
        origin = origins[0] if origins else {}

        # Sum non-OK vulnerability counts from the security risk profile.
        vuln_counts = comp.get("securityRiskProfile", {}).get("counts", [])
        vuln_total = sum(
            c.get("count", 0) for c in vuln_counts
            if c.get("countType", "OK") != "OK"
        )

        return HierarchicalBomComponentSummary(
            component_name=comp.get("componentName", ""),
            component_version=comp.get("componentVersionName", ""),
            origin_name=comp.get("originName"),
            origin_id=origin.get("originId"),
            origin_external_namespace=origin.get("externalNamespace"),
            origin_external_id=origin.get("externalId"),
            match_types=match_types if match_types else None,
            is_direct_dependency=is_direct,
            is_transitive_dependency=is_transitive,
            license_names=licenses,
            license_risk=license_risk,
            vulnerability_count=vuln_total,
            policy_status=comp.get("policyStatus"),
            component_source=comp.get("componentSource"),
        )

    async def get_hierarchical_components(
        self,
        project_name: str,
        version_name: str | None,
        filter_direct: bool | None = None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List BOM components with dependency hierarchy and origin details."""
        cached = self.response_cache.get("get_hierarchical_components",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower(),
            filter_direct=filter_direct,
            query=(query or "").lower(),
            limit=limit, offset=offset)
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)

        params: dict = {}
        if query:
            params["q"] = f"componentOrVersionName:{query}"

        components = await self._bd_call(
            self.client.get_resource,
            "components", version, items=True, params=params,
        )

        # Two-pass approach: first count direct/transitive totals across
        # all components, then apply the optional direct/transitive filter
        # and manual pagination (same pattern as get_vulnerable_components).
        results = []
        total = 0
        direct_count = 0
        transitive_count = 0
        for comp in components:
            normalized = self._normalize_hierarchical_component(comp)

            # Track overall counts before any filtering.
            if normalized.is_direct_dependency:
                direct_count += 1
            if normalized.is_transitive_dependency:
                transitive_count += 1

            # Apply direct/transitive filter if requested.
            if filter_direct is True and not normalized.is_direct_dependency:
                continue
            if filter_direct is False and not normalized.is_transitive_dependency:
                continue

            total += 1
            if total > offset and len(results) < limit:
                results.append(normalized)

        result = HierarchicalBomResponse(
            project_name=project["name"],
            version_name=version["versionName"],
            total_available=total,
            total_returned=len(results),
            direct_count=direct_count,
            transitive_count=transitive_count,
            items=results,
        ).model_dump()
        self.response_cache.put(result, "get_hierarchical_components",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower(),
            filter_direct=filter_direct,
            query=(query or "").lower(),
            limit=limit, offset=offset)
        return result

    # ── Report Generation ────────────────────────────────────

    async def generate_report(
        self,
        project_name: str,
        version_name: str | None,
        report_type: str = "SBOM",
        report_format: str = "JSON",
        categories: list[str] | None = None,
    ) -> dict:
        """Initiate report generation for a project version.

        Returns a report URL that can be polled with ``get_report_status``.
        """
        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)
        version_url = version["_meta"]["href"]

        # SBOM reports use a dedicated endpoint; standard version reports
        # go through the generic reports endpoint.
        if report_type == "SBOM":
            url = f"{version_url}/sbom-reports"
            post_data = {
                "reportFormat": report_format,
                "reportType": "SBOM",
                "sbomType": "SPDX_22",
            }
        else:
            url = f"{version_url}/reports"
            post_data = {
                "categories": categories or [
                    "VERSION", "COMPONENTS", "SECURITY",
                ],
                "reportType": report_type,
                "reportFormat": report_format,
            }

        # Report generation is asynchronous on the BD server; the POST
        # returns 201 with a Location header pointing to the report resource.
        resp = await self._bd_call(
            self.client.session.post,
            url,
            json=post_data,
        )
        resp.raise_for_status()

        # The Location header contains the URL to poll for report status.
        report_url = resp.headers.get("Location", "")

        return ReportGenerationResponse(
            report_url=report_url,
            project_name=project["name"],
            version_name=version["versionName"],
            report_type=report_type,
            message=f"Report generation initiated. Poll status at: {report_url}",
        ).model_dump()

    async def get_report_status(
        self,
        report_url: str,
    ) -> dict:
        """Check the status of a previously initiated report.

        No caching — status changes over time as the server generates
        the report (IN_PROGRESS → COMPLETED or FAILED).
        """
        resp = await self._bd_call(
            self.client.session.get,
            report_url,
        )
        resp.raise_for_status()
        data = resp.json()

        # When the report is finished, look for a download link in _meta.
        download_url = None
        if data.get("status") == "COMPLETED":
            for link in data.get("_meta", {}).get("links", []):
                if link.get("rel") in ("download", "content"):
                    download_url = link.get("href")
                    break

        # Extract the report ID from the trailing segment of the href.
        report_id = None
        href = data.get("_meta", {}).get("href", "")
        if href:
            report_id = href.rsplit("/", 1)[-1]

        return ReportSummary(
            report_id=report_id,
            report_url=report_url,
            report_type=data.get("reportType"),
            report_format=data.get("reportFormat"),
            status=data.get("status"),
            created_at=data.get("createdAt"),
            finished_at=data.get("finishedAt"),
            content_type=data.get("contentType"),
            download_url=download_url,
        ).model_dump()

    async def list_reports(
        self,
        project_name: str,
        version_name: str | None,
    ) -> dict:
        """List reports for a project version."""
        cached = self.response_cache.get("list_reports",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower())
        if cached is not _SENTINEL:
            return cached

        project = await self._resolve_project(project_name)
        version = await self._resolve_version(project, version_name)
        version_url = version["_meta"]["href"]

        resp = await self._bd_call(
            self.client.session.get,
            f"{version_url}/reports",
            params={"limit": 100},
        )
        resp.raise_for_status()
        data = resp.json()

        # Extract report ID from href since the API does not return a
        # top-level "id" field in report list items.
        items = []
        for report in data.get("items", []):
            r_id = None
            r_href = report.get("_meta", {}).get("href", "")
            if r_href:
                r_id = r_href.rsplit("/", 1)[-1]

            items.append(ReportSummary(
                report_id=r_id,
                report_url=r_href or None,
                report_type=report.get("reportType"),
                report_format=report.get("reportFormat"),
                status=report.get("status"),
                created_at=report.get("createdAt"),
                finished_at=report.get("finishedAt"),
            ).model_dump())

        result = {
            "project_name": project["name"],
            "version_name": version["versionName"],
            "reports": items,
            "total": len(items),
        }
        self.response_cache.put(result, "list_reports",
            project_name=project_name.lower(),
            version_name=(version_name or "_latest").lower())
        return result
