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
    LicenseEntry,
    LicenseInventory,
    PolicyStatusSummary,
    PolicyViolationSummary,
    ProjectSummary,
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


class ProjectNotFoundError(Exception):
    def __init__(self, name: str, suggestions: list[str] | None = None):
        self.name = name
        self.suggestions = suggestions or []
        super().__init__(f"Project not found: {name}")


class VersionNotFoundError(Exception):
    def __init__(self, name: str, suggestions: list[str] | None = None):
        self.name = name
        self.suggestions = suggestions or []
        super().__init__(f"Version not found: {name}")


class ComponentNotFoundError(Exception):
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Component not found: {name}")


class VulnerabilityNotFoundError(Exception):
    def __init__(self, vuln_id: str):
        self.vuln_id = vuln_id
        super().__init__(f"Vulnerability not found: {vuln_id}")


class BlackDuckClient:
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
        """Fetch all items from a paginated BD endpoint using the session directly."""
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
            if len(all_items) >= data.get("totalCount", len(all_items)):
                break
            if not items:
                break
            offset += len(items)
        return all_items

    async def _resolve_project(self, project_name: str) -> dict:
        cached = self.cache.get_project(project_name.lower())
        if cached:
            return cached

        projects = await self._bd_call(
            self.client.get_resource, "projects",
            params={"q": f"name:{project_name}"},
        )
        for project in projects:
            if project["name"].lower() == project_name.lower():
                self.cache.put_project(project_name.lower(), project)
                return project

        all_projects = await self._bd_call(self.client.get_resource, "projects")
        all_names = [p["name"] for p in all_projects]
        suggestions = fuzzy_match(project_name, all_names, max_results=3)
        raise ProjectNotFoundError(project_name, suggestions)

    async def _resolve_version(self, project: dict, version_name: str | None) -> dict:
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

        if version_name is None or version_name == "_latest":
            latest = max(versions, key=lambda v: v.get("createdAt", ""))
            return latest

        for version in versions:
            if version["versionName"].lower() == version_name.lower():
                self.cache.put_version(project_lower, version_name.lower(), version)
                return version

        suggestions = fuzzy_match(
            version_name,
            [v["versionName"] for v in versions],
            max_results=3,
        )
        raise VersionNotFoundError(version_name, suggestions)

    def _is_latest(self, version: dict, all_versions: list[dict] | None = None) -> bool:
        if all_versions is None:
            return False
        if not all_versions:
            return True
        latest = max(all_versions, key=lambda v: v.get("createdAt", ""))
        return version.get("_meta", {}).get("href") == latest.get("_meta", {}).get("href")

    # ── Normalization helpers ─────────────────────────────────

    @staticmethod
    def _normalize_vuln_component(vc: dict) -> VulnerableComponentSummary:
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
        ).model_dump()
        self.response_cache.put(result, "get_vulnerability_detail",
            vuln_id=vuln_id.lower())
        return result

    async def get_affected_projects(
        self, vuln_id: str, limit: int = 50,
    ) -> dict:
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
            if comp.get("policyStatus") == "IN_VIOLATION":
                for rule in comp.get("policyRules", []):
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
