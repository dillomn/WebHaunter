import httpx
import asyncio
from typing import Optional

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Services that are CDN/WAF/proxy infrastructure — when nmap reports these
# as the product with no specific version, keyword-searching NVD returns CVEs
# for the vendor's own products, not for sites *behind* them. Skip CVE lookup.
_CDN_PROXY_PATTERNS = {
    "cloudflare http proxy",
    "cloudflare",
    "amazon cloudfront",
    "akamai",
    "fastly",
    "incapsula",
    "sucuri",
    "f5 big-ip",
    "haproxy",           # too generic without version
    "nginx",             # too generic without version — will still run with version
    "tcpwrapped",
    "unknown",
}


def _should_skip_cve_lookup(product: str, version: Optional[str]) -> tuple[bool, str]:
    """Return (skip, reason) — skip when lookup would produce noise not signal."""
    p = product.lower().strip()

    # Generic CDN/WAF proxy detections with no version
    if p in _CDN_PROXY_PATTERNS and not version:
        return True, f"CDN/WAF/proxy detection ('{product}') without specific version — CVE lookup would return vendor-level CVEs unrelated to this target"

    # Partial matches for known CDNs (e.g. "Cloudflare http proxy" contains "cloudflare")
    for pattern in ("cloudflare", "cloudfront", "akamai", "fastly"):
        if pattern in p and not version:
            return True, f"CDN/WAF proxy detected ('{product}') — CVE results would be for {pattern.title()}'s own products, not this site"

    # Require at least a version for very generic service names
    generic_services = {"http", "https", "http proxy", "ssl/http", "tcpwrapped"}
    if p in generic_services:
        return True, f"Service too generic ('{product}') for meaningful CVE lookup"

    return False, ""


async def lookup_cves_for_service(product: str, version: Optional[str] = None, cpe: Optional[str] = None) -> list[dict]:
    """Query the NVD API for CVEs matching a service product/version."""
    if not product:
        return []

    skip, reason = _should_skip_cve_lookup(product, version)
    if skip:
        return []

    if cpe:
        # CPE-based lookup is version-exact — far less noise than keyword search
        params = {"cpeName": cpe, "resultsPerPage": 10, "startIndex": 0}
    elif version:
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 10, "startIndex": 0}
    else:
        params = {"keywordSearch": product, "resultsPerPage": 5, "startIndex": 0}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(NVD_API_BASE, params=params)
            if response.status_code == 200:
                data = response.json()
                return _parse_nvd_response(data)
            return []
    except Exception:
        return []


async def enrich_nmap_results_with_cves(nmap_results: dict) -> dict:
    """Add CVE data to each port's service in nmap results."""
    if "error" in nmap_results:
        return nmap_results

    # Deduplicate: same product+version across ports → look up once, share result
    seen: dict[str, list] = {}  # "product|version" -> cves
    tasks_needed: list[tuple[str, str, Optional[str], Optional[str]]] = []  # (key, product, version, cpe)

    for host in nmap_results.get("hosts", []):
        for port in host.get("ports", []):
            product = port.get("product") or port.get("service")
            version = port.get("version")
            cpe = port.get("cpe", [None])[0] if port.get("cpe") else None
            if not product:
                continue
            key = f"{product}|{version or ''}|{cpe or ''}"
            if key not in seen:
                seen[key] = None
                tasks_needed.append((key, product, version, cpe))

    # Fetch CVEs for unique product/version/cpe combos only
    for i, (key, product, version, cpe) in enumerate(tasks_needed):
        cves = await lookup_cves_for_service(product, version, cpe)
        seen[key] = cves
        if i < len(tasks_needed) - 1:
            await asyncio.sleep(0.2)  # NVD rate limit: 5 req/s without API key

    # Assign results back to each port (shared by reference — no repeated lookups)
    for host in nmap_results.get("hosts", []):
        for port in host.get("ports", []):
            product = port.get("product") or port.get("service")
            version = port.get("version")
            cpe = port.get("cpe", [None])[0] if port.get("cpe") else None
            if product:
                key = f"{product}|{version or ''}|{cpe or ''}"
                port["cves"] = seen.get(key, [])
                skip, reason = _should_skip_cve_lookup(product, version)
                if skip:
                    port["cve_skip_reason"] = reason

    return nmap_results


def _parse_nvd_response(data: dict) -> list[dict]:
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = "unknown"
        cvss_vector = None

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = metric_list[0].get("baseSeverity") or cvss_data.get("baseSeverity", "unknown")
                cvss_vector = cvss_data.get("vectorString")
                break

        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        cves.append({
            "id": cve_id,
            "description": description[:500] if description else "",
            "cvss_score": cvss_score,
            "severity": cvss_severity.lower() if cvss_severity else "unknown",
            "cvss_vector": cvss_vector,
            "references": refs,
            "published": cve.get("published", ""),
        })

    return sorted(cves, key=lambda x: (x.get("cvss_score") or 0), reverse=True)
