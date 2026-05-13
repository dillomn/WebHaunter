import httpx


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "high",
        "description": "Forces browsers to use HTTPS. Missing means the site is vulnerable to downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "high",
        "description": "Prevents XSS by whitelisting allowed content sources.",
        "recommendation": "Implement a strict CSP policy appropriate for your application.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking by controlling whether the page can be framed.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls which browser features are available to the page.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS protection for older browsers (largely superseded by CSP).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "cache-control": {
        "name": "Cache-Control",
        "severity": "info",
        "description": "Controls caching behavior. Sensitive pages should not be cached.",
        "recommendation": "For sensitive pages: Cache-Control: no-store, no-cache",
    },
}

DANGEROUS_HEADERS = {
    "server": {
        "name": "Server Header",
        "severity": "low",
        "description": "Reveals server software and version, aiding fingerprinting.",
        "recommendation": "Remove or obfuscate the Server header.",
    },
    "x-powered-by": {
        "name": "X-Powered-By Header",
        "severity": "low",
        "description": "Reveals backend technology stack (e.g., PHP/7.4.0).",
        "recommendation": "Remove the X-Powered-By header.",
    },
    "x-aspnet-version": {
        "name": "X-AspNet-Version Header",
        "severity": "medium",
        "description": "Reveals ASP.NET version, aiding targeted attacks.",
        "recommendation": "Remove this header in web.config.",
    },
}


async def run_headers_check(target: str, progress_callback=None) -> dict:
    """Check HTTP security headers."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    if progress_callback:
        await progress_callback("headers", 20, "Fetching HTTP headers...")

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            verify=False,
        ) as client:
            response = await client.get(target)

        headers = {k.lower(): v for k, v in response.headers.items()}

        if progress_callback:
            await progress_callback("headers", 70, "Analyzing security headers...")

        return _analyze_headers(headers, str(response.url), response.status_code)

    except httpx.ConnectError:
        # Try HTTP fallback
        http_target = target.replace("https://", "http://")
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
                response = await client.get(http_target)
            headers = {k.lower(): v for k, v in response.headers.items()}
            return _analyze_headers(headers, str(response.url), response.status_code)
        except Exception as e:
            return {"error": f"Could not connect: {e}", "findings": []}
    except Exception as e:
        return {"error": str(e), "findings": []}


def _analyze_headers(headers: dict, final_url: str, status_code: int) -> dict:
    findings = []
    present_headers = {}
    missing_headers = []

    for header_key, info in SECURITY_HEADERS.items():
        value = headers.get(header_key)
        if value:
            present_headers[header_key] = {
                "name": info["name"],
                "value": value,
                "status": "present",
            }
        else:
            missing_headers.append(header_key)
            findings.append({
                "type": "missing_header",
                "header": header_key,
                "name": info["name"],
                "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"],
            })

    for header_key, info in DANGEROUS_HEADERS.items():
        value = headers.get(header_key)
        if value:
            findings.append({
                "type": "dangerous_header",
                "header": header_key,
                "name": info["name"],
                "value": value,
                "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"],
            })

    # Score: 0-100
    total_security_headers = len(SECURITY_HEADERS)
    present_count = total_security_headers - len(missing_headers)
    score = int((present_count / total_security_headers) * 100)

    display_url = final_url if len(final_url) <= 120 else final_url[:120] + "…"

    return {
        "final_url": display_url,
        "status_code": status_code,
        "score": score,
        "present_headers": present_headers,
        "findings": sorted(findings, key=lambda x: _severity_rank(x["severity"])),
        "all_headers": dict(list(headers.items())[:30]),  # first 30 response headers
    }


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)
