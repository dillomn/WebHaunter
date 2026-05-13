# WebHaunter — Ideas & Future Features

## Scanning Modules

### High Priority
- **Screenshot capture** — Use Playwright or Puppeteer headless browser to take a screenshot of the target homepage. Embed in the PDF report. Clients love visual evidence.
- **WHOIS + DNS records** — Registrar, creation/expiry dates, nameservers, MX, SPF, DMARC, DKIM records. Fast to add, very useful context for every assessment.
- **Port-targeted Nikto** — If nmap finds a web service on a non-standard port (8080, 8443, 4443, etc.), automatically run Nikto against that port too, not just 80/443.
- **Technology fingerprinting** — Use `whatweb` or parse HTTP response headers/HTML to detect CMS (WordPress, Drupal, etc.), frameworks (Laravel, Rails), and CDN. Map to known vuln databases.

### Medium Priority
- **CORS misconfiguration check** — Send requests with `Origin: https://evil.com` and check if the server reflects it with `Access-Control-Allow-Origin: *` or the attacker origin. Common critical finding.
- **Open redirect scanner** — Test common redirect parameters (`?url=`, `?redirect=`, `?next=`) for open redirect to external domains.
- **Email security audit** — Check SPF, DMARC, DKIM records. DMARC misconfiguration is a common high finding in real assessments.
- **S3 / cloud storage enumeration** — Check for public S3 buckets using common naming patterns (target-name, target-backup, target-assets, etc.). High value finding.
- **robots.txt + sitemap.xml parser** — Automatically fetch and parse these files. Often reveals hidden paths and admin areas that Gobuster would miss.
- **Cookie security audit** — Check for missing `Secure`, `HttpOnly`, `SameSite` flags on session cookies. Already partially covered in headers but worth its own dedicated module.

### Lower Priority / Nice to Have
- **JWT token analyser** — If the app returns a JWT in headers or body, decode it and check: weak algorithm (HS256 with guessable secret, `none` alg), no expiry, sensitive data in payload.
- **GraphQL endpoint detection** — Check `/graphql`, `/api/graphql`, `/v1/graphql` for introspection enabled. Exposed introspection is a common misconfiguration.
- **WAF fingerprinting** — Detect which WAF is in front of the target (Cloudflare, AWS WAF, Akamai, etc.) and note its presence in the report. Already partially done via Cloudflare detection.
- **CVE RSS feed / alerts** — When a scan is older than 30 days, check NVD for new CVEs against the same products/versions and alert the user.

---

## UX & Workflow

- **Scheduled / recurring scans** — Let users set a cron schedule (daily/weekly). Auto-run the scan and email a diff of what changed. Great for ongoing monitoring.
- **Scan comparison / delta view** — "Compare to previous scan" — show new findings in green, fixed findings in strikethrough, unchanged in grey.
- **False positive tagging** — Mark individual findings as "Accepted Risk" or "False Positive". Persist across rescans. Suppress tagged items in the PDF.
- **Report customisation fields** — Add "Client Name", "Engagement Type", "Scope" fields to the scan form so the PDF cover reads "Prepared for: Acme Corp" instead of just the username.
- **Severity filter in results UI** — Filter the nmap CVE list by critical / high / medium / low without scrolling the full list.
- **Bulk export** — Export all scans for a domain as a single combined PDF.
- **Team / org accounts** — Multiple users sharing scan history under one organisation. Each user can see team scans.
- **API key auth** — Let users generate API keys to trigger scans programmatically (CI/CD pipeline integration).

---

## Reliability & Performance

- **Scan queue / concurrency limit** — If multiple scans start simultaneously, all tools compete for CPU and network. Add an asyncio semaphore (max 2-3 concurrent scans) with a visible queue position.
- **Adaptive wordlist selection** — Use `common.txt` (4.7k words, fast) for targets behind a CDN/WAF where large wordlists will be blocked anyway. Only use `raft-medium-words.txt` for direct-IP or non-CDN targets.
- **Gobuster status code filtering** — Add `-s 200,204,301,302,307,401,403` to reduce noise and speed up scans on verbose servers.
- **Nikto JSON output mode** — Add `-Format json` to Nikto command for more reliable structured parsing instead of text scraping.
- **Retry logic on network errors** — Some targets briefly drop connections. A simple 2-retry wrapper on HTTP checks (headers, SSL) would reduce false "connection failed" results.
- **Scan resume** — If a scan crashes mid-way (server restart), store partial results and allow resuming from the last completed module.

---

## Reporting

- **Executive summary narrative** — Auto-generate a one-paragraph plain-English summary: "The assessment identified 3 critical, 7 high severity issues. The most significant findings include an expired SSL certificate and missing HSTS header..."
- **Remediation priority matrix** — A 2×2 grid: Impact vs Effort to fix. Plot each finding. Gives clients a clear "fix this first" view.
- **CVSS score breakdown** — For each CVE, show the CVSS vector breakdown (AV:N/AC:L/PR:N/UI:N) in a human-readable table rather than just the score number.
- **Export to JSON** — Raw scan data as a JSON file for piping into other tools or SIEM systems.
- **Markdown export** — For devs who want to paste findings into GitHub issues or Notion pages.
