# WebHaunter — Vulnerability Scanner

A professional cybersecurity vulnerability scanner web app with PDF reporting.

## Features

| Module | Description |
|--------|-------------|
| **Nmap** | Service discovery, version detection, OS fingerprinting |
| **CVE Lookup** | NVD API enrichment for every discovered service |
| **Gobuster Dir** | Directory and file enumeration |
| **Gobuster DNS** | Subdomain enumeration |
| **Nikto** | Web server vulnerability scanning |
| **SSL/TLS** | Certificate validity, protocol deprecation, cipher checks |
| **HTTP Headers** | Security header audit (CSP, HSTS, X-Frame-Options, etc.) |
| **PDF Export** | Professional client/management report via WeasyPrint |

## Requirements

### System tools
```bash
brew install nmap gobuster nikto pango
```

### Python 3.10+

## Setup

```bash
# Create virtualenv and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

## Run

```bash
./start.sh
```

Then open http://localhost:8000

1. Create an account
2. Click **New Scan**
3. Enter target (IP, domain, or hostname)
4. Select modules
5. Click **Launch Scan** — progress updates live
6. When complete, click **Export PDF**

## Project Structure

```
WebHaunter/
├── backend/
│   ├── main.py              # FastAPI app + routes
│   ├── auth.py              # JWT authentication
│   ├── models.py            # SQLAlchemy DB models
│   ├── database.py          # SQLite connection
│   ├── cve_lookup.py        # NVD API CVE enrichment
│   ├── pdf_generator.py     # WeasyPrint PDF generation
│   ├── scanners/
│   │   ├── nmap_scanner.py
│   │   ├── gobuster_scanner.py
│   │   ├── nikto_scanner.py
│   │   ├── ssl_scanner.py
│   │   └── headers_scanner.py
│   └── requirements.txt
├── frontend/
│   ├── index.html           # SPA entry point
│   ├── static/css/style.css
│   ├── static/js/app.js     # Vanilla JS SPA
│   └── templates/report.html  # PDF report template
├── start.sh                 # Startup script
└── venv/                    # Python virtualenv
```

## Notes

- All scans run asynchronously with live Server-Sent Events progress
- The DB is SQLite stored at `backend/ghosthunter.db` — created on first run
- If a tool (nmap, gobuster, nikto) is not installed, that module returns an error gracefully
- The NVD API is used without a key (5 req/s rate limit) — add `NVD_API_KEY` env var for higher limits

## Security

This tool is for **authorized security testing only**. Only scan systems you own or have explicit written permission to test.
