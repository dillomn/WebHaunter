# WebHaunter

Nmap-based network vulnerability scanner with CVE enrichment, multi-target scheduling, and PDF reporting.

> **Authorized use only.** Only scan systems you own or have explicit written permission to test.

---

## Features

- **Nmap port scanning** — service detection, version fingerprinting across single IPs, ranges, or CIDR blocks
- **CVE enrichment** — every open port is cross-referenced against the NVD database for known vulnerabilities
- **Multi-target scanning** — paste a list of IPs/hostnames and scan them all in one job
- **Named targets** — label each target (`Client Corp | 192.168.1.1`) for easy identification in results
- **JSON import** — import a client list from a JSON file directly into the target field
- **Custom port scope** — presets (Top 100 / 1k / 10k / All Ports) or enter any nmap port expression (`22,80,443,8080-9090`)
- **Scheduled scans** — recurring scans on a cron-style interval (hourly → monthly), managed from the dashboard
- **Live progress** — real-time scan updates via Server-Sent Events
- **PDF export** — professional report generated with WeasyPrint
- **User accounts** — JWT authentication, each user sees only their own scans

---

## Requirements

### System dependencies

**macOS**
```bash
brew install nmap pango
```

**Debian / Ubuntu**
```bash
sudo apt install nmap libpango-1.0-0 libpangoft2-1.0-0
```

**Windows**

1. Install [Nmap for Windows](https://nmap.org/download.html#windows) — tick *Add Nmap to PATH* during setup
2. Install [GTK3 runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) (required by WeasyPrint for PDF generation)

### Python

Python 3.11+ is required. Download from [python.org](https://www.python.org/downloads/) if not already installed.  
Check with `python --version` (Windows) or `python3 --version` (macOS/Linux).

---

## Deploy

### macOS / Linux

```bash
# 1. Clone
git clone https://github.com/dillomn/WebHaunter.git
cd WebHaunter

# 2. Create virtualenv
python3 -m venv venv

# 3. Install Python dependencies
venv/bin/pip install -r backend/requirements.txt

# 4. Start
./start.sh
```

### Windows

```powershell
# 1. Clone
git clone https://github.com/dillomn/WebHaunter.git
cd WebHaunter

# 2. Create virtualenv
python -m venv venv

# 3. Install Python dependencies
venv\Scripts\pip install -r backend\requirements.txt

# 4. Start
venv\Scripts\python backend\main.py
```

Open **http://localhost:8000**, create an account, and start scanning.

> **Note:** `start.sh` is a bash script and won't run on Windows. Use the PowerShell command above instead. All other functionality is identical.

---

## Usage

### One-off scan

1. Click **New Scan**
2. Enter targets — one per line, optionally labelled:
   ```
   Head Office     | 10.0.0.1
   Client Corp     | 203.0.113.42
   192.168.1.0/24
   ```
3. Or click **Import JSON** to load a client list (see format below)
4. Choose port scope (default: Top 1 000)
5. Click **Launch Scan** — progress updates live
6. Click **Export PDF** when complete

### Scheduled scan

1. Click **New Scan** → toggle **Recurring Schedule**
2. Choose an interval (hourly / 6h / 12h / daily / 3 days / weekly / monthly)
3. Click **Create Schedule** — the job is registered and runs automatically
4. View, pause, or trigger schedules from the **Schedules** tab on the dashboard

### JSON import format

Save a `.json` file in this format and click **Import JSON** on the New Scan screen:

```json
[
  { "name": "Head Office",  "ip": "10.0.0.1"     },
  { "name": "Client Corp",  "ip": "203.0.113.42"  },
  { "name": "Branch Site",  "ip": "192.168.1.0/24" }
]
```

Any of these formats are also accepted:

```json
[{"client": "HQ", "address": "10.0.0.1"}]
```
```json
{"Client A": "1.2.3.4", "Client B": "10.0.0.1"}
```
```json
{"clients": [{"name": "Client A", "ip": "1.2.3.4"}]}
```

Recognised host fields: `ip`, `host`, `address`, `ip_address`, `target`  
Recognised label fields: `name`, `label`, `client`, `client_name`, `hostname`

### NVD API key (optional)

CVE lookups work without a key but are rate-limited to 5 requests/second. For faster enrichment on large scans, set an API key:

**macOS / Linux**
```bash
export NVD_API_KEY=your-key-here
./start.sh
```

**Windows**
```powershell
$env:NVD_API_KEY="your-key-here"
venv\Scripts\python backend\main.py
```

Get a free key at https://nvd.nist.gov/developers/request-an-api-key

---

## Project structure

```
WebHaunter/
├── backend/
│   ├── main.py              # FastAPI app, all routes, APScheduler
│   ├── models.py            # SQLAlchemy models (User, Scan, ScheduledScan)
│   ├── database.py          # SQLite engine + session
│   ├── auth.py              # JWT authentication
│   ├── cve_lookup.py        # NVD API CVE enrichment
│   ├── pdf_generator.py     # WeasyPrint PDF generation
│   ├── scanners/
│   │   └── nmap_scanner.py  # Nmap subprocess wrapper + XML parser
│   └── requirements.txt
├── frontend/
│   ├── index.html           # SPA shell
│   ├── static/css/style.css
│   ├── static/js/app.js     # Vanilla JS single-page app
│   └── templates/report.html
├── start.sh                 # Startup script with ASCII banner
└── venv/                    # Python virtualenv (gitignored)
```

---

## Notes

- The database is SQLite, created automatically at `backend/webhaunter.db` on first run
- Scheduled scan jobs are persisted in the database and reloaded on every restart — no state is lost if the server restarts
- `nmap` must be in `PATH`; the startup script checks and warns if it is missing
- Scans run as the user that starts the server — `nmap -sT` (TCP connect scan) is used so root is not required
