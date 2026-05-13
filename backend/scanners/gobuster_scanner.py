import asyncio
import os
import tempfile

# Resolve bundled wordlists path relative to this file's location
_HERE = os.path.dirname(os.path.abspath(__file__))
_BUNDLED = os.path.normpath(os.path.join(_HERE, "..", "..", "wordlists"))

WORDLIST_DIR_PATHS = [
    # Bundled with the project (highest priority — always present after setup)
    os.path.join(_BUNDLED, "raft-medium-words.txt"),   # 63k words, best general-purpose
    os.path.join(_BUNDLED, "common.txt"),              # 4.7k words, fast scan fallback
    # System seclists (Linux/Kali/Parrot common paths)
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    # Homebrew seclists (if user installed separately)
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    # dirb fallback
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

WORDLIST_DNS_PATHS = [
    # Bundled — 5k for speed, 100k for thoroughness
    os.path.join(_BUNDLED, "subdomains-5000.txt"),     # top 1M subdomains, top 5000
    os.path.join(_BUNDLED, "subdomains-100k.txt"),     # bitquark top 100k
    # System seclists
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
]

# Built-in fallbacks used when no wordlists are installed
_BUILTIN_DIR_WORDS = [
    ".git", ".env", ".htaccess", ".htpasswd", "admin", "administrator", "api",
    "api/v1", "api/v2", "backup", "bin", "cgi-bin", "config", "console",
    "dashboard", "data", "db", "debug", "dev", "docs", "download", "error",
    "files", "health", "help", "img", "index.php", "info", "info.php", "js",
    "login", "logout", "manager", "metrics", "panel", "phpmyadmin",
    "phpinfo.php", "private", "robots.txt", "server-status", "server-info",
    "sitemap.xml", "static", "status", "swagger", "swagger-ui", "test",
    "tmp", "upload", "uploads", "users", "vendor", "wp-admin",
    "wp-login.php", "wp-config.php", "xmlrpc.php", ".well-known",
]

_BUILTIN_DNS_WORDS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "vpn", "api", "dev", "staging", "test", "admin", "portal", "secure",
    "blog", "shop", "app", "m", "mobile", "cdn", "static", "media",
    "assets", "images", "video", "remote", "support", "help", "docs",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence", "status",
]


def _find_wordlist(paths: list[str]) -> str | None:
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _write_temp_wordlist(words: list[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(words))
    tmp.close()
    return tmp.name


async def run_gobuster_dir(target: str, progress_callback=None) -> dict:
    """Directory enumeration against a web target."""
    wordlist = _find_wordlist(WORDLIST_DIR_PATHS)
    builtin_used = False
    tmp_path = None

    if not wordlist:
        tmp_path = _write_temp_wordlist(_BUILTIN_DIR_WORDS)
        wordlist = tmp_path
        builtin_used = True

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    if progress_callback:
        await progress_callback("gobuster_dir", 10, "Starting directory enumeration...")

    label = "built-in wordlist" if builtin_used else os.path.basename(wordlist)

    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", "10",
        "--timeout", "10s",
        "-k",
        "-q",
        "--no-error",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if progress_callback:
            await progress_callback("gobuster_dir", 40, f"Enumerating directories ({label})...")

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        if progress_callback:
            await progress_callback("gobuster_dir", 90, "Parsing results...")

        paths = _parse_gobuster_output(stdout.decode())
        note = "Install seclists for a larger wordlist: brew install seclists" if builtin_used else None
        return {
            "paths": paths,
            "target": target,
            "wordlist": label,
            **({"note": note} if note else {}),
        }

    except asyncio.TimeoutError:
        proc.kill()
        return {"error": "gobuster dir timed out after 10 minutes — target may be slow or rate-limiting requests", "paths": []}
    except FileNotFoundError:
        return {"error": "gobuster is not installed. Install with: brew install gobuster", "paths": []}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


async def run_gobuster_dns(target: str, progress_callback=None) -> dict:
    """Subdomain enumeration via DNS brute-force."""
    wordlist = _find_wordlist(WORDLIST_DNS_PATHS)
    builtin_used = False
    tmp_path = None

    if not wordlist:
        tmp_path = _write_temp_wordlist(_BUILTIN_DNS_WORDS)
        wordlist = tmp_path
        builtin_used = True

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    if progress_callback:
        await progress_callback("gobuster_dns", 10, "Starting subdomain enumeration...")

    label = "built-in wordlist" if builtin_used else os.path.basename(wordlist)

    cmd = [
        "gobuster", "dns",
        "--domain", domain,   # newer gobuster: -d is now delay, --domain is the target
        "-w", wordlist,
        "-t", "20",
        "--timeout", "10s",
        "-q",
        "--no-error",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if progress_callback:
            await progress_callback("gobuster_dns", 40, f"Enumerating subdomains ({label})...")

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        if progress_callback:
            await progress_callback("gobuster_dns", 90, "Parsing results...")

        subdomains = _parse_dns_output(stdout.decode())
        note = "Install seclists for a larger wordlist: brew install seclists" if builtin_used else None
        return {
            "subdomains": subdomains,
            "domain": domain,
            "wordlist": label,
            **({"note": note} if note else {}),
        }

    except asyncio.TimeoutError:
        proc.kill()
        return {"error": "gobuster dns timed out", "subdomains": []}
    except FileNotFoundError:
        return {"error": "gobuster is not installed. Install with: brew install gobuster", "subdomains": []}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _parse_gobuster_output(output: str) -> list[dict]:
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("["):
            continue
        parts = line.split()
        if not parts:
            continue
        path = parts[0]
        status = None
        size = None
        for i, part in enumerate(parts):
            if part.lower() == "(status:":
                status = parts[i + 1].rstrip(")")
            if part.lower() == "[size:":
                size = parts[i + 1].rstrip("]")
        paths.append({"path": path, "status": status, "size": size})
    return paths


def _parse_dns_output(output: str) -> list[str]:
    subdomains = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("["):
            continue
        if line.lower().startswith("found:"):
            subdomains.append(line.split(":", 1)[1].strip())
        elif line and not line.startswith("["):
            subdomains.append(line)
    return subdomains
