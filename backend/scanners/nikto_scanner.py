import asyncio
import json
import socket


async def run_nikto(target: str, progress_callback=None) -> dict:
    """Run Nikto web server scanner — only if a web port is reachable."""

    host, port, scheme = _resolve_target(target)

    if progress_callback:
        await progress_callback("nikto", 5, f"Checking for web service on {host}:{port}...")

    if not _port_is_open(host, port):
        # Couldn't reach port 80 — try 443 before giving up
        fallback_port = 443 if port == 80 else 80
        if _port_is_open(host, fallback_port):
            port = fallback_port
            scheme = "https" if fallback_port == 443 else "http"
        else:
            return {
                "skipped": True,
                "reason": (
                    f"No web service found on {host} (checked ports 80 and 443). "
                    "Run Nikto against a target that has an HTTP/HTTPS server running."
                ),
                "vulnerabilities": [],
            }

    url = f"{scheme}://{host}:{port}"

    if progress_callback:
        await progress_callback("nikto", 15, f"Web service found at {url} — starting Nikto...")

    cmd = [
        "nikto",
        "-h", host,
        "-port", str(port),
        "-nointeractive",
        "-maxtime", "180",  # 3 min hard cap (Nikto-internal, counts after connect)
        "-timeout", "10",   # per-request socket timeout in seconds
    ]
    if scheme == "https":
        cmd += ["-ssl"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if progress_callback:
            await progress_callback("nikto", 40, "Nikto scanning (up to 3 min)...")

        # Outer asyncio timeout slightly longer than Nikto's own -maxtime
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=220)

        if progress_callback:
            await progress_callback("nikto", 90, "Parsing Nikto results...")

        return _parse_nikto_output(stdout.decode(), stderr.decode(), url)

    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "error": "Nikto scan timed out (exceeded 3.5 minutes after connecting)",
            "vulnerabilities": [],
        }
    except FileNotFoundError:
        return {
            "error": "nikto is not installed. Install with: brew install nikto",
            "vulnerabilities": [],
        }


def _resolve_target(target: str) -> tuple[str, int, str]:
    """Return (host, port, scheme) from a target string."""
    if target.startswith("https://"):
        host = target[8:].split("/")[0]
        scheme = "https"
        port = 443
    elif target.startswith("http://"):
        host = target[7:].split("/")[0]
        scheme = "http"
        port = 80
    else:
        host = target.split("/")[0]
        scheme = "http"
        port = 80

    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
            scheme = "https" if port == 443 else "http"
        except ValueError:
            pass

    return host, port, scheme


def _port_is_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Quick TCP check before launching Nikto."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_nikto_output(stdout: str, stderr: str, url: str) -> dict:
    vulnerabilities = []

    # Try JSON lines first
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                for v in data.get("vulnerabilities", []):
                    vulnerabilities.append({
                        "id": v.get("id"),
                        "method": v.get("method"),
                        "url": v.get("url"),
                        "msg": v.get("msg"),
                        "references": v.get("references", ""),
                        "severity": _classify_severity(v.get("msg", "")),
                    })
        except json.JSONDecodeError:
            _parse_text_line(line, vulnerabilities)

    # Plain-text fallback
    if not vulnerabilities:
        for line in stdout.splitlines():
            _parse_text_line(line, vulnerabilities)

    return {
        "target_url": url,
        "vulnerabilities": vulnerabilities,
        "raw_count": len(vulnerabilities),
    }


def _parse_text_line(line: str, out: list):
    line = line.strip()
    if not line:
        return
    # Nikto text lines start with + or *
    if line.startswith(("+", "*")):
        msg = line.lstrip("+ *").strip()
        if msg and len(msg) > 10 and not msg.startswith("Target ") and not msg.startswith("Start Time"):
            out.append({
                "id": None,
                "method": None,
                "url": None,
                "msg": msg,
                "references": "",
                "severity": _classify_severity(msg),
            })


def _classify_severity(msg: str) -> str:
    msg_lower = msg.lower()

    # Explicitly info-level Nikto messages that contain misleading keywords
    info_patterns = [
        "no cgi directories found",
        "cgi tests skipped",
        "cloudflare detected",
        "start time",
        "end time",
        "host(s) tested",
        "scan terminated",
        "alt-svc header",
        "http/3",
        "suggested security header",
        "advertising http",
        "multiple ips found",
        "platform:",
    ]
    if any(p in msg_lower for p in info_patterns):
        return "info"

    high_kw = ["sql injection", "xss", "rce", "remote code execution", "command injection",
               "shell", "backdoor", "webshell", "arbitrary file", "directory traversal",
               "file inclusion", "remote file", "local file"]
    medium_kw = ["disclosure", "exposed", "directory listing", "admin interface",
                 "phpinfo", "debug enabled", "backup file", "source code", "credentials",
                 "default password", "insecure", "bypass", "sensitive data"]
    if any(k in msg_lower for k in high_kw):
        return "high"
    if any(k in msg_lower for k in medium_kw):
        return "medium"
    return "info"
