import asyncio
import re
import xml.etree.ElementTree as ET


async def run_nmap(targets: list[str] | str, ports: str = "top1000", progress_callback=None) -> dict:
    """Run nmap service/version detection and return structured results."""
    if isinstance(targets, str):
        targets = [targets]

    if progress_callback:
        label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
        await progress_callback("nmap", 10, f"Starting nmap scan on {label}...")

    cmd = ["nmap", "-sT", "-sV", "--version-intensity", "5", "-T4", "--open", "-oX", "-"]

    if ports == "top100":
        cmd.extend(["--top-ports", "100"])
    elif ports == "top10k":
        cmd.extend(["--top-ports", "10000"])
    elif ports == "allports":
        cmd.append("-p-")
    elif ports not in ("top1000", "default", "", None):
        # Custom spec — already validated by the API layer
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["--top-ports", "1000"])

    cmd.extend(targets)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if progress_callback:
            await progress_callback("nmap", 50, "Scan running, waiting for results...")

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=7200)

        if progress_callback:
            await progress_callback("nmap", 90, "Parsing results...")

        raw = stdout.decode().strip()
        if not raw:
            err = stderr.decode().strip()
            return {"error": f"nmap produced no output. {err[:300] if err else 'Ensure nmap is installed and the target is reachable.'}"}

        if proc.returncode not in (0, 1):
            return {"error": f"nmap exited {proc.returncode}: {stderr.decode()[:500]}"}

        return _parse_nmap_xml(raw)

    except asyncio.TimeoutError:
        proc.kill()
        return {"error": "nmap scan timed out after 5 minutes"}
    except FileNotFoundError:
        return {"error": "nmap is not installed or not in PATH"}


def _parse_nmap_xml(xml_data: str) -> dict:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"error": f"Failed to parse nmap XML: {e}"}

    results = {
        "hosts": [],
        "scan_info": {},
    }

    # Scan metadata
    scan_info = root.find("scaninfo")
    if scan_info is not None:
        results["scan_info"] = {
            "type": scan_info.get("type"),
            "protocol": scan_info.get("protocol"),
            "num_services": scan_info.get("numservices"),
        }

    for host in root.findall("host"):
        host_data = {
            "status": None,
            "addresses": [],
            "hostnames": [],
            "os_matches": [],
            "ports": [],
        }

        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state")

        for addr in host.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr"),
                "type": addr.get("addrtype"),
            })

        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                host_data["hostnames"].append(hn.get("name"))

        os_el = host.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch")[:3]:
                host_data["os_matches"].append({
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                })

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")

                port_data = {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": None,
                    "version": None,
                    "product": None,
                    "extrainfo": None,
                    "cpe": [],
                    "scripts": [],
                }

                if service_el is not None:
                    port_data["service"] = service_el.get("name")
                    port_data["version"] = service_el.get("version")
                    port_data["product"] = service_el.get("product")
                    port_data["extrainfo"] = service_el.get("extrainfo")
                    for cpe in service_el.findall("cpe"):
                        port_data["cpe"].append(cpe.text)

                for script in port.findall("script"):
                    port_data["scripts"].append({
                        "id": script.get("id"),
                        "output": script.get("output", "")[:500],
                    })

                host_data["ports"].append(port_data)

        results["hosts"].append(host_data)

    return results
