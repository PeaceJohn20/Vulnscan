"""
Nmap Port & Service Scanner
Uses python-nmap to identify open ports, services and versions.
Maps results to NVD CVE data via cve_fetcher.
"""

import nmap
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

SEVERITY_REMAP = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "NONE":     "Low",
}

# Remediation hints per service / port
REMEDIATION_MAP = {
    21:   "Disable anonymous FTP access; upgrade to SFTP or FTPS.",
    22:   "Ensure SSH is configured with key-based auth; disable root login.",
    23:   "Disable Telnet — replace with SSH for encrypted communication.",
    25:   "Restrict SMTP relay; enforce authentication and TLS.",
    53:   "Limit DNS zone transfers; apply rate-limiting against DDoS.",
    80:   "Redirect HTTP to HTTPS; enforce TLS 1.2+.",
    110:  "Disable POP3 if unused; migrate to IMAPS (port 993).",
    111:  "Block RPC portmapper from external access via firewall.",
    135:  "Block MS-RPC ports at perimeter firewall.",
    139:  "Disable NetBIOS over TCP/IP if not required.",
    143:  "Disable IMAP if unused; migrate to IMAPS (port 993).",
    443:  "Ensure TLS certificates are current; use strong cipher suites.",
    445:  "Disable SMBv1; restrict SMB access to trusted hosts only.",
    1433: "Restrict SQL Server port to application servers only.",
    1521: "Restrict Oracle DB to application servers; use Strong Auth.",
    3306: "Bind MySQL to localhost or VPN; disable remote root login.",
    3389: "Restrict RDP to VPN/bastion; enable NLA and MFA.",
    5432: "Restrict PostgreSQL to app servers; use pg_hba.conf rules.",
    5900: "Disable VNC or restrict to VPN; enable password protection.",
    6379: "Bind Redis to localhost; enable requirepass authentication.",
    8080: "Restrict HTTP alt-port; prefer HTTPS on 443.",
    8443: "Ensure TLS is properly configured on this port.",
    27017: "Enable MongoDB authentication; bind to localhost.",
}

DEFAULT_REMEDIATION = (
    "Review whether this port/service is required. "
    "If not, disable or firewall it. Keep service software updated."
)


def run_port_scan(target: str, scan_type: str = "full") -> Dict[str, Any]:
    """
    Run Nmap scan against target.
    Returns structured dict: {host_info, open_ports, raw_output}
    """
    nm = nmap.PortScanner()

    # Choose Nmap arguments by scan type
    if scan_type == "quick":
        args = "-sV -T4 --top-ports 100"
    elif scan_type == "port":
        args = "-sV -T4 -p 1-1024"
    else:  # full
        args = "-sV -T4 -p 1-65535 --open"

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        return {"error": str(e), "open_ports": [], "raw_output": ""}

    results: List[Dict] = []
    raw_lines = []

    for host in nm.all_hosts():
        host_info = nm[host]
        raw_lines.append(f"Host: {host} ({host_info.hostname()})")
        raw_lines.append(f"State: {host_info.state()}")

        for proto in host_info.all_protocols():
            port_list = sorted(host_info[proto].keys())
            for port in port_list:
                svc = host_info[proto][port]
                if svc["state"] != "open":
                    continue

                service_name = svc.get("name", "unknown")
                version      = f"{svc.get('product','')} {svc.get('version','')}".strip()
                raw_lines.append(f"  {proto}/{port}: {service_name} {version}")

                remediation = REMEDIATION_MAP.get(port, DEFAULT_REMEDIATION)
                severity    = _port_severity(port, service_name)

                results.append({
                    "finding_type": "open_port",
                    "port":         port,
                    "protocol":     proto,
                    "service":      service_name,
                    "version":      version or "unknown",
                    "severity":     severity,
                    "description":  (
                        f"Port {port}/{proto} is open running {service_name}"
                        + (f" version {version}" if version else "")
                        + ". Exposed ports increase the attack surface."
                    ),
                    "remediation":  remediation,
                    "raw_detail":   json.dumps(svc),
                })

    return {
        "open_ports":  results,
        "raw_output":  "\n".join(raw_lines),
        "host_count":  len(nm.all_hosts()),
    }


def _port_severity(port: int, service: str) -> str:
    """Assign severity based on well-known dangerous ports."""
    critical_ports = {23, 135, 139, 445, 1433, 3389, 5900}
    high_ports     = {21, 25, 111, 1521, 3306, 5432, 6379, 27017}
    medium_ports   = {53, 80, 110, 143, 8080}

    if port in critical_ports:
        return "Critical"
    if port in high_ports:
        return "High"
    if port in medium_ports:
        return "Medium"
    return "Low"
