"""
Scan Orchestrator
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone
import json

from database import db, Scan, ScanResult, Vulnerability
from scanners.nmap_scanner  import run_port_scan
from scanners.cve_fetcher   import correlate_service_cves
from scanners.bandit_scanner import scan_code_string
from scanners.yara_scanner   import scan_string as yara_scan_string


def _upsert_vulnerability(app, cve_data):
    with app.app_context():
        vuln = Vulnerability.query.filter_by(cve_id=cve_data["cve_id"]).first()
        if not vuln:
            vuln = Vulnerability(
                cve_id      =cve_data["cve_id"],
                description =cve_data.get("description", ""),
                severity    =cve_data.get("severity", "Low"),
                cvss_score  =cve_data.get("cvss_score", 0.0),
                published   =cve_data.get("published", ""),
                references  =json.dumps(cve_data.get("references", [])),
            )
            db.session.add(vuln)
            db.session.commit()
        return vuln.id


def _save_finding(app, scan_id, finding, vuln_id=None):
    with app.app_context():
        result = ScanResult(
            scan_id         =scan_id,
            vulnerability_id=vuln_id,
            finding_type    =finding.get("finding_type", "unknown"),
            host            =finding.get("host"),
            port            =finding.get("port"),
            protocol        =finding.get("protocol"),
            service         =finding.get("service"),
            version         =finding.get("version"),
            severity        =finding.get("severity", "Low"),
            description     =finding.get("description", ""),
            remediation     =finding.get("remediation", ""),
            raw_detail      =finding.get("raw_detail", ""),
        )
        db.session.add(result)
        db.session.commit()


def run_full_scan(app, scan_id):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        scan.status     = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()
        all_raw = []
        try:
            nmap_result = run_port_scan(scan.target, scan.scan_type)
            all_raw.append(nmap_result.get("raw_output", ""))
            for finding in nmap_result.get("open_ports", []):
                try:
                    cves = correlate_service_cves(
                        finding.get("service", ""),
                        finding.get("version", ""),
                    )
                except Exception:
                    cves = []
                if cves:
                    for cve_data in cves[:2]:
                        try:
                            vuln_id = _upsert_vulnerability(app, cve_data)
                            sev_order = {"Critical":4,"High":3,"Medium":2,"Low":1}
                            cve_sev   = cve_data.get("severity", "Low")
                            if sev_order.get(cve_sev, 1) > sev_order.get(finding["severity"], 1):
                                finding["severity"] = cve_sev
                            _save_finding(app, scan_id, finding, vuln_id)
                        except Exception:
                            pass
                else:
                    _save_finding(app, scan_id, finding)
            try:
                yara_result = yara_scan_string(nmap_result.get("raw_output", ""), filename="nmap_output")
                for finding in yara_result.get("findings", []):
                    _save_finding(app, scan_id, finding)
            except Exception:
                pass
            scan.status     = "completed"
            scan.ended_at   = datetime.now(timezone.utc)
            scan.raw_output = "\n".join(all_raw)[:50000]
            db.session.commit()
        except Exception as e:
            scan.status     = "failed"
            scan.ended_at   = datetime.now(timezone.utc)
            scan.raw_output = str(e)
            db.session.commit()


def run_code_scan(app, scan_id, code_content):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        scan.status     = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()
        try:
            bandit_result = scan_code_string(code_content)
            for finding in bandit_result.get("findings", []):
                _save_finding(app, scan_id, finding)
            yara_result = yara_scan_string(code_content, filename="submitted_code.py")
            for finding in yara_result.get("findings", []):
                _save_finding(app, scan_id, finding)
            scan.status     = "completed"
            scan.ended_at   = datetime.now(timezone.utc)
            scan.raw_output = (
                bandit_result.get("raw_output", "") + "\n" +
                yara_result.get("raw_output", "")
            )[:50000]
            db.session.commit()
        except Exception as e:
            scan.status     = "failed"
            scan.ended_at   = datetime.now(timezone.utc)
            scan.raw_output = str(e)
            db.session.commit()
