"""
Bandit Static Code Scanner
Scans Python source files for common security issues.
"""

import subprocess
import json
import os
import tempfile
from typing import Dict, Any, List

SEVERITY_MAP = {
    "HIGH":   "High",
    "MEDIUM": "Medium",
    "LOW":    "Low",
}

CONFIDENCE_MAP = {
    "HIGH":   3,
    "MEDIUM": 2,
    "LOW":    1,
}

REMEDIATION_HINTS = {
    "B101": "Avoid assert statements in production code; use proper validation.",
    "B102": "os.execl and related calls can be dangerous; validate all inputs.",
    "B103": "Setting file permissions explicitly; ensure least-privilege access.",
    "B105": "Hardcoded passwords detected — use environment variables or a secrets manager.",
    "B106": "Hardcoded passwords detected — use environment variables or a secrets manager.",
    "B107": "Hardcoded passwords detected — use environment variables or a secrets manager.",
    "B108": "Use a temp directory that is not world-writable.",
    "B110": "Use exception handling carefully; don't swallow exceptions silently.",
    "B112": "Use sys.exit() instead of os._exit().",
    "B201": "Flask app running in debug mode — disable in production.",
    "B301": "Use of pickle is insecure; switch to JSON or msgpack.",
    "B302": "Marshal module is insecure for untrusted data.",
    "B303": "MD5/SHA1 are weak hash functions; use SHA-256 or higher.",
    "B304": "Weak cipher; use AES-256-GCM.",
    "B305": "Weak cipher mode; use GCM or CBC with HMAC.",
    "B306": "mktemp is insecure; use tempfile.mkstemp().",
    "B307": "eval() is dangerous; avoid or restrict to trusted input.",
    "B308": "mark_safe() can create XSS vulnerabilities; sanitize input.",
    "B310": "Validate URLs before using urlopen.",
    "B311": "Standard random is not cryptographically secure; use secrets module.",
    "B312": "Telnet is insecure; use SSH.",
    "B313": "XML parsing vulnerable to XXE; use defusedxml.",
    "B314": "XML parsing vulnerable to XXE; use defusedxml.",
    "B315": "XML parsing vulnerable to XXE; use defusedxml.",
    "B316": "XML parsing vulnerable to XXE; use defusedxml.",
    "B317": "XML parsing vulnerable to XXE; use defusedxml.",
    "B318": "XML parsing vulnerable to XXE; use defusedxml.",
    "B319": "XML parsing vulnerable to XXE; use defusedxml.",
    "B320": "XML parsing vulnerable to XXE; use defusedxml.",
    "B321": "FTP is insecure; switch to SFTP.",
    "B322": "input() is insecure in Python 2; use raw_input() or Python 3.",
    "B323": "Unverified SSL context — enable certificate verification.",
    "B324": "Use hashlib.sha256 or stronger; avoid MD5/SHA1.",
    "B325": "tempnam is insecure; use tempfile module.",
    "B401": "Import of insecure module (telnetlib); prefer paramiko/SSH.",
    "B402": "Import of insecure module; review usage.",
    "B403": "Import of pickle is a security risk for untrusted data.",
    "B404": "subprocess use — validate and sanitize all inputs.",
    "B501": "Weak TLS version — enforce TLS 1.2 minimum.",
    "B502": "ssl.wrap_socket() is deprecated; use SSLContext.",
    "B503": "Weak SSL/TLS settings; enforce strong ciphers.",
    "B504": "ssl.wrap_socket() with weak settings; use SSLContext.",
    "B505": "Weak RSA/DSA key size; use at least 2048 bits.",
    "B506": "YAML load() is unsafe; use yaml.safe_load().",
    "B507": "Paramiko missing host key check — enable strict host key checking.",
    "B601": "shell=True with subprocess — inject risk; avoid or sanitize input.",
    "B602": "subprocess call with shell=True — validate all inputs.",
    "B603": "subprocess call without shell=True — validate inputs.",
    "B604": "Function call with shell=True — injection risk.",
    "B605": "os.system() is a security risk; use subprocess with validation.",
    "B606": "os.system() equivalent — same risks; prefer subprocess.",
    "B607": "Partial executable path — use absolute paths.",
    "B608": "Hardcoded SQL query — use parameterized queries to prevent SQL injection.",
    "B609": "Wildcard injection in subprocess call.",
    "B610": "Django extra() with user input — SQL injection risk.",
    "B611": "Django RawSQL with user input — SQL injection risk.",
    "B701": "Jinja2 autoescape disabled — XSS risk; enable autoescape.",
    "B702": "Mako template without autoescape — XSS risk.",
    "B703": "Django mark_safe — XSS risk; sanitize content first.",
}

DEFAULT_REMEDIATION = "Review this code pattern for security implications and apply secure coding best practices."


def scan_code(file_path: str) -> Dict[str, Any]:
    """
    Run Bandit on a Python file or directory.
    Returns structured findings.
    """
    if not os.path.exists(file_path):
        return {"error": f"Path not found: {file_path}", "findings": []}

    try:
        result = subprocess.run(
         ["py", "-3.11", "-m", "bandit", "-r", "-f", "json", "-l", "-i", file_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw_json = result.stdout
        if not raw_json.strip():
            return {"findings": [], "raw_output": result.stderr}

        data     = json.loads(raw_json)
        findings = _parse_bandit_output(data)
        return {
            "findings":   findings,
            "raw_output": raw_json,
            "stats": {
                "total_issues":  len(findings),
                "high":   sum(1 for f in findings if f["severity"] == "High"),
                "medium": sum(1 for f in findings if f["severity"] == "Medium"),
                "low":    sum(1 for f in findings if f["severity"] == "Low"),
            },
        }
    except subprocess.TimeoutExpired:
        return {"error": "Bandit scan timed out", "findings": []}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}", "findings": []}
    except FileNotFoundError:
        return {"error": "Bandit not installed (pip install bandit)", "findings": []}


def scan_code_string(code: str, filename: str = "uploaded_code.py") -> Dict[str, Any]:
    """Scan a Python code string by writing to a temp file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="vulnscan_"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = scan_code(tmp_path)
        # Fix filename in results
        for finding in result.get("findings", []):
            finding["filename"] = filename
        return result
    finally:
        os.unlink(tmp_path)


def _parse_bandit_output(data: dict) -> List[Dict]:
    """Convert Bandit JSON output to VulnScan finding format."""
    findings = []
    for issue in data.get("results", []):
        test_id   = issue.get("test_id", "")
        severity  = SEVERITY_MAP.get(issue.get("issue_severity", "LOW"), "Low")
        remediation = REMEDIATION_HINTS.get(test_id, DEFAULT_REMEDIATION)

        findings.append({
            "finding_type": "code_issue",
            "port":         None,
            "protocol":     None,
            "service":      "Python Code",
            "version":      None,
            "severity":     severity,
            "description":  (
                f"[{test_id}] {issue.get('issue_text', '')} "
                f"(Confidence: {issue.get('issue_confidence','UNKNOWN')}) "
                f"at {issue.get('filename','')} line {issue.get('line_number','?')}"
            ),
            "remediation":  remediation,
            "filename":     issue.get("filename", ""),
            "line_number":  issue.get("line_number"),
            "test_id":      test_id,
            "raw_detail":   json.dumps(issue),
        })

    return findings
