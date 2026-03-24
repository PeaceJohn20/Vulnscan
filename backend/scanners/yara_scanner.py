"""
YARA Scanner
Pattern-matching engine for malware/threat signatures.
Scans files or directories against a set of YARA rules.
"""

import os
import json
import tempfile
from typing import Dict, Any, List

# Built-in YARA rules for common threats & vulnerability signatures
BUILTIN_RULES = r"""
rule Suspicious_Eval_Exec {
    meta:
        description = "Detects suspicious eval/exec patterns often used in webshells"
        severity = "High"
        remediation = "Review and remove dynamic code execution; use safe alternatives."
    strings:
        $eval1 = "eval(base64_decode" nocase
        $eval2 = "eval($_POST" nocase
        $eval3 = "eval($_GET" nocase
        $exec1 = "exec($_REQUEST" nocase
        $exec2 = "passthru($_" nocase
        $exec3 = "system($_" nocase
    condition:
        any of them
}

rule Hardcoded_Credentials {
    meta:
        description = "Detects hardcoded passwords or API keys in source files"
        severity = "High"
        remediation = "Move credentials to environment variables or a secrets manager."
    strings:
        $p1 = "password = \"" nocase
        $p2 = "passwd = \"" nocase
        $p3 = "api_key = \"" nocase
        $p4 = "secret_key = \"" nocase
        $p5 = "AWS_SECRET" nocase
        $p6 = "PRIVATE_KEY" nocase
    condition:
        any of them
}

rule SQL_Injection_Pattern {
    meta:
        description = "Detects unsafe SQL query construction patterns"
        severity = "Critical"
        remediation = "Use parameterized queries or an ORM to prevent SQL injection."
    strings:
        $sql1 = "SELECT * FROM" nocase
        $sql2 = "' OR '1'='1" nocase
        $sql3 = "UNION SELECT" nocase
        $sql4 = "DROP TABLE" nocase
        $unsafe = "\" + user_input" nocase
    condition:
        ($sql2 or $sql3 or $sql4) or
        ($sql1 and $unsafe)
}

rule Malware_Reverse_Shell {
    meta:
        description = "Detects common reverse shell patterns"
        severity = "Critical"
        remediation = "Remove this code immediately; investigate system for compromise."
    strings:
        $r1 = "/bin/bash -i" nocase
        $r2 = "nc -e /bin/sh" nocase
        $r3 = "bash -i >& /dev/tcp" nocase
        $r4 = "python -c 'import socket,subprocess,os'" nocase
        $r5 = "0>&1" nocase
    condition:
        2 of them
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell indicators"
        severity = "Critical"
        remediation = "Remove webshell file; rotate all credentials; audit access logs."
    strings:
        $w1 = "c99shell" nocase
        $w2 = "r57shell" nocase
        $w3 = "<?php @eval(" nocase
        $w4 = "<?php system(" nocase
        $w5 = "FilesMan" nocase
        $w6 = "b374k" nocase
    condition:
        any of them
}

rule Insecure_Random {
    meta:
        description = "Detects use of insecure random number generators for security purposes"
        severity = "Medium"
        remediation = "Use 'import secrets' or 'os.urandom()' for cryptographic randomness."
    strings:
        $r1 = "random.randint" nocase
        $r2 = "random.choice" nocase
        $r3 = "Math.random()" nocase
    condition:
        any of them
}

rule Sensitive_Data_Exposure {
    meta:
        description = "Detects potential exposure of sensitive data in logs or output"
        severity = "Medium"
        remediation = "Do not log sensitive fields; sanitize output before display."
    strings:
        $s1 = "print(password" nocase
        $s2 = "log.info(password" nocase
        $s3 = "console.log(password" nocase
        $s4 = "print(secret" nocase
        $s5 = "print(api_key" nocase
    condition:
        any of them
}
"""

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _get_rules():
    """Compile and return YARA rules object, or None if yara not installed."""
    try:
        import yara
        return yara.compile(source=BUILTIN_RULES)
    except ImportError:
        return None
    except Exception as e:
        print(f"[YARA] Rule compilation error: {e}")
        return None


def scan_file(file_path: str) -> Dict[str, Any]:
    """Scan a single file with YARA rules."""
    rules = _get_rules()
    if rules is None:
        return _yara_unavailable()

    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "findings": []}

    try:
        import yara
        matches = rules.match(file_path)
        return _build_result(matches, file_path)
    except yara.Error as e:
        return {"error": str(e), "findings": []}


def scan_string(content: str, filename: str = "content") -> Dict[str, Any]:
    """Scan a string of content with YARA rules."""
    rules = _get_rules()
    if rules is None:
        return _yara_unavailable()

    try:
        import yara
        matches = rules.match(data=content.encode())
        return _build_result(matches, filename)
    except yara.Error as e:
        return {"error": str(e), "findings": []}


def scan_directory(dir_path: str, extensions: List[str] = None) -> Dict[str, Any]:
    """Scan all files in a directory."""
    if extensions is None:
        extensions = [".py", ".php", ".js", ".sh", ".rb", ".pl", ".txt", ".conf"]

    all_findings = []
    rules = _get_rules()
    if rules is None:
        return _yara_unavailable()

    try:
        import yara
        for root, _, files in os.walk(dir_path):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    matches = rules.match(fpath)
                    result  = _build_result(matches, fpath)
                    all_findings.extend(result["findings"])
                except Exception:
                    continue
    except Exception as e:
        return {"error": str(e), "findings": []}

    return {
        "findings":    all_findings,
        "raw_output":  f"YARA directory scan of {dir_path}: {len(all_findings)} findings",
        "stats": _stats(all_findings),
    }


def _build_result(matches, source_path: str) -> Dict[str, Any]:
    findings = []
    for match in matches:
        meta      = match.meta or {}
        severity  = meta.get("severity", "Medium")
        remediation = meta.get("remediation", "Review flagged pattern and remediate accordingly.")

        matched_strings = []
        for s in match.strings:
            if hasattr(s, "instances"):
                for inst in s.instances:
                    matched_strings.append(inst.matched_data.decode("utf-8", errors="replace"))
            elif isinstance(s, tuple):
                matched_strings.append(str(s))

        findings.append({
            "finding_type": "yara_match",
            "port":         None,
            "protocol":     None,
            "service":      "File Scan",
            "version":      None,
            "severity":     severity,
            "description":  (
                f"YARA rule '{match.rule}' matched in {os.path.basename(source_path)}. "
                f"{meta.get('description', '')} "
                f"Matched strings: {matched_strings[:3]}"
            ),
            "remediation":  remediation,
            "filename":     source_path,
            "rule_name":    match.rule,
            "raw_detail":   json.dumps({
                "rule":     match.rule,
                "tags":     list(match.tags),
                "meta":     meta,
                "matches":  matched_strings[:5],
            }),
        })

    return {
        "findings":   findings,
        "raw_output": f"YARA scan of {source_path}: {len(findings)} rules matched",
        "stats": _stats(findings),
    }


def _stats(findings: List[Dict]) -> Dict:
    return {
        "total":    len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high":     sum(1 for f in findings if f["severity"] == "High"),
        "medium":   sum(1 for f in findings if f["severity"] == "Medium"),
        "low":      sum(1 for f in findings if f["severity"] == "Low"),
    }


def _yara_unavailable() -> Dict:
    return {
        "findings":   [],
        "raw_output": "YARA not available (pip install yara-python)",
        "error":      "YARA library not installed",
        "stats":      {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
    }
