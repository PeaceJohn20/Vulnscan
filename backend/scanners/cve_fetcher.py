"""
NVD CVE API Client
Fetches CVE data from NIST National Vulnerability Database API v2.
Used to correlate service versions with known vulnerabilities.
"""

import requests
import json
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS  = {"User-Agent": "VulnScan/1.0"}

CVSS_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "NONE":     "Low",
}
def _is_online() -> bool:
    """Check if NVD API is reachable."""
    try:
        requests.get("https://nvd.nist.gov", timeout=5, headers=HEADERS)
        return True
    except Exception:
        return False
    
def _save_cves_to_db(cves: List[Dict]):
    """Save fetched CVEs to local SQLite for offline use."""
    try:
        from database import db, Vulnerability
        for cve in cves:
            existing = Vulnerability.query.filter_by(cve_id=cve["cve_id"]).first()
            if existing:
                existing.description = cve["description"]
                existing.severity    = cve["severity"]
                existing.cvss_score  = cve["cvss_score"]
                existing.published   = cve["published"]
                existing.references  = json.dumps(cve["references"])
                existing.fetched_at  = datetime.now(timezone.utc)
            else:
                vuln = Vulnerability(
                    cve_id      = cve["cve_id"],
                    description = cve["description"],
                    severity    = cve["severity"],
                    cvss_score  = cve["cvss_score"],
                    published   = cve["published"],
                    references  = json.dumps(cve["references"]),
                    fetched_at  = datetime.now(timezone.utc)
                )
                db.session.add(vuln)
        db.session.commit()
        print(f"[CVE] Cached {len(cves)} CVEs locally")
    except Exception as e:
        print(f"[CVE] Cache save error: {e}")


def _get_cves_from_db(keyword: str, limit: int = 5) -> List[Dict]:
    """Query local SQLite for CVEs when offline."""
    try:
        from database import Vulnerability
        results = Vulnerability.query.filter(
            Vulnerability.description.ilike(f"%{keyword}%")
        ).limit(limit).all()
        print(f"[CVE] Offline mode — found {len(results)} local CVEs for '{keyword}'")
        return [v.to_dict() for v in results]
    except Exception as e:
        print(f"[CVE] Local DB query error: {e}")
        return []

def _cvss_from_item(item: dict) -> tuple:
    """Extract (score, severity) from NVD CVE item."""
    metrics = item.get("metrics", {})

    # Try CVSSv3.1 first, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score    = data.get("baseScore", 0.0)
            severity = data.get("baseSeverity", "NONE")
            return float(score), CVSS_SEVERITY.get(severity.upper(), "Low")

    for entry in metrics.get("cvssMetricV2", []):
        data     = entry.get("cvssData", {})
        score    = data.get("baseScore", 0.0)
        severity = entry.get("baseSeverity", "NONE")
        return float(score), CVSS_SEVERITY.get(severity.upper(), "Low")

    return 0.0, "Low"


def fetch_cves_by_keyword(keyword: str, limit: int = 5) -> List[Dict]:
    """
    Search NVD for CVEs matching a service/version keyword.
    Falls back to local SQLite cache when offline.
    """
    if not _is_online():
        print("[CVE] Offline — using local cache")
        return _get_cves_from_db(keyword, limit)

    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": limit,
        "startIndex":     0,
    }
    try:
        resp = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return _get_cves_from_db(keyword, limit)
        data = resp.json()
        cves = _parse_nvd_response(data)
        # Save to local cache for future offline use
        _save_cves_to_db(cves)
        return cves
    except Exception as e:
        print(f"[CVE] Fetch error for '{keyword}': {e} — trying local cache")
        return _get_cves_from_db(keyword, limit)


def fetch_cve_by_id(cve_id: str) -> Optional[Dict]:
    """Fetch a specific CVE by its ID (e.g. CVE-2021-44228)."""
    params = {"cveId": cve_id}
    try:
        resp = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return None
        data  = resp.json()
        items = _parse_nvd_response(data)
        return items[0] if items else None
    except Exception as e:
        print(f"[CVE] Fetch error for '{cve_id}': {e}")
        return None

def fetch_recent_cves(days_back: int = 7, limit: int = 20) -> List[Dict]:
    """
    Fetch recently published CVEs for dashboard feed.
    Falls back to most recent locally cached CVEs when offline.
    """
    if not _is_online():
        print("[CVE] Offline — returning cached recent CVEs")
        try:
            from database import Vulnerability
            results = Vulnerability.query.order_by(
                Vulnerability.fetched_at.desc()
            ).limit(limit).all()
            return [v.to_dict() for v in results]
        except Exception as e:
            print(f"[CVE] Local recent CVE error: {e}")
            return []

    from datetime import datetime, timedelta, timezone
    end    = datetime.now(timezone.utc)
    start  = end - timedelta(days=days_back)
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": limit,
    }
    try:
        resp = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=20)
        if resp.status_code != 200:
            return []
        cves = _parse_nvd_response(resp.json())
        _save_cves_to_db(cves)
        return cves
    except Exception as e:
        print(f"[CVE] Recent CVE fetch error: {e}")
        return []


def _parse_nvd_response(data: dict) -> List[Dict]:
    """Parse raw NVD API response into simplified list."""
    results = []
    for vuln in data.get("vulnerabilities", []):
        item = vuln.get("cve", {})
        cve_id = item.get("id", "")
        descs  = item.get("descriptions", [])
        desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "No description available.")
        refs   = [r.get("url") for r in item.get("references", [])[:5]]
        score, severity = _cvss_from_item(item)

        results.append({
            "cve_id":      cve_id,
            "description": desc,
            "severity":    severity,
            "cvss_score":  score,
            "published":   item.get("published", ""),
            "references":  refs,
        })
    return results


def correlate_service_cves(service: str, version: str) -> List[Dict]:
    """
    Given a service name + version string, query NVD and return
    matching CVEs. Combines service+version for best match.
    """
    results = []
    keywords = []

    if version and version != "unknown":
        keywords.append(f"{service} {version}")
    keywords.append(service)

    seen = set()
    for kw in keywords:
        cves = fetch_cves_by_keyword(kw, limit=3)
        for cve in cves:
            if cve["cve_id"] not in seen:
                seen.add(cve["cve_id"])
                results.append(cve)
        time.sleep(0.4)   # NVD rate-limit courtesy

    return results[:5]
