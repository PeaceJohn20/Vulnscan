 🛡️ VulnScan — Vulnerability Scanning Tool

**Design and Implementation of a Vulnerability Scanning Tool**

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Tools & Technologies](#tools--technologies)
4. [Scope](#scope)
5. [Installation](#installation)
6. [Running the Application](#running-the-application)
7. [LAN Deployment](#lan-deployment)
8. [CVE Offline Support](#cve-offline-support)
9. [Usage Guide](#usage-guide)
10. [API Reference](#api-reference)
11. [Ethical & Legal Notice](#ethical--legal-notice)

---

## Project Overview

VulnScan is a web-based vulnerability scanning platform built for non-experts. It identifies security weaknesses in computer systems and networks including:

- **Open ports** and exposed services (via Nmap)
- **CVE-correlated vulnerabilities** matched against the NIST National Vulnerability Database
- **Static code security issues** in Python source files (via Bandit)
- **Malware and threat pattern detection** in files (via YARA)
- **Professional PDF reports** with CVSS-based severity ranking and remediation guidance

> **Scope Limitation:** This tool identifies and reports vulnerabilities only.
> It does NOT exploit systems, attempt to fix weaknesses, or store data beyond
> a configurable retention window. All scans require explicit user authorization.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React.js)                   │
│  Dashboard │ Assets │ Scans │ Reports │ User Management  │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API (JWT Auth)
┌──────────────────────▼──────────────────────────────────┐
│               BACKEND (Python / Flask)                   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  Nmap    │  │  Bandit  │  │   YARA   │  │ Report │  │
│  │ Scanner  │  │  Scanner │  │  Scanner │  │  Lab   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  │
│       └─────────────┴─────────────┘             │       │
│                      │                          │       │
│             ┌─────────▼──────────┐              │       │
│             │  Scan Orchestrator  │              │       │
│             └─────────┬──────────┘              │       │
│                       │                         │       │
│             ┌─────────▼──────────┐              │       │
│             │   NVD CVE API      │◄─────────────┘       │
│             │  (NIST Online DB)  │                      │
│             └─────────┬──────────┘                      │
│                       │                                  │
│             ┌─────────▼──────────┐                      │
│             │  SQLite Database   │                      │
│             │ Users │ Scans      │                      │
│             │ Assets│ Results    │                      │
│             │ Vulns │ Reports    │                      │
│             └────────────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

---

## Tools & Technologies

| Tool | Role | Reference |
|------|------|-----------|
| **Python 3.10+** | Primary backend language | Lyon, 2009 |
| **Flask** | Web framework / API controller | — |
| **SQLite + SQLAlchemy** | Local offline-capable database | — |
| **React.js** | Frontend dashboard UI | — |
| **JWT (JSON Web Tokens)** | Secure authentication | RFC 7519 |
| **Nmap** | Port scanning & service fingerprinting | Lyon, 2009 |
| **Bandit** | Python static code analysis | — |
| **YARA** | File-based pattern/malware matching | — |
| **ReportLab** | PDF report generation | — |
| **NIST NVD API v2** | Live CVE/vulnerability database | NIST, 2026 |
| **CVSS** | Vulnerability severity scoring | Schiffman, 2012 |

---

## Scope

✅ **In Scope:**
- Identifying open ports and running services on target systems
- Detecting outdated software versions and weak configurations
- Correlating findings with CVE records from the NVD
- Scanning Python source code for security anti-patterns (Bandit)
- Detecting malware signatures and threat patterns in files (YARA)
- Generating structured, non-technical vulnerability reports with remediation guidance
- Supporting users with little cybersecurity experience

❌ **Out of Scope:**
- Exploiting discovered vulnerabilities
- Attempting to fix or patch identified weaknesses
- Scanning systems without explicit user authorization
- Web application scanning (SQL injection, XSS, etc.)
- IoT or containerized infrastructure scanning

---

## Installation

### Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| Python | 3.10+ | https://python.org |
| Nmap | 7.x+ | `sudo apt install nmap` (Linux) / https://nmap.org |
| pip | latest | included with Python |

### Step 1 — Clone / Extract Project

```bash
cd /path/to/vulnscan
```

### Step 2 — Create Virtual Environment

A virtual environment is required to avoid system package conflicts, especially on Kali Linux and other externally-managed Python environments.

```bash
cd backend
python3 -m venv venv
```

### Step 3 — Activate Virtual Environment

```bash
# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

> You will see `(venv)` appear at the start of your terminal line when activated. Always activate the virtual environment before running any pip or python commands.

### Step 4 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
```
flask==3.0.3
flask-cors==4.0.1
flask-jwt-extended==4.6.0
python-nmap==0.7.1
bandit==1.7.9
yara-python==4.5.1
reportlab==4.2.2
requests==2.31.0
python-dotenv==1.0.1
bcrypt==4.1.3
sqlalchemy==2.0.31
```

> **Note on yara-python:** May require build tools.
> Ubuntu/Kali: `sudo apt install build-essential libssl-dev python3-dev -y`
> macOS: `xcode-select --install`

### Step 5 — Install Nmap (Port Scanning)

```bash
# Ubuntu/Debian/Kali
sudo apt update && sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap

# Windows
# Download installer from: https://nmap.org/download.html
# Run as Administrator for best results
```

---

## Running the Application

### Quick Start (Linux/macOS)

```bash
chmod +x start.sh
./start.sh
```

### Manual Start

```bash
# Terminal 1 — Backend
cd backend
source venv/bin/activate
python app.py
# API running at: http://localhost:5000

# Browser — Frontend
# Open: frontend/index.html
```

> **Note:** SQLite database is created automatically in `backend/instance/vulnscan.db` on first run.

### Verify Database Tables

After starting the backend, confirm all tables were created:

```bash
sqlite3 backend/instance/vulnscan.db ".tables"
```

Expected output:
```
assets    reports    scan_results    scans    users    vulnerabilities
```

### Default Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `Admin` | `Admin@1234!` |

> Change the admin password immediately after first login via the Users page.

---

## LAN Deployment

VulnScan supports multi-user access over a local network. Only the server owner needs to install and run VulnScan. All other users simply open a browser.

### How It Works

```
[Server Machine — runs VulnScan]
        │
        │  LAN (WiFi or Cable)
        │
   ┌────┴────┬──────────┐
   │         │          │
 Laptop    Phone    Desktop
 (browser) (browser) (browser)
```

### Server Owner Setup

```bash
# Start the backend (makes it available on the network)
cd backend
source venv/bin/activate
python app.py
```

The backend binds to `0.0.0.0` by default, meaning it is accessible from any device on the same network.

### Other Users (No Installation Required)

1. Connect to the same WiFi or LAN as the server machine
2. Open any browser
3. Navigate to: `http://<server-ip>:5000`

To find your server IP:

```bash
ip a
# Look for your local IP e.g. 192.168.1.x or 192.168.83.x
```

Example: `http://192.168.83.137:5000`

---

## CVE Offline Support

VulnScan supports **hybrid CVE mode** — it queries the NIST NVD API when online and automatically falls back to a local SQLite cache when offline.

### How It Works

```
Online:
VulnScan → NVD API → Fetch CVEs → Save to SQLite → Return results

Offline:
VulnScan → NVD API unreachable → Query local SQLite → Return cached results
```

### CVE Mode Behaviour

| Mode | Source | Behaviour |
|------|--------|-----------|
| Online | NIST NVD API | Fetches live CVEs and caches them locally |
| Offline | Local SQLite | Queries previously cached CVEs automatically |
| Dashboard (online) | NIST NVD API | Shows live CVE feed |
| Dashboard (offline) | Local SQLite | Shows most recently cached CVEs |

> CVE caching happens automatically every time a scan is run while online. The more scans run online, the richer the offline cache becomes.

### Pre-Populating the CVE Database (Recommended)

To maximise offline CVE coverage, bulk download CVEs from the NVD API before going offline.

#### Step 1 — Create the download script

```bash
cd backend
nano nvd_bulk_download.py
```

Paste the following:

```python
import requests
import json
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_FILE = "nvd_bulk_cves.json"

def fetch_all_cves():
    all_cves = []
    start = 0
    page_size = 2000
    total = None

    print("[NVD] Starting bulk CVE download...")

    while True:
        params = {
            "startIndex": start,
            "resultsPerPage": page_size
        }
        try:
            resp = requests.get(NVD_API, params=params, timeout=30,
                                headers={"User-Agent": "VulnScan/1.0"})
            if resp.status_code != 200:
                print(f"[NVD] Error {resp.status_code} at index {start}")
                break

            data = resp.json()

            if total is None:
                total = data.get("totalResults", 0)
                print(f"[NVD] Total CVEs available: {total}")

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            all_cves.extend(vulns)
            start += len(vulns)
            print(f"[NVD] Downloaded {start}/{total} CVEs...")

            if len(all_cves) % 10000 == 0:
                save_progress(all_cves)

            time.sleep(6)  # Respect NVD rate limit (5 req/30s)

        except Exception as e:
            print(f"[NVD] Error: {e} — retrying in 30s...")
            time.sleep(30)

    print(f"[NVD] Download complete! Total: {len(all_cves)} CVEs")
    save_progress(all_cves)

def save_progress(cves):
    with open(OUTPUT_FILE, "w") as f:
        json.dump(cves, f)
    print(f"[NVD] Saved {len(cves)} CVEs to {OUTPUT_FILE}")

if __name__ == "__main__":
    fetch_all_cves()
```

#### Step 2 — Run the download

```bash
source venv/bin/activate
python nvd_bulk_download.py
```

> ⚠️ This process takes 30–60 minutes due to NVD API rate limits. Progress is saved every 10,000 CVEs so it can be safely interrupted and resumed.

#### Step 3 — Import into SQLite

After download completes, import the CVEs into your local database:

```bash
python import_nvd.py
```

---

## Usage Guide

### 1. Login
Open `frontend/index.html` in your browser and sign in with the default admin credentials.

### 2. Add an Asset
Navigate to **Assets → Add Asset**
- Enter a name (e.g., "Web Server")
- Provide the IP address or hostname of the target
- Select asset type (host, server, network, webapp)

> ⚠️ **Authorization Required:** Only add assets you own or have explicit written permission to scan.

### 3. Run a Scan

**Network Scan (Nmap + CVE Correlation):**
1. Go to **Scans → New Scan → Network / Port Scan**
2. Select your asset and scan type:
   - **Quick:** Top 100 ports (fastest, ~1–2 min)
   - **Port:** Ports 1–1024 (standard, ~2–5 min)
   - **Full:** All 65535 ports (comprehensive, ~10–30 min)
3. Click **Start Scan** — the scan runs in the background

**Code Scan (Bandit + YARA):**
1. Go to **Scans → New Scan → Code Scan**
2. Select your asset
3. Paste Python code into the text area
4. Click **Analyse Code**

### 4. Review Results
- Click **View Results** on any completed scan
- Findings are sorted by severity: Critical → High → Medium → Low
- Each finding includes:
  - Finding type and affected port/service
  - CVE ID and CVSS score (when available)
  - Plain-language description
  - Step-by-step remediation guidance

### 5. Generate PDF Report
- From the Results view, click **Generate PDF**
- The report is saved and accessible via the **Reports** page
- Click **Download PDF** to save it locally

### 6. Monitor CVE Feed
The Dashboard shows the last 7 days of CVEs published to the NIST NVD, giving real-time threat intelligence. When offline, the most recently cached CVEs are displayed instead.

---

## API Reference

All API endpoints require `Authorization: Bearer <token>` header except `/api/auth/login` and `/api/auth/register`.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, receive JWT |
| GET | `/api/auth/me` | Current user info |
| GET | `/api/auth/users` | List users (admin) |
| PUT | `/api/auth/users/<id>` | Update user (admin) |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assets` | List assets |
| POST | `/api/assets` | Create asset |
| GET | `/api/assets/<id>` | Get asset |
| PUT | `/api/assets/<id>` | Update asset |
| DELETE | `/api/assets/<id>` | Delete asset |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans` | Start network scan |
| POST | `/api/scans/code` | Start code scan |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/<id>` | Get scan details |
| GET | `/api/scans/<id>/results` | Get findings |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/reports/generate/<scan_id>` | Generate PDF |
| GET | `/api/reports` | List reports |
| GET | `/api/reports/<id>/download` | Download PDF |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | Summary statistics |
| GET | `/api/dashboard/recent-cves` | Live CVE feed |

---

## Database Schema (ERD Summary)

```
User ──< Asset ──< Scan ──< ScanResult >── Vulnerability
                    │
                    └──< Report
```

Six entities (matching the ERD in Chapter 3.4.3):
- **User** — admin or customer roles, JWT authentication
- **Asset** — IP/hostname resources being monitored
- **Scan** — scanning process run against an asset
- **ScanResult** — individual findings from each scan
- **Vulnerability** — CVE records from NVD database (also used as local offline cache)
- **Report** — PDF documentation of scan findings

> **Database Location:** SQLite database is stored at `backend/instance/vulnscan.db`

---

## Ethical & Legal Notice

> This tool is provided strictly for **authorized security testing** only.

**Authorized use cases** :
- Individual developers testing their own systems
- Students conducting academic/educational research on owned lab systems
- Authorized bug bounty programs
- Professional security testing with written contracts
- Small to medium organizations scanning their own infrastructure
- Countries where authorized penetration testing is legal

**Prohibited use:**
- Scanning any system without explicit written authorization
- Using findings to exploit or damage systems
- Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA),
  Nigeria's Cybercrimes (Prohibition, Prevention, etc.) Act 2015, and equivalent laws
  in most jurisdictions.

By using this tool, you confirm that you have authorization to scan all targeted systems.

---

## References

- Lyon, G. F. (2009). *Nmap Network Scanning*. Insecure.com.
- Scarfone, K., & Mell, P. (2007). *NIST SP 800-115: Technical Guide to Information Security Testing*. NIST.
- NIST (2026). *National Vulnerability Database (NVD)*. https://nvd.nist.gov/
- Schiffman, M. (2012). *A Complete Guide to the Common Vulnerability Scoring System (CVSS)*.
- Premchand et al. (2024). *Vulnerability Scanner: Build a Tool That Scans a System for Potential Vulnerability*.
- Moreira, D. et al. (2025). *Intelligent Platform for Automating Vulnerability Detection in Web Applications*.
