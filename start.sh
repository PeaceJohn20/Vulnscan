#!/usr/bin/env bash
# VulnScan - Start Script (Linux / Kali / macOS)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"

echo ""
echo "========================================"
echo "   VulnScan - Vulnerability Scanner     "
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "ERROR: Python 3 is required."
  echo "Kali: sudo apt install python3"
  exit 1
fi
echo "Python: $(python3 --version)"

# Check Nmap
if command -v nmap &>/dev/null; then
  echo "Nmap:   $(nmap --version | head -1)"
else
  echo "WARNING: Nmap not found. Port scanning unavailable."
  echo "Kali: sudo apt install nmap"
fi

# Create reports folder
mkdir -p "$BACKEND/reports"

# Install dependencies
echo ""
echo "Installing dependencies..."
cd "$BACKEND"
pip3 install -q flask flask-cors flask-jwt-extended flask-sqlalchemy \
  python-nmap bandit reportlab requests python-dotenv bcrypt sqlalchemy

echo ""
echo "Starting VulnScan on http://localhost:5000"
echo "Open frontend/index.html in your browser"
echo "Login: Peace / Justdoit@25"
echo "Press Ctrl+C to stop"
echo ""

python3 app.py
