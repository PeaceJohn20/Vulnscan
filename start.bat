@echo off
title VulnScan - Vulnerability Scanner
echo.
echo ========================================
echo    VulnScan - Vulnerability Scanner
echo ========================================
echo.

cd /d "%~dp0backend"

echo Installing dependencies...
pip install flask flask-cors flask-jwt-extended flask-sqlalchemy python-nmap bandit reportlab requests python-dotenv bcrypt sqlalchemy

if not exist "reports" mkdir reports

echo.
echo Starting VulnScan on http://localhost:5000
echo Open frontend\index.html in your browser
echo Login: Peace / Justdoit@25
echo Press Ctrl+C to stop
echo.

python app.py
pause
