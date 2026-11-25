# CloudScan - Python-Based Cloud Port Scanner and Security Reporter

A Flask web application that scans **localhost, private-network or explicitly authorized** targets for open TCP ports,
labels *probable* services, rates exposure risk, generates recommendations and exports PDF / CSV / JSON reports.

> Use only on systems you own or have written permission to test. No stealth scanning, exploitation or DoS features exist.

## Run on Windows (PowerShell)

```powershell
cd C:\path\to\cloud-port-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python database.py
python app.py
```

If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then activate again.
Open **http://127.0.0.1:5000**. The page loads Bootstrap and Chart.js from a CDN, so an internet connection is needed.

## Quick test
1. Register, log in.
2. Port Scanner -> target `127.0.0.1`, ports `1`-`1024` -> Start scan.
3. To see an open port, run `python -m http.server 8000` in another terminal and scan `127.0.0.1` ports `8000`-`8000`.
4. Scan Results / Report Generator -> download PDF, CSV, JSON (copies are also saved in `reports\`).

## Project structure
```
app.py               Flask routes, auth, CSRF, API
scanner.py           validation, authorization guard, threaded TCP scanner
security_analyzer.py risk rules, explanations, recommendations
report_generator.py  PDF (ReportLab), CSV, JSON
database.py          SQLite layer (parameterised queries)
templates/ static/   UI (Bootstrap 5, Chart.js)
reports/ database/   generated files / SQLite DB
```

## Security features
Salted password hashes (Werkzeug), CSRF tokens on every POST/DELETE, HttpOnly + SameSite cookies, 2-hour sessions,
login rate limiting, server-side validation, bound SQL parameters, no shell commands, scan caps
(5000 ports, 200 threads, 0.1-5 s timeout, one scan per user), per-user data isolation, CSP and other security headers,
server bound to 127.0.0.1 only.

## Viva tips
* Services are *probable* (port-number based); no banner grabbing.
* closed = connection refused, filtered = no reply (timeout/firewall), open = TCP handshake completed.
* Open port != vulnerability; ratings describe exposure and are user-configurable.
* Flask dev server is for demonstration only.
