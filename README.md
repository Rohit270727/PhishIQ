# PhishIQ - Phishing Detection Platform

PhishIQ is a full-stack phishing detection tool that scans URLs, messages, QR codes, and uploaded files (`.txt`, `.eml`, `.pdf`) for phishing indicators, combining rule-based heuristics with machine learning, WHOIS lookups, SSL certificate inspection, and visual brand-impersonation detection. It also ships as a Chrome extension and exposes a public REST API for programmatic scanning.

## Features

**Detection engine**
- URL analysis: suspicious TLDs, URL shorteners, IP-based URLs, excessive subdomains, brand-name impersonation, redirect patterns, non-standard ports
- Typosquatting detection using Levenshtein edit-distance against a list of known brands
- Domain age lookup via WHOIS (flags very recently registered domains)
- SSL certificate inspection (flags freshly issued free-CA certificates)
- Visual brand-impersonation detection â€” screenshots the target page with Playwright and compares it against known brand login pages using perceptual hashing
- Machine learning model blended with heuristic scoring for a final risk score (0-100) and verdict (Safe / Suspicious / Dangerous)
- Message/SMS/email scam analysis (urgency language, embedded links, etc.)
- QR code decoding and scanning
- File upload scanning: `.txt`, `.eml` (with header/body parsing), and `.pdf` (text extraction)
- Bulk scanning of multiple URLs at once, with CSV export

**Platform features**
- User accounts with registration, login, and password reset via email
- Per-scan history with filtering by type and verdict
- Downloadable PDF scan reports
- Weekly email digest summarizing scan activity
- Admin dashboard with platform-wide analytics (top flagged URLs, recent activity across all users)
- Public REST API (`/api/v1/scan`) secured with per-user API keys
- Chrome extension (Manifest V3) for one-click scanning of the active tab

**Security**
- CSRF protection on all state-changing forms (Flask-WTF)
- Rate limiting on public/unauthenticated endpoints
- XSS-safe rendering (Jinja2 auto-escaping) verified against injected script payloads
- Escaped user input in generated PDF reports to prevent markup injection

## Tech Stack

- **Backend:** Flask, SQLAlchemy, SQLite
- **Auth:** Werkzeug password hashing, Flask sessions, Flask-WTF (CSRF)
- **Detection:** scikit-learn (ML scoring), python-whois, OpenCV, Playwright + ImageHash (visual similarity), qrcode/pyzbar-style decoding
- **Reports & email:** ReportLab (PDF generation), Gmail SMTP
- **Rate limiting:** Flask-Limiter
- **Extension:** Chrome Manifest V3 (vanilla JS)

## Project Structure

```
PhishIQ/
â”œâ”€â”€ app.py                     # Flask routes and app setup
â”œâ”€â”€ config.py                  # App configuration (reads from .env)
â”œâ”€â”€ models.py                  # SQLAlchemy models
â”œâ”€â”€ detectors/
â”‚   â”œâ”€â”€ url_analyzer.py        # Core URL heuristics + scoring
â”‚   â”œâ”€â”€ message_analyzer.py    # Message/SMS/email scam analysis
â”‚   â”œâ”€â”€ typosquat_detector.py  # Levenshtein-based typosquatting checks
â”‚   â”œâ”€â”€ whois_utils.py         # Domain age lookups
â”‚   â”œâ”€â”€ ssl_utils.py           # Certificate inspection
â”‚   â”œâ”€â”€ visual_similarity.py   # Screenshot + perceptual hash comparison
â”‚   â”œâ”€â”€ brand_hashes.json      # Reference hashes for known brand login pages
â”‚   â”œâ”€â”€ file_extractor.py      # .txt / .eml / .pdf text extraction
â”‚   â”œâ”€â”€ report_generator.py    # PDF report generation
â”‚   â”œâ”€â”€ email_utils.py         # SMTP sending
â”‚   â””â”€â”€ qr_utils.py            # QR code decoding
â”œâ”€â”€ chrome_extension/          # Manifest V3 Chrome extension
â”œâ”€â”€ templates/                 # Jinja2 templates
â”œâ”€â”€ static/                    # CSS, uploaded files
â””â”€â”€ requirements.txt
```

## Setup

**1. Clone and create a virtual environment**
```bash
git clone <your-repo-url>
cd PhishIQ
python -m venv venv
venv\Scripts\Activate.ps1        # Windows PowerShell
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Install Playwright's browser binary** (required for visual similarity checks; not covered by `requirements.txt`)
```bash
playwright install chromium
```

**4. Configure environment variables**

Create a `.env` file in the project root:
```
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
GMAIL_ADDRESS=your.email@gmail.com
GMAIL_APP_PASSWORD=<a Gmail App Password, not your regular password>
```

Gmail App Passwords require 2-Step Verification enabled on the account, generated at
`https://myaccount.google.com/apppasswords`.

**5. Run the app**
```bash
python app.py
```

Visit `http://127.0.0.1:5050`.

## Demo Account

To quickly populate the app with realistic sample data instead of starting with an empty dashboard:

```bash
python seed_demo_data.py
```

This creates a demo account (`demo` / `demo1234`) with 10 sample scans covering URL, message, and QR scan types, across Safe, Suspicious, and Dangerous verdicts. The script is idempotent - running it again won't create duplicates.

## Loading the Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `chrome_extension/` folder
4. Pin the PhishIQ icon to your toolbar
5. Make sure `python app.py` is running locally â€” the extension calls `http://127.0.0.1:5050/api/extension/scan`

## Using the Public API

Generate an API key from the **API Keys** page in the app, then:

```bash
curl -X POST http://127.0.0.1:5050/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{"url": "http://example.com"}'
```

Rate limited to 30 requests/minute per key.

## Known Limitations

- Rate limiting uses in-memory storage â€” resets on restart and isn't safe for multi-process deployments. Would need Redis-backed storage for real production use.
- Visual brand-impersonation detection currently covers 9 major brands (PayPal, Google, Microsoft, Amazon, Facebook, Apple, Netflix, Instagram, LinkedIn) â€” easily extendable.
- No automated test suite yet.

## Why I Built This

PhishIQ was built to go beyond simple keyword-matching phishing detectors by combining multiple independent signals â€” heuristic scoring, ML, WHOIS domain age, SSL certificate metadata, and visual brand-impersonation detection via perceptual hashing â€” into a single risk score. It also includes the kind of platform features (auth, API keys, admin analytics, CSRF/XSS hardening) that a real product would need, not just a detection script.

