# PhishIQ - Phishing Detection Platform

PhishIQ is a full-stack phishing detection tool that scans URLs, messages, QR codes, and uploaded files (`.txt`, `.eml`, `.pdf`) for phishing indicators, combining rule-based heuristics with machine learning, WHOIS lookups, SSL certificate inspection, and visual brand-impersonation detection. It also ships as a Chrome extension and exposes a public REST API for programmatic scanning.

## Features

**Detection engine**
- URL analysis: suspicious TLDs, URL shorteners, IP-based URLs, excessive subdomains, brand-name impersonation, redirect patterns, non-standard ports
- Typosquatting detection using Levenshtein edit-distance against a list of known brands
- Domain age lookup via WHOIS (flags very recently registered domains)
- SSL certificate inspection (flags freshly issued free-CA certificates)
- Visual brand-impersonation detection — screenshots the target page with Playwright and compares it against known brand login pages using perceptual hashing
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

## Advanced Features

Beyond the core detection engine, PhishIQ also includes:

**🔍 URL / Domain intelligence**
- DNS analysis (A, AAAA, MX, NS, TXT, CNAME records) to detect suspicious hosting/configuration
- Domain reputation checks against threat-intelligence feeds (VirusTotal, URLhaus, PhishTank, Google Safe Browsing)
- ASN / hosting-provider analysis to flag infrastructure frequently associated with abuse
- Domain/brand relationship detection for visual brand resemblance beyond simple typos
- Unicode / IDN homograph detection (catches look-alike Unicode character attacks, e.g. `paypaⅼ.com`)
- Punycode detection for suspicious `xn--` domains
- Dangling DNS / subdomain takeover detection for domains pointing to unclaimed cloud resources
- Historical DNS/IP change tracking to catch recently weaponized domains
- Redirect-chain visualization showing every hop, HTTP status, hostname, and final destination
- URL normalization (percent encoding, punycode, HTML entities, unusual separators) before analysis
- Query-parameter analysis for suspicious parameters, tracking redirects, encoded payloads, and credential-harvesting patterns
- Favicon fingerprinting against known brands
- Page-source analysis for suspicious JavaScript, external-posting forms, hidden iframes, obfuscated scripts, and credential fields

**🧠 Enhanced phishing detection**
- Brand/entity extraction to determine which company/service a page claims to represent
- Brand-to-domain consistency scoring (e.g. page claims "Microsoft" but the domain is unrelated)
- Login-form detection for pages requesting passwords, OTPs, card numbers, or recovery codes
- Credential-exfiltration detection tracing where submitted form data is actually sent
- Fake CAPTCHA detection
- Browser notification abuse detection
- Cryptocurrency wallet/payment-address detection
- Social-engineering scoring, separated from technical risk scoring

**📧 Email & SMS analysis**

For `.eml` files:
- SPF, DKIM, and DMARC validation/evaluation
- Reply-To vs. From mismatch detection
- Return-Path analysis
- Received-header / IP-chain analysis
- Sender-domain age and reputation checks
- Display-name spoofing and lookalike-sender detection
- Attachment metadata analysis
- Link-text vs. actual-destination mismatch detection
- QR-code extraction from email images/PDFs
- Plain-English "Why is this suspicious?" evidence timeline

**📱 QR security**
- Full URL extraction and re-scanning of every QR-encoded URL through the core scanner
- QR → redirect → final-domain chain detection
- Shortened-URL detection
- Payment/UPI link detection
- QR codes embedded in phishing PDFs/images
- Warnings when visible text and QR destination disagree

**📄 File scanning**

Expanded beyond `.txt`, `.eml`, and `.pdf` to also support:
- `.html`, `.docx`, `.xlsx`, `.pptx`, `.msg`
- Images containing QR codes
- ZIP/container metadata inspection without executing contents

For PDFs specifically:
- Embedded URLs, JavaScript detection, embedded files, forms, external references, QR codes, suspicious annotations, and metadata anomalies

**🌐 Website behavior analysis** (via Playwright)
- Before/after-redirect screenshots
- Login-form and password-field detection
- Fake browser/system dialog detection
- Automatic-download detection
- Clipboard-manipulation detection
- Suspicious popup detection
- Hidden/off-screen element detection
- Right-click/devtools-disabling detection
- Network-request capture
- DOM structure comparison against known phishing templates
- External form-submission endpoint detection
- Page fingerprinting (DOM, favicon, screenshots, text, key assets) to recognize reused phishing kits

**🤖 Explainable ML / scoring**

Instead of a single opaque score, results break down contributing signals, e.g.:

| Signal | Contribution |
|---|---|
| Newly registered domain | +20 |
| Brand impersonation | +25 |
| Suspicious redirect | +15 |
| Credential form | +20 |
| Free SSL certificate | +2 |
| Known malicious reputation | +5 |

Each scan returns a verdict, a calibrated confidence score, and a primary reason (e.g. *"Microsoft login impersonation on an unrelated newly registered domain"*) rather than treating the raw ML output as confidence.

**🛡️ Threat-intelligence layer**

An internal IOC (Indicator of Compromise) system tracking domains, URLs, IPs, ASNs, hashes, email/sender addresses, certificate fingerprints, favicon hashes, and page fingerprints — with relationships (e.g. `phishing-domain → IP → ASN → certificate → other domains`) that form a mini threat graph.

**👤 User-facing features**
- Saved/custom watchlists
- "Scan again" and compare-two-URLs tools
- Scan history timeline and risk-score trend over time
- Team/shared workspaces
- Tags and notes on scans
- User-defined trusted and blocked domain lists
- Notifications when a previously safe domain becomes suspicious
- API usage dashboard with scan quotas/usage limits
- Shareable scan reports with expiring links

**🔌 API / developer features**

Extended beyond the base `/api/v1/scan` endpoint:
- Async scanning/jobs with webhook notification on completion
- Batch scanning API
- API versioning
- OpenAPI/Swagger documentation
- Per-key permissions and per-key rate limits
- API usage statistics
- Idempotency keys
- Signed webhooks
- JSON and CSV output
- Machine-readable risk reasons

```
POST /api/v1/scan
GET  /api/v1/scan/{id}
POST /api/v1/bulk-scan
GET  /api/v1/history
POST /api/v1/webhooks
```

**🧩 Browser extension**
- Scan current page or link under cursor
- Scan QR code visible on screen
- Pre-navigation warning before loading a high-risk URL
- Toolbar badge showing risk level
- Context-menu scanning
- "Why?" explanation popup
- Optional real-time protection mode
- Report false positive / false negative

**🔥 Attack Chain view**

Rather than showing isolated results, PhishIQ visualizes the full attack path end-to-end, for example:

```
SMS
 ↓
bit.ly/xxxxx
 ↓
redirector.example
 ↓
newly-registered-domain.com
 ↓
fake Microsoft login
 ↓
credential submission
 ↓
attacker endpoint
```

...and highlights exactly where in the chain the attack becomes suspicious.

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
├── app.py                     # Flask routes and app setup
├── config.py                  # App configuration (reads from .env)
├── models.py                  # SQLAlchemy models
├── detectors/
│   ├── url_analyzer.py        # Core URL heuristics + scoring
│   ├── message_analyzer.py    # Message/SMS/email scam analysis
│   ├── typosquat_detector.py  # Levenshtein-based typosquatting checks
│   ├── whois_utils.py         # Domain age lookups
│   ├── ssl_utils.py           # Certificate inspection
│   ├── visual_similarity.py   # Screenshot + perceptual hash comparison
│   ├── brand_hashes.json      # Reference hashes for known brand login pages
│   ├── file_extractor.py      # .txt / .eml / .pdf text extraction
│   ├── report_generator.py    # PDF report generation
│   ├── email_utils.py         # SMTP sending
│   └── qr_utils.py            # QR code decoding
├── chrome_extension/          # Manifest V3 Chrome extension
├── templates/                 # Jinja2 templates
├── static/                    # CSS, uploaded files
└── requirements.txt
```

## Setup

**1. Clone and create a virtual environment**
```bash
git clone https://github.com/Rohit270727/PhishIQ.git
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
5. Make sure `python app.py` is running locally — the extension calls `http://127.0.0.1:5050/api/extension/scan`

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

- Rate limiting uses in-memory storage — resets on restart and isn't safe for multi-process deployments. Would need Redis-backed storage for real production use.
- Visual brand-impersonation detection currently covers 9 major brands (PayPal, Google, Microsoft, Amazon, Facebook, Apple, Netflix, Instagram, LinkedIn) — easily extendable.
- No automated test suite yet.

## Why I Built This

PhishIQ was built to go beyond simple keyword-matching phishing detectors by combining multiple independent signals — heuristic scoring, ML, WHOIS domain age, SSL certificate metadata, and visual brand-impersonation detection via perceptual hashing — into a single risk score. It also includes the kind of platform features (auth, API keys, admin analytics, CSRF/XSS hardening) that a real product would need, not just a detection script.
