# CyberShield AI

**"Think Before You Click."**

CyberShield AI is an educational, **defensive** cybersecurity web application that helps everyday users spot common phishing and scam indicators in links, messages, and screenshots (WhatsApp, Facebook, Instagram, SMS, email, etc.) before they put an account at risk.

> ⚠️ **Important:** CyberShield AI does **not** and cannot detect whether a WhatsApp/Facebook/Instagram account has already been hacked. It analyzes *submitted content* (a link, a message, or text extracted from a screenshot) for patterns commonly associated with phishing, scams, impersonation, and social engineering, and reports an **estimated risk score** — never a guarantee. It never asks for your passwords, OTPs, recovery codes, or authentication cookies.

---

## Table of Contents

1. [Features](#features)
2. [Technologies](#technologies)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
   - [Windows](#windows-setup)
   - [macOS / Linux](#macos--linux-setup)
5. [Configuring `.env`](#configuring-env)
6. [Running the Application](#running-the-application)
7. [Running Tests](#running-tests)
8. [API Documentation](#api-documentation)
9. [Security Notes](#security-notes)
10. [Privacy](#privacy)
11. [Limitations](#limitations)
12. [Future Improvements](#future-improvements)

---

## Features

- **Link Scanner** — analyzes a URL's structure (HTTPS, domain, TLD, length, shorteners, IP-literal hosts, suspicious keywords, basic brand-impersonation heuristics) without ever fetching or attacking the target site.
- **Message Scanner** — detects urgency language, fear/threat wording, prize-scam patterns, fake verification requests, credential/OTP requests, suspicious payment requests, impersonation, job/investment scam patterns, and more, in free text.
- **Screenshot Scanner** — extracts visible text from an uploaded screenshot via OCR (pytesseract + Pillow) and runs it through the same message-analysis engine. Degrades gracefully (with a clear message) if OCR isn't available on the host machine.
- **Transparent Risk Scoring** — a clean, centralized scoring engine (0–100) with named signals so the logic is easy to audit and extend.
- **Full authentication system** — secure registration/login/logout with bcrypt password hashing, signed session cookies, and protected routes.
- **Dashboard** — scan totals, risk-level breakdown, and recent scan history.
- **Security Tips page** — practical, actionable advice.
- **Privacy-conscious by design** — no credential collection, scan history stores only short safe summaries (not full raw messages/images), uploaded images are not persisted to disk unless explicitly enabled.
- **Robust error handling** — global exception handlers, input validation, file-type/size limits, SSRF-safe URL-handling utilities, and no leaked stack traces.

---

## Technologies

- **Backend:** FastAPI, Pydantic, SQLAlchemy, SQLite
- **Auth:** Passlib (bcrypt), itsdangerous (signed session tokens)
- **OCR (optional):** pytesseract + Pillow
- **Frontend:** Server-rendered Jinja2 templates, vanilla CSS + JS (no build step required)
- **Testing:** Pytest + FastAPI TestClient

---

## Project Structure

```
cybershield-ai/
│
├── app/
│   ├── main.py              # FastAPI app, startup, global exception handlers
│   ├── config.py            # Settings loaded from environment variables
│   ├── database.py          # SQLAlchemy engine/session/init
│   │
│   ├── models/               # SQLAlchemy models (users, scans)
│   ├── schemas/               # Pydantic request/response schemas
│   ├── routers/               # auth, scan, tips, pages (HTML views), deps
│   ├── services/               # scoring engine, url/message analyzers, OCR, recommendations
│   ├── utils/                   # password hashing/session tokens, SSRF guard
│   │
│   ├── templates/                # Jinja2 HTML templates
│   └── static/
│       ├── css/style.css
│       └── js/*.js
│
├── tests/                    # Pytest test suite (isolated test database)
├── uploads/                  # Only used if PERSIST_UPLOADED_IMAGES=true
│
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
└── run.py                    # `python run.py` convenience entrypoint
```

---

## Installation

### Prerequisites

- Python 3.10+ (tested on 3.12)
- (Optional, for the screenshot scanner) the **Tesseract OCR** engine installed on your system. The app works fully without it — the screenshot scanner will simply tell you OCR isn't available and suggest pasting the text manually instead.

### Windows Setup

Open the project folder in VS Code, then open a terminal (`` Ctrl+` ``):

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate it
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) install Tesseract OCR for the screenshot scanner
#    Download the installer from: https://github.com/UB-Mannheim/tesseract/wiki
#    and make sure it's added to your PATH.

# 5. Copy the example environment file
copy .env.example .env

# 6. Run the app
python run.py
```

Then open **http://127.0.0.1:8000** in your browser.

### macOS / Linux Setup

```bash
# 1. Create a virtual environment
python3 -m venv .venv

# 2. Activate it
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) install Tesseract OCR
#    macOS:  brew install tesseract
#    Ubuntu: sudo apt install tesseract-ocr

# 5. Copy the example environment file
cp .env.example .env

# 6. Run the app
python run.py
```

Then open **http://127.0.0.1:8000** in your browser.

You can also run it directly with uvicorn:

```bash
uvicorn app.main:app --reload
```

---

## Configuring `.env`

Copy `.env.example` to `.env` and adjust as needed. **Every value is optional** — the app runs with safe defaults even if `.env` is missing entirely.

| Variable | Purpose | Required? |
|---|---|---|
| `SECRET_KEY` | Signs session cookies. Auto-generated if blank (set explicitly in production so sessions survive restarts). | No |
| `DATABASE_URL` | SQLAlchemy database URL. Defaults to a local SQLite file. | No |
| `MAX_UPLOAD_SIZE_MB` | Max screenshot upload size. Default `5`. | No |
| `PERSIST_UPLOADED_IMAGES` | If `true`, uploaded screenshots are saved to `/uploads`. Default `false` (images are analyzed in-memory and discarded). | No |
| `OPENAI_API_KEY` | Reserved for a future optional AI-provider integration. The app works fully without it (local heuristic analysis only). | No |
| `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY` | Reserved for future optional threat-intel integrations. | No |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins. | No |

The database (tables `users`, `scans`) is created automatically on first run — no manual migration step needed.

---

## Running Tests

```bash
# with the virtual environment activated:
pytest tests/ -v
```

The test suite (24 tests) uses an isolated, temporary SQLite database — it never touches your real `cybershield.db` — and covers:

- Registration (success, duplicate email, weak password, mismatched passwords, empty fields)
- Login (success, wrong password, nonexistent user), logout
- Authorization (dashboard and scan endpoints reject unauthenticated requests)
- URL scanning (suspicious vs. safe URLs, empty input)
- Message scanning (phishing/prize-scam patterns, OTP requests, empty input)
- Image scanning (invalid file type, empty file, oversized file, valid image, graceful OCR-unavailable handling)
- Scan history retrieval and the security-tips endpoint

---

## API Documentation

Interactive API docs (Swagger UI) are available automatically at **http://127.0.0.1:8000/docs** once the app is running.

### Auth

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Create an account. Body: `full_name`, `email`, `password`, `confirm_password`. |
| POST | `/api/auth/login` | Log in. Body: `email`, `password`. |
| POST | `/api/auth/logout` | Log out (clears the session cookie). |

### Scanning

| Method | Path | Description |
|---|---|---|
| POST | `/api/scan/url` | Analyze a URL. Body: `{ "url": "..." }`. |
| POST | `/api/scan/message` | Analyze free text. Body: `{ "message": "..." }`. |
| POST | `/api/scan/image` | Analyze a screenshot. Multipart form field: `file` (JPG/JPEG/PNG/WebP, ≤5MB by default). |
| GET | `/api/scans` | List the current user's scan history. |
| GET | `/api/scans/{scan_id}` | Get one scan's summary. |
| GET | `/api/security-tips` | Get the list of security tips. |

All scan endpoints require an authenticated session (login first) and return a JSON object containing `risk_score`, `risk_level`, `findings`, `recommended_actions`, `explanation`, and `analysis_note`.

---

## Security Notes

- Passwords are hashed with **bcrypt** and never stored or logged in plain text.
- Session cookies are signed (`itsdangerous`) and marked `HttpOnly`.
- All inputs are validated with Pydantic; oversized/invalid uploads are rejected before processing.
- A dedicated **SSRF guard** (`app/utils/ssrf_guard.py`) blocks localhost, private/internal IP ranges, and cloud metadata endpoints — ready for use if/when server-side URL fetching (e.g. a future reputation-check integration) is added. The current URL analyzer performs **purely local, structural analysis** and never fetches the submitted URL.
- Global exception handlers ensure users never see raw Python stack traces; detailed errors are only logged server-side.
- CORS is restricted to explicitly configured origins.

---

## Privacy

- **Never submit passwords, OTPs, authentication cookies, or recovery codes** — CyberShield AI never needs them, and no legitimate service will ever ask you to share them.
- Uploaded screenshots may contain personal information; please remove sensitive details before uploading where possible.
- Scan history stores only a short, safe summary of each scan (truncated to ~280 characters) — not full raw messages or images.
- Uploaded images are analyzed in-memory and **not saved to disk** unless you explicitly set `PERSIST_UPLOADED_IMAGES=true`.
- Risk scores are AI/heuristic estimates for educational and defensive purposes — not a guarantee of safety, and not proof that any account has or hasn't been compromised.

---

## Limitations

- Local heuristic analysis only, by default — no external threat-intelligence API is called unless you configure one yourself (none are required for the app to work).
- OCR accuracy depends on screenshot quality and the Tesseract installation on the host machine.
- The keyword/pattern lists (urgency, prize scams, impersonation, etc.) are illustrative and will not catch every phishing technique — they're meant to teach recognizable patterns, not serve as a complete detection system.
- English-language patterns are the current focus; multilingual support (including Roman Urdu) is a planned future improvement.

---

## Future Improvements

The codebase is structured so these can be added without touching the core scanning flow:

- VirusTotal / Google Safe Browsing / URLhaus / AbuseIPDB reputation lookups (via the SSRF-guarded fetch utility)
- A more advanced NLP/AI model behind the existing `OPENAI_API_KEY` hook
- Multilingual analysis, including Roman Urdu scam detection
- Browser extension and mobile app front-ends against the existing REST API
- Dedicated email and WhatsApp/Facebook screenshot analysis modes
