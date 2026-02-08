# Malicious Link Detector 🛡️

Advanced heuristic, external, and visual analysis for detecting malicious URLs and phishing attempts.

[![Tests](https://github.com/driveathon/malicious-link-detector/actions/workflows/test.yml/badge.svg)](https://github.com/driveathon/malicious-link-detector/actions)

## Key Features

### 🔍 Multiple Layers of Defense
- **Core Heuristics**: Detects Punycode (IDN homographs), high-entropy randomized domains (DGA), and typosquatting of popular brands.
- **WHOIS Intelligence**: Automatically flags newly registered domains (high indicator of phishing).
- **SSL/TLS Validation**: Checks for expired certificates and non-HTTPS insecure connections.
- **Third-Party Intel**: Integrated support for Google Safe Browsing and PhishTank.
- **Visual AI (Playwright)**: Captures screenshots of pages to detect visual impersonation of login portals.

### ⚡ High Performance
- **Asynchronous Processing**: Concurrent URL scanning using `asyncio` and `aiohttp`.
- **Intelligent Caching**: SQLite-backed results cache for instantaneous repeat lookups.
- **Redirect Tracing**: Follows link shorteners (bit.ly, t.co) to reveal the final destination before analysis.

### 💻 User Interfaces
- **Professional CLI**: Powerful command-line tool for single scans or batch file processing.
- **REST API (FastAPI)**: Robust backend for automated security workflows.
- **Visual Dashboard**: Modern React + Tailwind UI with glassmorphism, dark mode, and visual evidence cards.

---

## Quick Start

### Installation
Clone the repository and install the package in editable mode:
```bash
# Clone the repository
git clone https://github.com/driveathon/malicious-link-detector.git
cd malicious_link_detector

# Install package and dependencies
pip install -e .

# Install Playwright browser binaries
playwright install chromium
```

### CLI Usage
```bash
# Scan a single URL
malicious-detector --url "https://g00gle.com"

# Batch scan URLs from a file
malicious-detector --file links.txt

# Options
# --no-redirects    Skip redirect tracing
# --no-whois        Skip domain age check
# --no-visual       Skip visual screenshot analysis
```

---

## Interface Setup

### Web Dashboard
The dashboard requires both the backend and frontend to be running:

1. **Start Backend**:
   ```bash
   uvicorn detector.api:app --reload
   ```

2. **Start Dashboard**:
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```

---

## Development

### Automated Tests
Run the complete test suite:
```bash
$env:PYTHONPATH += ";."; python tests/test_core.py
$env:PYTHONPATH += ";."; python tests/test_phase2.py
$env:PYTHONPATH += ";."; python tests/test_phase3.py
```

### License
MIT License. See `LICENSE` for details.
