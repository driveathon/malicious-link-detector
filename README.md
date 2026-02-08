# Malicious Link Detector

A simple Python library and CLI tool to detect potentially malicious URLs using heuristics like Punycode detection, typosquatting checks, and entropy analysis.

## Features

- **Punycode Detection**: Flags IDN homograph attacks (e.g., `xn--...`).
- **Typosquatting Check**: Detects URLs that visually resemble popular domains (e.g., `g00gle.com` vs `google.com`) using Levenshtein distance.
- **Entropy Analysis**: Measures domain name randomness to help identify Domain Generation Algorithms (DGA).
- **Structure Analysis**: Checks for suspicious elements like UserInfo (`@`) in the domain or excessive subdomains.

## Installation

Clone the repository and install dependencies (none required for core logic, uses standard library).

```bash
git clone <your-repo-url>
cd malicious_link_detector
```

## Usage

### CLI

Scan a single URL:
```bash
python -m detector.cli --url "https://g00gle.com"
```

Scan a file of URLs:
```bash
python -m detector.cli --file urls.txt
```

### Python API

```python
from detector import scan_link

report = scan_link("https://g00gle.com")
if report["is_malicious"]:
    print(f"Suspicious: {report['reasons']}")
```

## Running Tests

```bash
$env:PYTHONPATH += ";."
python tests/test_core.py
```
