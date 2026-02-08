# FinLink | Institutional Security Ecosystem 🛡️🏦

**FinLink** is a high-density, professional security platform designed to analyze, detect, and neutralize malicious links with financial-grade precision. Originally an iOS-inspired tool, it has been evolved into an institutional "Obsidian" dashboard with deep intelligence layers.

## 🏦 Institutional Features

### 🔍 Intelligence Layer
- **Deep Heuristic Analysis**: Detects typosquatting, Punycode (IDN) homograph attacks, and suspicious URL structures.
- **Geolocation & ASN Tracking**: Resolves origin server IP to physical location (City/Country) and identifies the host ISP.
- **Entropy Randomness Score**: High-precision calculation of domain chaos to flag DGA and phishing handles.
- **Threat Intelligence**: Plug-and-play support for Google Safe Browsing and VirusTotal (API keys required).
- **24h Security TTL**: Enforced cache validity to ensure security reports remain fresh and relevant.

### 🏛️ Platform Integrity
- **Corporate Audit Trail**: Every scan is logged into an encrypted-style "Vault" with granular timestamps and status indicators.
- **Institutional Rate Limiting**: Intelligent backend protection using standard `slowapi` policies to prevent platform exhaustion.
- **Windows Optimized**: Thread-isolated scanning paths to ensure 100% stability on modern Windows infrastructure.
- **Optical Evidence Log**: Automated website capturing for visual verification of link content.

### ✨ Visual Fidelity
- **Obsidian Design System**: A premium, centered dashboard focused on "Clean and Tidy" presentation.
- **High-Density Widgets**: Real-time stats tracking Total Assets, Blocked Incursions, and System Latency.
- **Liquid Glass UI**: Modern translucent components with `backdrop-blur` and Inter typography.

## 🚀 Rapid Deployment

### Backend
1. **Bootstrap Environment**:
   ```bash
   pip install fastapi uvicorn requests slowapi
   ```
2. **Launch Node**:
   ```bash
   python -m uvicorn detector.api:app --reload
   ```

### Frontend
1. **Initialize Console**:
   ```bash
   cd dashboard
   npm install
   ```
2. **Access Dashboard**:
   ```bash
   npm run dev
   ```
   Visit `http://localhost:5173`

## 📊 Technical Schema
FinLink operates using a **Sync-Synchronous Fallback Architecture** for maximum cross-platform compatibility. It integrates standard network protocols (WHOIS, SSL, DNS, RDAP) with advanced mathematical modeling (Shannon Entropy) to provide a holistic security profile for any incoming URL.

---
*Verified by Antigravity AI • Corporate Security Node 20394-B*
