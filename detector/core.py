import re
import math
import json
import os
import asyncio
import requests as sync_requests
from urllib.parse import urlparse

def is_punycode(domain):
    """Check if the domain uses Punycode (IDN)."""
    return domain.startswith('xn--')

def calculate_entropy(text):
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def levenshtein_distance(s1, s2):
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def check_typosquatting(domain, popular_domains, threshold=2):
    """Check if the domain is a typosquatted version of a popular domain."""
    # Strip common subdomains like 'www.'
    if domain.startswith('www.'):
        domain = domain[4:]
    
    domain_part = domain.split('.')[0]
    for target in popular_domains:
        target_part = target.split('.')[0]
        if domain_part != target_part:
            distance = levenshtein_distance(domain_part, target_part)
            if distance <= threshold:
                return True, target
    return False, None

async def follow_redirects(url, max_redirects=5):
    """Trace the final URL after redirects (Windows-safe version)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _follow_redirects_sync, url, max_redirects)

def _follow_redirects_sync(url, max_redirects=5):
    """Sync version of redirect follower to avoid Windows asyncio subprocess issues."""
    redirects = [url]
    current_url = url
    try:
        session = sync_requests.Session()
        for _ in range(max_redirects):
            # We use HEAD to be lightweight
            resp = session.head(current_url, allow_redirects=False, timeout=5)
            if 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                current_url = resp.headers['Location']
                if not urlparse(current_url).scheme:
                    base = urlparse(redirects[-1])
                    current_url = f"{base.scheme}://{base.netloc}{current_url}"
                redirects.append(current_url)
            else:
                break
    except Exception as e:
        import logging
        logging.error(f"Redirect follow failed: {e}")
        
    return current_url, redirects

def analyze_url_heuristics(url, popular_domains):
    """Analyze basic heuristics for a single URL/domain."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    
    findings = {
        "is_punycode": is_punycode(domain),
        "entropy": calculate_entropy(domain),
        "typosquatting": None,
        "suspicious_structure": False,
        "reasons": []
    }

    if findings["is_punycode"]:
        findings["reasons"].append("Punycode detected (IDN homograph attack risk)")
    
    if findings["entropy"] > 4.0:
        findings["reasons"].append(f"High domain entropy ({findings['entropy']:.2f})")

    is_typo, target = check_typosquatting(domain, popular_domains)
    if is_typo:
        findings["typosquatting"] = target
        findings["reasons"].append(f"Possible typosquatting of '{target}'")

    if "@" in parsed.netloc:
        findings["suspicious_structure"] = True
        findings["reasons"].append("UserInfo (@) found in URL (credentials phishing risk)")
    
    if len(domain.split('.')) > 4:
        findings["suspicious_structure"] = True
        findings["reasons"].append("Too many subdomains")

    return findings

def scan_link_sync(url, popular_domains, trace_redirects=True, check_whois=True, check_intel=True, check_ssl=True, check_visual=True, screenshots_dir="screenshots", settings=None):
    """Synchronous version of link scanning for Windows workers."""
    import logging
    import os
    import time
    import hashlib
    import asyncio
    import requests as sync_requests
    from .whois_check import analyze_domain_age
    from .ssl_check import analyze_ssl
    from .visual import capture_screenshot_sync, analyze_visual_impersonation_sync
    from .intelligence import analyze_redirect_jurisdictions, check_phishing_visual_ai
    from .reputation import analyze_domain_reputation
    from urllib.parse import urlparse

    # Load Dynamic Institutional Thresholds
    S = settings or {}
    MIN_AGE = int(S.get("min_domain_age_days", 30))
    MAX_ENTROPY = float(S.get("max_entropy_threshold", 4.0))
    JUMP_LIMIT = int(S.get("jurisdiction_jump_limit", 3))
    VISION_ENABLED = S.get("enable_vision_ai", "1") == "1"

    # 1. Normalize & Canonicalize
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    # Industrial Canonicalization: strip fragments, standardize trailing slash
    parsed_canonical = urlparse(url)
    clean_path = parsed_canonical.path.rstrip('/') if parsed_canonical.path != '/' else '/'
    url = f"{parsed_canonical.scheme}://{parsed_canonical.netloc}{clean_path}"
    if parsed_canonical.query:
        url += f"?{parsed_canonical.query}"
    current_url = url
    redirect_chain = [url]
    if trace_redirects:
        try:
            session = sync_requests.Session()
            for _ in range(5):
                resp = session.head(current_url, allow_redirects=False, timeout=5)
                if 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                    current_url = resp.headers['Location']
                    if not urlparse(current_url).scheme:
                        base = urlparse(redirect_chain[-1])
                        current_url = f"{base.scheme}://{base.netloc}{current_url}"
                    redirect_chain.append(current_url)
                else: break
        except Exception: pass

    # Initialize report structure
    report = {
        "url": url, 
        "final_url": current_url, 
        "domain": urlparse(current_url).netloc,
        "redirect_chain": redirect_chain, 
        "is_malicious": False, # Will be updated based on findings
        "reasons": [], 
        "heuristics": {}, 
        "entropy": 0.0,
        "info": []
    }

    # 4. Geolocation
    from .integrations.geo_intel import get_geo_info
    geo_data = get_geo_info(report["domain"])
    report["geo"] = geo_data

    # 4.5. Domain Reputation v2
    reputation_findings = analyze_domain_reputation(report["domain"], geo_info=geo_data)
    report["reputation"] = reputation_findings
    if reputation_findings["is_suspicious"]:
        report["is_malicious"] = True
        report["reasons"].extend(reputation_findings["findings"])

    # 2. Heuristics Analysis (In-process)
    heuristics = analyze_url_heuristics(url, popular_domains)
    report["heuristics"] = heuristics
    report["entropy"] = heuristics["entropy"]
    # Applied Threshold
    if heuristics["entropy"] > MAX_ENTROPY:
        heuristics["reasons"].append(f"Entropy ({heuristics['entropy']:.2f}) exceeds node threshold ({MAX_ENTROPY})")
        report["is_malicious"] = True
        
    report["reasons"].extend(heuristics["reasons"])
            
    # 5. WHOIS
    if check_whois:
        whois_f = analyze_domain_age(report["domain"], threshold_days=MIN_AGE)
        report["whois"] = whois_f
        if whois_f["is_new_domain"]:
            report["is_malicious"] = True
            report["reasons"].extend(whois_f["reasons"])

    # 6. SSL
    if check_ssl:
        ssl_f = analyze_ssl(current_url)
        report["ssl"] = ssl_f
        if ssl_f["is_expired"] or not ssl_f["has_https"]:
            report["is_malicious"] = True
            report["reasons"].extend(ssl_f["reasons"])

    # 7. Deep Redirect Unmasking
    if trace_redirects and len(redirect_chain) > 1:
        # Run in loop executor or directly (it's internal sync geodata mostly)
        jurisdiction_stats = asyncio.run(analyze_redirect_jurisdictions(redirect_chain))
        report["redirect_analysis"] = jurisdiction_stats
        if jurisdiction_stats["jurisdiction_count"] > JUMP_LIMIT:
             report["is_malicious"] = True
             report["reasons"].append(f"Jurisdictional jump count ({jurisdiction_stats['jurisdiction_count']}) exceeds node limit ({JUMP_LIMIT})")
        elif jurisdiction_stats["jump_risk"] == "High":
             report["is_malicious"] = True
             report["reasons"].append("Suspicious jurisdictional pattern detected")

    # 8. Visual (Enhanced with Vision AI)
    if check_visual:
        if not os.path.exists(screenshots_dir):
            os.makedirs(screenshots_dir)
        screenshot_name = f"{report['domain'].replace('.', '_')}.png"
        screenshot_path = os.path.join(screenshots_dir, screenshot_name)
        if capture_screenshot_sync(current_url, screenshot_path):
            report["screenshot_path"] = screenshot_path
            # Heuristic visual check
            report["visual_analysis"] = analyze_visual_impersonation_sync(current_url, screenshot_path)
            
            # Neural Scan
            if VISION_ENABLED:
                vision_findings = asyncio.run(check_phishing_visual_ai(current_url, screenshot_path))
                report["vision_analysis"] = vision_findings
                if vision_findings.get("impersonation_risk") == "High":
                    report["is_malicious"] = True
                    report["reasons"].extend(vision_findings["findings"])

    return report
