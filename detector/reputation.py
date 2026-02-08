import logging
import re
from .whois_check import analyze_domain_age

# Institutional Grade High-Risk TLDs
HIGH_RISK_TLDS = {
    "top", "xyz", "zip", "mov", "win", "bid", "pw", "monster", "icu", "click",
    "country", "gdn", "science", "gq", "tk", "ml", "ga", "cf"
}

# Suspicious ISP Keywords (e.g. mass hosting often used for phishing)
SUSPICIOUS_ISP_KEYWORDS = [
    "digitalocean", "ovh", "hetzner", "linode", "vultr", "m247", "choopa"
]

def analyze_domain_reputation(domain, geo_info=None):
    """
    Score the reputation of a domain based on multiple vectors.
    Returns findings and a calculated risk score (0-100).
    """
    findings = []
    risk_score = 0
    
    # 1. TLD Check
    tld = domain.split('.')[-1].lower()
    if tld in HIGH_RISK_TLDS:
        risk_score += 20
        findings.append(f"High-risk TLD detected (.{tld})")
        
    # 2. Domain Age Check
    age_findings = analyze_domain_age(domain)
    if age_findings["is_new_domain"]:
        risk_score += 40
        findings.extend(age_findings["reasons"])
        
    # 3. ISP Reputation Check
    if geo_info and geo_info.get("isp"):
        isp = geo_info["isp"].lower()
        for keyword in SUSPICIOUS_ISP_KEYWORDS:
            if keyword in isp:
                risk_score += 15
                findings.append(f"Hosted on consumer/mass-hosting infrastructure ({geo_info['isp']})")
                break
                
    # 4. Domain Composition (e.g. too many dashes or numbers)
    if len(re.findall(r'\d', domain)) > 5:
        risk_score += 10
        findings.append("Domain contains unusually high digit count")
        
    if domain.count('-') > 2:
        risk_score += 10
        findings.append("Domain contains multiple hyphens (phishing pattern)")

    return {
        "reputation_score": max(0, 100 - risk_score), # 100 is perfect, 0 is bad
        "risk_score": risk_score,
        "findings": findings,
        "is_suspicious": risk_score >= 50
    }
