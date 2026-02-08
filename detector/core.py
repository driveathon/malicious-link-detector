import re
import math
import json
import os
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
    # Simplified check: only compare the main part of the domain (excluding TLD)
    domain_part = domain.split('.')[0]
    for target in popular_domains:
        target_part = target.split('.')[0]
        if domain_part != target_part:
            distance = levenshtein_distance(domain_part, target_part)
            if distance <= threshold:
                return True, target
    return False, None

def analyze_url(url, popular_domains):
    """Perform a comprehensive analysis of a URL."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0] # Basic fallback for URLs without protocol
    
    report = {
        "url": url,
        "domain": domain,
        "is_punycode": is_punycode(domain),
        "entropy": calculate_entropy(domain),
        "suspicious_structure": False,
        "typosquatting": None,
        "is_malicious": False,
        "reasons": []
    }

    # Punycode check
    if report["is_punycode"]:
        report["reasons"].append("Punycode detected (IDN homograph attack risk)")
        report["is_malicious"] = True

    # Entropy check (DGA detection tip)
    if report["entropy"] > 4.0: # Threshold can be tuned
        report["reasons"].append(f"High domain entropy ({report['entropy']:.2f})")
        report["is_malicious"] = True

    # Typosquatting check
    is_typo, target = check_typosquatting(domain, popular_domains)
    if is_typo:
        report["typosquatting"] = target
        report["reasons"].append(f"Possible typosquatting of '{target}'")
        report["is_malicious"] = True

    # Structure check
    if "@" in parsed.netloc:
        report["suspicious_structure"] = True
        report["reasons"].append("UserInfo (@) found in URL (credentials phishing risk)")
        report["is_malicious"] = True
    
    if len(domain.split('.')) > 4:
        report["suspicious_structure"] = True
        report["reasons"].append("Too many subdomains")
        report["is_malicious"] = True

    return report
