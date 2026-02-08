import re
import math
import json
import os
import aiohttp
import asyncio
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
    """Trace the final URL after redirects."""
    redirects = [url]
    current_url = url
    try:
        async with aiohttp.ClientSession() as session:
            for _ in range(max_redirects):
                async with session.head(current_url, allow_redirects=False, timeout=5) as resp:
                    if 300 <= resp.status < 400 and 'Location' in resp.headers:
                        current_url = resp.headers['Location']
                        if not urlparse(current_url).scheme:
                            base = urlparse(redirects[-1])
                            current_url = f"{base.scheme}://{base.netloc}{current_url}"
                        redirects.append(current_url)
                    else:
                        break
    except Exception:
        pass # Ignore errors, return what we have
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

async def analyze_url_async(url, popular_domains):
    """Comprehensive async analysis including redirect tracing."""
    final_url, redirect_chain = await follow_redirects(url)
    
    # Analyze both initial and final URL
    initial_findings = analyze_url_heuristics(url, popular_domains)
    final_findings = analyze_url_heuristics(final_url, popular_domains)
    
    # Base malicious reasons
    malicious_reasons = list(set(initial_findings["reasons"] + final_findings["reasons"]))
    info_messages = []
    
    # If final URL is different, note the redirect
    if final_url != url:
        info_messages.append(f"Redirects to: {final_url}")
        if any(bad_word in final_url.lower() for bad_word in ["login", "signin", "verify", "account"]):
             # Check if it's NOT a popular domain (e.g. login.microsoft.com is fine)
             if not any(pop in final_url for pop in popular_domains):
                 malicious_reasons.append("Final URL contains suspicious keywords outside popular domains")

    return {
        "url": url,
        "final_url": final_url,
        "domain": urlparse(final_url).netloc or urlparse(final_url).path.split('/')[0],
        "redirect_chain": redirect_chain,
        "is_malicious": len(malicious_reasons) > 0,
        "reasons": malicious_reasons,
        "info": info_messages,
        "heuristics": final_findings 
    }
