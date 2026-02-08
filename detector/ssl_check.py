import ssl
import socket
from datetime import datetime
import logging
from urllib.parse import urlparse

def get_ssl_info(domain):
    """Retrieve SSL certificate information for a domain."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        logging.debug(f"SSL lookup failed for {domain}: {e}")
        return None

def analyze_ssl(url):
    """Analyze the SSL certificate of a URL and return risk findings."""
    parsed = urlparse(url)
    domain = parsed.netloc
    
    findings = {
        "has_https": parsed.scheme == "https",
        "is_expired": False,
        "expiry_date": None,
        "days_to_expiry": None,
        "issuer": None,
        "reasons": []
    }
    
    if not findings["has_https"]:
        findings["reasons"].append("Site does not use HTTPS (Insecure)")
        return findings

    cert = get_ssl_info(domain)
    if cert:
        # Extract expiry date
        not_after_str = cert.get('notAfter')
        if not_after_str:
            expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            findings["expiry_date"] = expiry_date.isoformat()
            
            delta = expiry_date - datetime.now()
            findings["days_to_expiry"] = delta.days
            
            if delta.days < 0:
                findings["is_expired"] = True
                findings["reasons"].append("SSL certificate has expired")
            elif delta.days < 14:
                findings["reasons"].append(f"SSL certificate expires soon ({delta.days} days)")

        # Extract issuer (simplified)
        issuer = dict(x[0] for x in cert.get('issuer', []))
        findings["issuer"] = issuer.get('organizationName', 'Unknown')
    else:
        findings["reasons"].append("Could not retrieve SSL certificate information")
        
    return findings
