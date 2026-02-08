import requests as sync_requests
from datetime import datetime, timezone
import logging

def get_domain_age_days(domain):
    """Retrieve the age of a domain in days using a subprocess-free method."""
    # We'll use a public RDAP API which is HTTPS based and doesn't need subprocesses
    # This is much safer for Windows asyncio loops
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = sync_requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    date_str = event.get("eventDate")
                    if date_str:
                        # RDAP dates are usually ISO8601
                        # Remove 'Z' for parsing if present
                        if date_str.endswith('Z'):
                            date_str = date_str[:-1]
                        creation_date = datetime.fromisoformat(date_str)
                        age = datetime.utcnow() - creation_date
                        return age.days
    except Exception as e:
        logging.error(f"RDAP lookup failed for {domain}: {e}")
        
    return None

def analyze_domain_age(domain, threshold_days=30):
    """Analyze the domain age and return risk findings."""
    age_days = get_domain_age_days(domain)
    
    findings = {
        "age_days": age_days,
        "is_new_domain": False,
        "reasons": []
    }
    
    if age_days is not None:
        if age_days < threshold_days:
            findings["is_new_domain"] = True
            findings["reasons"].append(f"Domain is very new ({age_days} days old)")
    else:
        # If WHOIS fails, it's not necessarily malicious but might be suspicious for some TLDs
        # We won't flag it here to avoid false positives, but could log it.
        pass
        
    return findings
