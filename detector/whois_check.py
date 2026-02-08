import whois
from datetime import datetime, timezone
import logging

def get_domain_age_days(domain):
    """Retrieve the age of a domain in days using WHOIS data."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # creation_date can be a single datetime object or a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Handle timezone awareness
            now = datetime.now()
            if creation_date.tzinfo is not None:
                now = datetime.now(creation_date.tzinfo)
                
            age = now - creation_date
            return age.days
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        
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
