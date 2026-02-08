from .core import analyze_url
import json
import os

POPULAR_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'popular_domains.json')

def load_popular_domains():
    if os.path.exists(POPULAR_DOMAINS_PATH):
        with open(POPULAR_DOMAINS_PATH, 'r') as f:
            return json.load(f).get("popular_domains", [])
    return []

def scan_link(url):
    """Entry point for the library to scan a single URL."""
    popular_domains = load_popular_domains()
    return analyze_url(url, popular_domains)
