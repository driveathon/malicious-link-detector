from .core import analyze_url_heuristics, scan_link_sync
from .scanner import Scanner
from .database import ScanCache
import json
import os
import asyncio

POPULAR_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'popular_domains.json')

def load_popular_domains():
    if os.path.exists(POPULAR_DOMAINS_PATH):
        with open(POPULAR_DOMAINS_PATH, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return data.get("popular_domains", [])
    return []

def scan_link(url, trace_redirects=True, check_whois=True, check_intel=True, check_ssl=True, check_visual=True, google_api_key=None, vt_api_key=None):
    """Sync wrapper for scanning a single link."""
    popular_domains = load_popular_domains()
    scanner = Scanner(popular_domains, google_api_key=google_api_key, vt_api_key=vt_api_key)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result, _ = loop.run_until_complete(
            scanner.scan_one(url, trace_redirects=trace_redirects, check_whois=check_whois, check_intel=check_intel, check_ssl=check_ssl, check_visual=check_visual)
        )
        return result
    finally:
        loop.close()

async def scan_links_async(urls, **kwargs):
    """Async entry point for scanning multiple links."""
    popular_domains = load_popular_domains()
    # Extract scanner init args from kwargs if present
    init_args = {
        "google_api_key": kwargs.pop("google_api_key", None),
        "vt_api_key": kwargs.pop("vt_api_key", None)
    }
    scanner = Scanner(popular_domains, **init_args)
    results = await scanner.scan_batch(urls, **kwargs)
    return results
