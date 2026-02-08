import asyncio
import os
import json
from urllib.parse import urlparse
from .core import scan_link_sync, analyze_url_heuristics
from .database import ScanCache
from .whois_check import analyze_domain_age
from .integrations.threat_intel import ThreatIntel
from .ssl_check import analyze_ssl
from .visual import capture_screenshot, analyze_visual_impersonation
from .reputation import analyze_domain_reputation

class Scanner:
    _browser = None
    _playwright = None

    def __init__(self, popular_domains, cache=None, google_api_key=None, vt_api_key=None, screenshots_dir="screenshots"):
        self.popular_domains = popular_domains
        self.cache = cache or ScanCache()
        self.intel = ThreatIntel(google_api_key=google_api_key, vt_api_key=vt_api_key)
        self.screenshots_dir = screenshots_dir
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)

    async def _get_browser(self):
        """Get or create singleton browser instance."""
        from playwright.async_api import async_playwright
        if not Scanner._playwright:
            Scanner._playwright = await async_playwright().start()
        if not Scanner._browser:
            Scanner._browser = await Scanner._playwright.chromium.launch()
        return Scanner._browser

    async def close(self):
        """Close browser and playwright instances."""
        if Scanner._browser:
            await Scanner._browser.close()
            Scanner._browser = None
        if Scanner._playwright:
            await Scanner._playwright.stop()
            Scanner._playwright = None

    async def scan_one(self, url, skip_cache=False, trace_redirects=True, check_whois=True, check_intel=True, check_ssl=True, check_visual=True):
        """Scan a single URL, using cache if available."""
        import sys
        # Note: checks are now handled via a mix of sync/async to be safe on all platforms

        # Normalize URL Early - Ensure scheme exists
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        if not skip_cache:
            cached = self.cache.get(url)
            if cached:
                return cached, True

        if trace_redirects:
            try:
                # Use sync logic in executor for redirects
                loop = asyncio.get_event_loop()
                report = await loop.run_in_executor(
                    None, 
                    scan_link_sync, 
                    url, 
                    self.popular_domains,
                    True, # trace
                    False, # whois (done later)
                    False, # intel (done later)
                    False # ssl
                )
                
                # Deep Redirect Unmasking Integration
                if len(report.get("redirect_chain", [])) > 1:
                     from .intelligence import analyze_redirect_jurisdictions
                     jurisdiction_stats = await analyze_redirect_jurisdictions(report["redirect_chain"])
                     report["redirect_analysis"] = jurisdiction_stats
                     if jurisdiction_stats["jump_risk"] == "High":
                          report["reasons"].append(f"Suspicious jurisdictional jumping ({jurisdiction_stats['jurisdiction_count']} countries)")
            except Exception as e:
                import logging
                logging.error(f"Redirect tracing failed: {e}")
                report = {
                    "url": url, "final_url": url, "domain": urlparse(url).netloc or urlparse(url).path.split('/')[0],
                    "is_malicious": False, "reasons": [], "heuristics": {}, "info": [f"Redirect tracing error: {e}"]
                }
        else:
            heuristics = analyze_url_heuristics(url, self.popular_domains)
            report = {
                "url": url,
                "final_url": url,
                "domain": urlparse(url).netloc or urlparse(url).path.split('/')[0],
                "is_malicious": len(heuristics["reasons"]) > 0,
                "reasons": heuristics["reasons"],
                "heuristics": heuristics,
                "info": []
            }
        
        domain = report["domain"]
        
        # Phase 2: WHOIS & Intel
        if check_whois:
            try:
                # WHOIS is blocking, run in executor
                loop = asyncio.get_event_loop()
                whois_findings = await loop.run_in_executor(None, analyze_domain_age, domain)
                report["whois"] = whois_findings
                if whois_findings["is_new_domain"]:
                    report["is_malicious"] = True
                    report["reasons"].extend(whois_findings["reasons"])
            except Exception as e:
                report["whois_error"] = str(e)

        if check_intel:
            try:
                intel_results = await self.intel.get_all_intel(url)
                report["external_intel"] = intel_results
                for result in intel_results:
                    if result.get("is_flagged"):
                        report["is_malicious"] = True
                        report["reasons"].append(f"Flagged by {result['provider']}")
            except Exception as e:
                report["intel_error"] = str(e)

        # Phase 3: SSL & Visual
        if check_ssl:
            try:
                # Socket code is blocking, run in executor
                loop = asyncio.get_event_loop()
                ssl_findings = await loop.run_in_executor(None, analyze_ssl, report["final_url"])
                report["ssl"] = ssl_findings
                if ssl_findings["is_expired"] or not ssl_findings["has_https"]:
                    report["is_malicious"] = True
                    report["reasons"].extend(ssl_findings["reasons"])
            except Exception as e:
                report["ssl_error"] = str(e)

        # Phase 4: Reputation (Institutional Grade)
        try:
            # Need geo data for reputation ISP check
            if "geo" not in report:
                from .integrations.geo_intel import get_geo_info
                report["geo"] = await loop.run_in_executor(None, get_geo_info, report["domain"])
                
            reputation = analyze_domain_reputation(report["domain"], geo_info=report.get("geo"))
            report["reputation"] = reputation
            if reputation["is_suspicious"]:
                report["is_malicious"] = True
                report["reasons"].extend(reputation["findings"])
        except Exception as re_err:
            logging.error(f"Reputation analysis failed: {re_err}")
            report["reputation_error"] = str(re_err)

        if check_visual:
            screenshot_name = f"{domain.replace('.', '_')}.png"
            screenshot_path = os.path.join(self.screenshots_dir, screenshot_name)
            try:
                # Get the shared browser instance to avoid loop policy issues
                browser = await self._get_browser()
                success = await capture_screenshot(report["final_url"], screenshot_path, shared_browser=browser)
                if success:
                    report["screenshot_path"] = screenshot_path
                    # Legacy Heuristic Analysis
                    report["visual_analysis"] = await analyze_visual_impersonation(report["final_url"], screenshot_path)
                    
                    # New Vision AI Analysis
                    from .intelligence import check_phishing_visual_ai
                    vision_findings = await check_phishing_visual_ai(report["final_url"], screenshot_path)
                    report["vision_analysis"] = vision_findings
                    
                    if vision_findings.get("impersonation_risk") == "High":
                        report["is_malicious"] = True
                        report["reasons"].extend(vision_findings["findings"])
            except Exception as ve:
                logging.error(f"Visual analysis failed: {ve}")
                report["visual_error"] = str(ve)

        self.cache.set(url, report)
        return report, False

    async def scan_batch(self, urls, **kwargs):
        """Scan multiple URLs."""
        import sys
        if sys.platform == 'win32':
            # Sequential on Windows to avoid event loop policy issues with concurrent subprocesses
            results = []
            for url in urls:
                results.append(await self.scan_one(url, **kwargs))
            return results
        else:
            # Parallel on other OSs
            tasks = [self.scan_one(url, **kwargs) for url in urls]
            results = await asyncio.gather(*tasks)
            return results
