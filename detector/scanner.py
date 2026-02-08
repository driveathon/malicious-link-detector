import asyncio
import os
import json
from urllib.parse import urlparse
from .core import analyze_url_async, analyze_url_heuristics
from .database import ScanCache
from .whois_check import analyze_domain_age
from .integrations.threat_intel import ThreatIntel
from .ssl_check import analyze_ssl
from .visual import capture_screenshot, analyze_visual_impersonation

class Scanner:
    def __init__(self, popular_domains, cache=None, google_api_key=None, vt_api_key=None, screenshots_dir="screenshots"):
        self.popular_domains = popular_domains
        self.cache = cache or ScanCache()
        self.intel = ThreatIntel(google_api_key=google_api_key, vt_api_key=vt_api_key)
        self.screenshots_dir = screenshots_dir
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)

    async def scan_one(self, url, skip_cache=False, trace_redirects=True, check_whois=True, check_intel=True, check_ssl=True, check_visual=True):
        """Scan a single URL, using cache if available."""
        if not skip_cache:
            cached = self.cache.get(url)
            if cached:
                return cached, True

        if trace_redirects:
            report = await analyze_url_async(url, self.popular_domains)
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
            whois_findings = analyze_domain_age(domain)
            report["whois"] = whois_findings
            if whois_findings["is_new_domain"]:
                report["is_malicious"] = True
                report["reasons"].extend(whois_findings["reasons"])

        if check_intel:
            intel_results = await self.intel.get_all_intel(url)
            report["external_intel"] = intel_results
            for result in intel_results:
                if result.get("is_flagged"):
                    report["is_malicious"] = True
                    report["reasons"].append(f"Flagged by {result['provider']}")

        # Phase 3: SSL & Visual
        if check_ssl:
            ssl_findings = analyze_ssl(report["final_url"])
            report["ssl"] = ssl_findings
            if ssl_findings["is_expired"] or not ssl_findings["has_https"]:
                report["is_malicious"] = True
                report["reasons"].extend(ssl_findings["reasons"])

        if check_visual:
            screenshot_name = f"{domain.replace('.', '_')}.png"
            screenshot_path = os.path.join(self.screenshots_dir, screenshot_name)
            success = await capture_screenshot(report["final_url"], screenshot_path)
            if success:
                report["screenshot_path"] = screenshot_path
                visual_findings = await analyze_visual_impersonation(report["final_url"], screenshot_path)
                report["visual_analysis"] = visual_findings
                if visual_findings.get("impersonation_risk") == "High":
                    report["is_malicious"] = True
                    report["reasons"].append("Visual impersonation detected")

        self.cache.set(url, report)
        return report, False

    async def scan_batch(self, urls, **kwargs):
        """Scan multiple URLs concurrently."""
        tasks = [self.scan_one(url, **kwargs) for url in urls]
        results = await asyncio.gather(*tasks)
        return results
