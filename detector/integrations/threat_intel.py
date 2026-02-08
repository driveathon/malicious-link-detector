import aiohttp
import asyncio
import os
import json
import logging

class ThreatIntel:
    """Consolidated client for external threat intelligence APIs."""
    
    def __init__(self, google_api_key=None, vt_api_key=None):
        self.google_api_key = google_api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        self.vt_api_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    async def check_phishtank(self, url):
        """Check URL against PhishTank (Open API)."""
        # Note: PhishTank often requires an API key for higher limits, 
        # but we'll implement a basic check or placeholder.
        # For simplicity, this is a skeleton.
        return {"provider": "PhishTank", "is_flagged": False, "details": "Not implemented"}

    async def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API."""
        if not self.google_api_key:
            return None
            
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
        payload = {
            "client": {"clientId": "malicious-link-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HAZARDOUS"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "matches" in data:
                            return {"provider": "Google", "is_flagged": True, "details": data["matches"]}
                        return {"provider": "Google", "is_flagged": False}
        except Exception as e:
            logging.error(f"Google Safe Browsing check failed: {e}")
            
        return None

    async def check_virustotal(self, url):
        """Check URL against VirusTotal API."""
        if not self.vt_api_key:
            return None
            
        # VT requires a base64 encoded URL or a scan ID
        # For simplicity, this is a skeleton.
        return {"provider": "VirusTotal", "is_flagged": False, "details": "Not implemented"}

    async def get_all_intel(self, url):
        """Aggregate results from all enabled providers."""
        tasks = []
        tasks.append(self.check_phishtank(url))
        
        if self.google_api_key:
            tasks.append(self.check_google_safe_browsing(url))
        if self.vt_api_key:
            tasks.append(self.check_virustotal(url))
            
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
