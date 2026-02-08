import requests as sync_requests
import asyncio
import os
import json
import logging

class ThreatIntel:
    """Consolidated client for external threat intelligence APIs."""
    
    def __init__(self, google_api_key=None, vt_api_key=None):
        self.google_api_key = google_api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        self.vt_api_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    def check_google_safe_browsing_sync(self, url):
        """Sync version of GSB check."""
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
            resp = sync_requests.post(endpoint, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "matches" in data:
                    return {"provider": "Google", "is_flagged": True, "details": data["matches"]}
                return {"provider": "Google", "is_flagged": False}
        except Exception as e:
            logging.error(f"Google Safe Browsing check failed: {e}")
            
        return None

    async def get_all_intel(self, url):
        """Aggregate results from all enabled providers (Windows-safe)."""
        loop = asyncio.get_event_loop()
        
        # Aggregate synchronously in thread for now to avoid ALL loop issues
        results = await loop.run_in_executor(None, self._get_all_intel_sync, url)
        return results

    def _get_all_intel_sync(self, url):
        """Synchronous aggregator for thread isolation."""
        results = []
        
        # PhishTank
        results.append({"provider": "PhishTank", "is_flagged": False, "details": "Not implemented"})
        
        # Google
        if self.google_api_key:
            results.append(self.check_google_safe_browsing_sync(url))
            
        # VirusTotal
        if self.vt_api_key:
            results.append({"provider": "VirusTotal", "is_flagged": False, "details": "Not implemented"})
            
        return [r for r in results if r is not None]
