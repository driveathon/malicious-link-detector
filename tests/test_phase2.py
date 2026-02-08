import unittest
from unittest.mock import patch, MagicMock
from detector.whois_check import analyze_domain_age
from detector.integrations.threat_intel import ThreatIntel
import asyncio

class TestPhase2(unittest.IsolatedAsyncioTestCase):
    
    @patch('whois.whois')
    def test_domain_age_new(self, mock_whois):
        from datetime import datetime, timedelta
        # Mock a very new domain
        mock_info = MagicMock()
        mock_info.creation_date = datetime.now() - timedelta(days=10)
        mock_whois.return_value = mock_info
        
        findings = analyze_domain_age("new-malicious-site.com")
        self.assertTrue(findings["is_new_domain"])
        self.assertEqual(findings["age_days"], 10)
        self.assertIn("Domain is very new", findings["reasons"][0])

    @patch('whois.whois')
    def test_domain_age_old(self, mock_whois):
        from datetime import datetime, timedelta
        # Mock an old domain
        mock_info = MagicMock()
        mock_info.creation_date = datetime.now() - timedelta(days=1000)
        mock_whois.return_value = mock_info
        
        findings = analyze_domain_age("google.com")
        self.assertFalse(findings["is_new_domain"])
        self.assertEqual(findings["age_days"], 1000)

    async def test_threat_intel_google_mock(self):
        # We'll mock the ClientSession to avoid real requests
        intel = ThreatIntel(google_api_key="fake_key")
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_resp = MagicMock()
            mock_resp.status = 200
            async def mock_json():
                return {"matches": [{"threatType": "MALWARE"}]}
            mock_resp.json = mock_json
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            result = await intel.check_google_safe_browsing("http://malware.com")
            self.assertTrue(result["is_flagged"])
            self.assertEqual(result["provider"], "Google")

if __name__ == "__main__":
    unittest.main()
