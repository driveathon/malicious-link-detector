import unittest
from unittest.mock import patch, MagicMock
from detector.ssl_check import analyze_ssl
from detector.visual import capture_screenshot
import asyncio

class TestPhase3(unittest.IsolatedAsyncioTestCase):
    
    @patch('detector.ssl_check.get_ssl_info')
    def test_ssl_valid(self, mock_ssl_info):
        # Mock a valid certificate
        mock_ssl_info.return_value = {
            'notAfter': 'Feb 08 15:34:11 2027 GMT',
            'issuer': ((('organizationName', 'Google Trust Services LLC'),),)
        }
        
        findings = analyze_ssl("https://www.google.com")
        self.assertTrue(findings["has_https"])
        self.assertFalse(findings["is_expired"])
        self.assertEqual(findings["issuer"], "Google Trust Services LLC")

    @patch('detector.ssl_check.get_ssl_info')
    def test_ssl_expired(self, mock_ssl_info):
        # Mock an expired certificate
        mock_ssl_info.return_value = {
            'notAfter': 'Feb 08 15:34:11 2025 GMT',
            'issuer': ((('organizationName', 'Unknown Issuer'),),)
        }
        
        findings = analyze_ssl("https://expired-site.com")
        self.assertTrue(findings["is_expired"])
        self.assertIn("SSL certificate has expired", findings["reasons"][0])

    def test_ssl_insecure(self):
        findings = analyze_ssl("http://insecure-site.com")
        self.assertFalse(findings["has_https"])
        self.assertIn("Site does not use HTTPS", findings["reasons"][0])

    async def test_capture_screenshot_mock(self):
        # Mock playwright to avoid launching real browser in unit tests
        with patch('playwright.async_api.async_playwright') as mock_pw:
            mock_browser = MagicMock()
            mock_context = MagicMock()
            mock_page = MagicMock()
            
            mock_pw.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
            mock_browser.new_page.return_value = mock_page
            
            success = await capture_screenshot("https://example.com", "test.png")
            self.assertTrue(success)

if __name__ == "__main__":
    unittest.main()
