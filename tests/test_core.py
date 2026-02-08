import unittest
import asyncio
import os
from detector.core import is_punycode, calculate_entropy, levenshtein_distance, check_typosquatting, analyze_url_heuristics, analyze_url_async
from detector.database import ScanCache
from detector.scanner import Scanner

class TestDetector(unittest.IsolatedAsyncioTestCase):
    def test_is_punycode(self):
        self.assertTrue(is_punycode("xn--80ak6aa92e.com"))
        self.assertFalse(is_punycode("google.com"))

    def test_calculate_entropy(self):
        self.assertLess(calculate_entropy("google.com"), 3.5)
        self.assertGreater(calculate_entropy("asdfghjkl12345.com"), 3.0)

    def test_levenshtein_distance(self):
        self.assertEqual(levenshtein_distance("google", "g00gle"), 2)

    def test_check_typosquatting(self):
        popular = ["google.com"]
        is_typo, target = check_typosquatting("g00gle.com", popular)
        self.assertTrue(is_typo)
        self.assertEqual(target, "google.com")

    def test_analyze_heuristics(self):
        popular = ["google.com"]
        findings = analyze_url_heuristics("https://g00gle.com", popular)
        self.assertIn("Possible typosquatting", findings["reasons"][0])

    def test_cache(self):
        db_path = "test_cache.db"
        if os.path.exists(db_path):
            os.remove(db_path)
        
        cache = ScanCache(db_path=db_path)
        url = "https://safe-link.com"
        report = {"url": url, "is_malicious": False, "reasons": []}
        
        cache.set(url, report)
        cached_report = cache.get(url)
        
        self.assertEqual(cached_report, report)
        
        if os.path.exists(db_path):
            os.remove(db_path)

    async def test_async_scanner(self):
        popular = ["google.com"]
        db_path = "test_scanner_async.db"
        if os.path.exists(db_path):
            os.remove(db_path)
            
        scanner = Scanner(popular, cache=ScanCache(db_path))
        urls = ["https://google.com", "https://g00gle.com"]
        results = await scanner.scan_batch(urls)
        
        self.assertEqual(len(results), 2)
        
        # google.com should be safe (reasons list should be empty)
        report1 = results[0][0]
        self.assertFalse(report1["is_malicious"], f"google.com flagged as malicious! Reasons: {report1.get('reasons')}")
        
        # g00gle.com should be suspicious
        report2 = results[1][0]
        self.assertTrue(report2["is_malicious"], "g00gle.com NOT flagged as malicious")
        
        if os.path.exists(db_path):
            os.remove(db_path)

if __name__ == "__main__":
    unittest.main()
