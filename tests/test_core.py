import unittest
from detector.core import is_punycode, calculate_entropy, levenshtein_distance, check_typosquatting, analyze_url

class TestDetector(unittest.TestCase):
    def test_is_punycode(self):
        self.assertTrue(is_punycode("xn--80ak6aa92e.com"))
        self.assertFalse(is_punycode("google.com"))

    def test_calculate_entropy(self):
        # Low entropy domain
        self.assertLess(calculate_entropy("google.com"), 3.5)
        # High entropy domain (random-ish)
        self.assertGreater(calculate_entropy("asdfghjkl12345.com"), 3.0)

    def test_levenshtein_distance(self):
        self.assertEqual(levenshtein_distance("google", "g00gle"), 2)
        self.assertEqual(levenshtein_distance("apple", "aple"), 1)
        self.assertEqual(levenshtein_distance("facebook", "facebook"), 0)

    def test_check_typosquatting(self):
        popular = ["google.com", "apple.com"]
        is_typo, target = check_typosquatting("g00gle.com", popular)
        self.assertTrue(is_typo)
        self.assertEqual(target, "google.com")
        
        is_typo, target = check_typosquatting("google.com", popular)
        self.assertFalse(is_typo)

    def test_analyze_url(self):
        popular = ["google.com"]
        # Suspicious Punycode
        report = analyze_url("http://xn--80ak6aa92e.com", popular)
        self.assertTrue(report["is_malicious"])
        self.assertIn("Punycode detected", report["reasons"][0])
        
        # Typosquatting
        report = analyze_url("https://g00gle.com", popular)
        self.assertTrue(report["is_malicious"])
        self.assertIn("Possible typosquatting", report["reasons"][0])

        # Safe URL
        report = analyze_url("https://google.com", popular)
        self.assertFalse(report["is_malicious"])

if __name__ == "__main__":
    unittest.main()
