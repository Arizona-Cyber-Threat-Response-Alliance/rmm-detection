import unittest
from source import normalize_domain, is_ipv4, is_domain_ioc_safe


class TestSource(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("  google.com  "), "google.com")
        self.assertEqual(normalize_domain("HTTP://GOOGLE.COM/foo"), "google.com")
        self.assertEqual(normalize_domain("*.google.com"), "google.com")
        self.assertEqual(normalize_domain("test.com."), "test.com")
        self.assertEqual(normalize_domain(""), "")

    def test_is_ipv4(self):
        self.assertTrue(is_ipv4("1.2.3.4"))
        self.assertTrue(is_ipv4("0.0.0.0"))
        self.assertTrue(is_ipv4("255.255.255.255"))
        self.assertFalse(is_ipv4("256.0.0.1"))
        self.assertFalse(is_ipv4("1.2.3"))
        self.assertFalse(is_ipv4("google.com"))

    def test_is_domain_ioc_safe(self):
        self.assertTrue(is_domain_ioc_safe("google.com"))
        self.assertTrue(is_domain_ioc_safe("sub.domain.co.uk"))
        self.assertFalse(is_domain_ioc_safe("-start.com"))
        # Our regex requires at least one dot and length constraints
        self.assertFalse(is_domain_ioc_safe("localhost"))


if __name__ == "__main__":
    unittest.main()
