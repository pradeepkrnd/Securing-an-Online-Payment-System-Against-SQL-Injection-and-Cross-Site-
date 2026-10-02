#!/usr/bin/env python3
"""Unit tests for secure_payment_demo.py.  Run:  python3 -m unittest -v test_secure_payment.py"""
import unittest
import secure_payment_demo as s


class SQLInjectionTests(unittest.TestCase):
    def setUp(self):
        self.db = s.open_db()

    def test_tautology_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.get_payment(self.db, 1, "1001' OR '1'='1")

    def test_piggyback_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.get_payment(self.db, 1, "1001; DROP TABLE payments;--")

    def test_union_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.get_payment(self.db, 1, "1002 UNION SELECT 1,2,3")

    def test_ownership_enforced(self):
        self.assertEqual(s.get_payment(self.db, 1, "1002"), [])

    def test_valid_lookup(self):
        self.assertEqual(len(s.get_payment(self.db, 1, "1001")), 1)

    def test_sort_allow_list(self):
        with self.assertRaises(s.ValidationError):
            s.list_payments(self.db, 1, "amount; DROP TABLE payments")
        self.assertTrue(s.list_payments(self.db, 1, "amount"))

    def test_card_number_not_stored(self):
        oid = s.create_payment(self.db, 1, {"amount": "10.00", "currency": "USD",
                                            "cardholder_name": "Alice Doe",
                                            "card_number": "4111111111111111"})
        row = self.db.execute("SELECT * FROM payments WHERE order_id = ?", (oid,)).fetchone()
        self.assertNotIn("4111111111111111", [str(c) for c in row])

    def test_amount_validation(self):
        for bad in ["-5", "0", "10000.01", "1.999", "abc"]:
            with self.assertRaises(s.ValidationError):
                s.validate_amount(bad)


class XSSTests(unittest.TestCase):
    def test_name_with_script_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.validate_name("<script>alert(1)</script>")

    def test_apostrophe_name_allowed(self):
        self.assertEqual(s.validate_name("Pat O'Brien"), "Pat O'Brien")

    def test_html_encoding(self):
        self.assertEqual(s.enc_html('<b>"x"</b>'), "&lt;b&gt;&quot;x&quot;&lt;/b&gt;")

    def test_js_encoding_cannot_close_script(self):
        self.assertNotIn("</script>", s.enc_js("</script><script>alert(1)</script>"))

    def test_javascript_url_blocked(self):
        self.assertEqual(s.safe_url("javascript:alert(1)"), "#")
        self.assertEqual(s.safe_url("https://shop.example/cart"), "https://shop.example/cart")

    def test_receipt_output_is_inert(self):
        headers, page = s.render_receipt("x</script><script>alert(1)</script>", 1, "1.00",
                                         "\"><img src=x onerror=alert(1)>", "javascript:alert(1)")
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("nonce-", headers["Content-Security-Policy"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
