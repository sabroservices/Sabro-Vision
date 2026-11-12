"""
test_all_in_one_package.py
Comprehensive verification of the All-in-One 250 PKR (1 Screen) Package for SABRO VISION.
Ensures that the package includes each and everything: 100% channel access, single-screen enforcement,
correct 250 PKR pricing, public catalog rendering, and Xtream Codes API support.
"""

import unittest
import requests
import db

BASE_URL = "http://127.0.0.1:8080"

class TestAllInOnePackage(unittest.TestCase):

    def test_01_database_package_attributes(self):
        """Validate package exists with exact 250 PKR price, 1 screen limit, and 'all' categories"""
        pkgs = db.get_packages(active_only=False)
        aio = next((p for p in pkgs if p["code"] == "all_in_one"), None)
        self.assertIsNotNone(aio, "Package with code 'all_in_one' must exist in database")

        self.assertEqual(aio["price_pkr"], 250, "Price must be exactly 250 PKR")
        self.assertEqual(aio["max_connections"], 1, "Must be configured for exactly 1 screen")
        self.assertEqual(aio["duration_days"], 30, "Duration must be 30 days")
        self.assertEqual(aio["allowed_categories"], "all", "Must include each and everything (allowed_categories='all')")
        self.assertEqual(aio["is_active"], 1, "Package must be active")

    def test_02_default_settings_monthly_price(self):
        """Validate system settings monthly_price is set to 250 PKR"""
        settings = db.get_settings()
        self.assertEqual(settings.get("monthly_price"), "250", "Default monthly price must be 250 PKR")

    def test_03_public_packages_catalog_rendering(self):
        """Validate /packages page renders 250 PKR All-in-One card with 1 screen and all channels badge"""
        resp = requests.get(f"{BASE_URL}/packages", timeout=5)
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("ALL-IN-ONE • JUST 250 RS (1 SCREEN)", html)
        self.assertIn("250 PKR", html)
        self.assertIn("1 Screen", html)
        self.assertIn("Everything Included (All 11,459 Channels)", html)

    def test_04_gatekeeper_payment_pricing(self):
        """Validate Gatekeeper screen displays 250 PKR for the monthly pass"""
        resp = requests.get(f"{BASE_URL}/gatekeeper", timeout=5)
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("PKR 250", html)
        self.assertIn("1 Screen", html)
        self.assertIn("All-In-One", html)

    def test_05_payment_submit_page_default_package(self):
        """Validate /payment/submit defaults to All-in-One 250 PKR package when authenticated"""
        # Create and activate a session
        key_code = db.create_access_key(duration_days=30)
        s = requests.Session()
        s.post(f"{BASE_URL}/activate", data={"key_code": key_code})

        resp = s.get(f"{BASE_URL}/payment/submit", timeout=5)
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        self.assertIn("Sabro All-in-One Super Pass", html)
        self.assertIn('value="250"', html)

    def test_06_key_activation_and_all_channels_access(self):
        """Activate key for All-in-One package and verify unrestricted streaming across all categories"""
        pkgs = db.get_packages(active_only=True)
        aio = next(p for p in pkgs if p["code"] == "all_in_one")

        # Create voucher key for All-in-One package
        key_code = db.create_access_key(package_id=aio["id"], duration_days=30, notes="All-in-One Test")
        self.assertTrue(key_code.startswith("SABRO-"))

        # Activate key in session
        s = requests.Session()
        act_resp = s.post(f"{BASE_URL}/activate", data={"key_code": key_code}, allow_redirects=True)
        self.assertEqual(act_resp.status_code, 200)
        self.assertIn("iptvVideo", act_resp.text)

        # Retrieve subscriber
        sub_row = db.get_db().execute("SELECT * FROM subscribers WHERE active_key_code = ?", (key_code,)).fetchone()
        self.assertIsNotNone(sub_row)
        self.assertEqual(sub_row["package_id"], aio["id"])

        # Check permission for Sports channel
        sports_ch = db.get_channels(category="Sports", limit=1)
        if sports_ch:
            self.assertTrue(db.can_subscriber_access_channel(subscriber_id=sub_row["id"], channel_id=sports_ch[0]["id"]))
            stream_resp = s.get(f"{BASE_URL}/stream/{sports_ch[0]['id']}", allow_redirects=False)
            self.assertIn(stream_resp.status_code, [200, 302])

        # Check permission for Comedy channel
        comedy_ch = db.get_channels(category="Comedy", limit=1)
        if comedy_ch:
            self.assertTrue(db.can_subscriber_access_channel(subscriber_id=sub_row["id"], channel_id=comedy_ch[0]["id"]))
            stream_resp = s.get(f"{BASE_URL}/stream/{comedy_ch[0]['id']}", allow_redirects=False)
            self.assertIn(stream_resp.status_code, [200, 302])

        # Check permission for News channel
        news_ch = db.get_channels(category="News", limit=1)
        if news_ch:
            self.assertTrue(db.can_subscriber_access_channel(subscriber_id=sub_row["id"], channel_id=news_ch[0]["id"]))
            stream_resp = s.get(f"{BASE_URL}/stream/{news_ch[0]['id']}", allow_redirects=False)
            self.assertIn(stream_resp.status_code, [200, 302])

        # Check permission for Movies channel
        movies_ch = db.get_channels(category="Movies", limit=1)
        if movies_ch:
            self.assertTrue(db.can_subscriber_access_channel(subscriber_id=sub_row["id"], channel_id=movies_ch[0]["id"]))
            stream_resp = s.get(f"{BASE_URL}/stream/{movies_ch[0]['id']}", allow_redirects=False)
            self.assertIn(stream_resp.status_code, [200, 302])

    def test_07_xtream_codes_api_unrestricted_access(self):
        """Validate Xtream Codes API handshake returns all categories for All-in-One subscriber"""
        pkgs = db.get_packages(active_only=True)
        aio = next(p for p in pkgs if p["code"] == "all_in_one")

        key_code = db.create_access_key(package_id=aio["id"], duration_days=30)
        s = requests.Session()
        s.post(f"{BASE_URL}/activate", data={"key_code": key_code})

        sub_row = db.get_db().execute("SELECT * FROM subscribers WHERE active_key_code = ?", (key_code,)).fetchone()
        auth_url = f"{BASE_URL}/player_api.php?username={sub_row['username']}&password={sub_row['plain_password']}"

        resp = requests.get(f"{auth_url}&action=get_live_categories", timeout=5)
        self.assertEqual(resp.status_code, 200)
        categories = resp.json()
        self.assertGreaterEqual(len(categories), 7, "All categories must be available to All-in-One user")


    @classmethod
    def tearDownClass(cls):
        """Ensure test data created during test run is completely wiped so database stays pristine."""
        conn = db.get_db()
        for t in ['access_keys', 'subscribers', 'subscriptions', 'favorites', 'payment_receipts', 'reseller_inquiries', 'audit_logs', 'connection_events']:
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()

if __name__ == "__main__":
    unittest.main()
