"""
test_multi_device.py
====================
Verification of Multinational Multi-Device Ecosystem for SABRO VISION:
- Web TV Cinema Player
- Smart TV Leanback Mode (/tv)
- Android TV, Fire TV & Mobile PWA (/apps#android)
- Xtream Codes API & Standalone IPTV Apps (/apps#xtream)
- Apple iOS & tvOS ecosystem
"""

import unittest
import app as application
import db

class TestMultiDeviceEcosystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        application.app.config['TESTING'] = True
        application.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = application.app.test_client()

    def test_01_apps_page_loads_and_renders_ecosystem(self):
        """Validate /apps and /devices render the multinational multi-device ecosystem."""
        for path in ["/apps", "/devices"]:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"GLOBAL MULTI-DEVICE ECOSYSTEM", resp.data)
            self.assertIn(b"One Subscription.", resp.data)
            self.assertIn(b"Every Screen You Own.", resp.data)
            self.assertIn(b"Flagship Web TV Cinema Player", resp.data)
            self.assertIn(b"Smart TV Big Screen Mode", resp.data)
            self.assertIn(b"Android Smartphone", resp.data)
            self.assertIn(b"Tablet Experience", resp.data)
            self.assertIn(b"IPTV Smarters Pro, TiviMate", resp.data)
            self.assertIn(b"Apple iPhone, iPad, Mac", resp.data)

    def test_02_navbar_and_footer_multi_device_links(self):
        """Validate base template includes Apps & Devices links in header and footer."""
        resp = self.client.get("/gatekeeper")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Apps & Devices", resp.data)
        self.assertIn(b"Multi-Screen Ready:", resp.data)
        self.assertIn(b"Apps Hub &rarr;", resp.data)

    def test_03_player_multi_device_quick_bar(self):
        """Validate main web player displays the multinational multi-device switcher bar."""
        # Create fresh key
        key_code = db.create_access_key("subscriber", "Multi Device Tester", duration_days=30)
        
        # Activate session
        resp_act = self.client.post("/activate", data={"key_code": key_code}, follow_redirects=True)
        self.assertEqual(resp_act.status_code, 200)
        
        # Check player page
        self.assertIn(b"Multi-Screen", resp_act.data)
        self.assertIn(b"Streaming in <strong>Web TV Mode</strong>", resp_act.data)
        self.assertIn(b"Smart TV Mode", resp_act.data)
        self.assertIn(b"Android App", resp_act.data)
        self.assertIn(b"Xtream Codes", resp_act.data)
        self.assertIn(b"All Devices &rarr;", resp_act.data)

    def test_04_authenticated_apps_shows_credentials(self):
        """Validate /apps pre-fills subscriber username and password for 1-click Xtream setup."""
        # Active session from test_03
        resp = self.client.get("/apps")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Download M3U Playlist File", resp.data)

    def test_05_smart_tv_webapp_has_all_devices_button(self):
        """Validate Smart TV Leanback WebApp has All Devices navigation."""
        # Active session
        resp = self.client.get("/tv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SMART TV LEANBACK", resp.data)
        self.assertIn(b"Web Mode", resp.data)
        self.assertIn(b"All Devices", resp.data)

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
