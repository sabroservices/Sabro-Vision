import unittest
import os
import tempfile
import db
import seeds
from app import app, generate_proxy_token, verify_proxy_token

class TestRenderAndHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.test_db_path = cls.test_db.name
        cls.test_db.close()

        cls.orig_db_path = db.DB_PATH
        db.DB_PATH = cls.test_db_path
        seeds.seed_database(force_reset=True)
        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        db.DB_PATH = cls.orig_db_path
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def test_01_proxy_fix_https_generation(self):
        """Verify X-Forwarded-Proto=https & X-Forwarded-Host generate HTTPS URLs on Render."""
        key = db.create_access_key("subscriber", "Render Test User", duration_days=30)
        _, _, sub, _, pw, _ = db.auto_provision_subscriber_from_key(key)
        headers = {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "sabro-vision.onrender.com"
        }
        resp = self.client.get(f"/player_api.php?username={sub['username']}&password={pw}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["server_info"]["server_protocol"], "https")
        self.assertEqual(data["server_info"]["url"], "sabro-vision.onrender.com")
        self.assertEqual(data["server_info"]["https_port"], "443")

        m3u_resp = self.client.get(f"/get.php?username={sub['username']}&password={pw}", headers=headers)
        self.assertEqual(m3u_resp.status_code, 200)
        self.assertIn(b"https://sabro-vision.onrender.com/live/", m3u_resp.data)

    def test_02_xtream_proxy_token_signing_and_validation(self):
        """Verify /live redirects with signed xt token and /proxy rejects tampered tokens."""
        token = generate_proxy_token(ttl_seconds=60)
        self.assertTrue(verify_proxy_token(token))
        self.assertFalse(verify_proxy_token("9999999999.tamperedsignature"))
        self.assertFalse(verify_proxy_token("invalid"))

        key = db.create_access_key("subscriber", "Xtream Proxy User", duration_days=30)
        _, _, sub, _, pw, _ = db.auto_provision_subscriber_from_key(key)
        ch = db.get_channels(limit=1)[0]

        with app.test_client() as c:
            r = c.get(f"/live/{sub['username']}/{pw}/{ch['id']}.m3u8", follow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertIn("xt=", r.headers["Location"])

            # Tampered xt without session must return 401
            r_bad = c.get("/proxy?url=https://example.com/stream.m3u8&xt=9999999999.badtoken")
            self.assertEqual(r_bad.status_code, 401)

    def test_03_safe_int_malformed_admin_inputs(self):
        """Verify empty/invalid integers in admin forms never trigger HTTP 500."""
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["is_admin"] = True
                sess["admin_user"] = "ahmedbaloch"

            r_page = c.get("/admin/customers?page=notanumber")
            self.assertEqual(r_page.status_code, 200)

            r_key = c.post("/admin/keys/create", data={
                "user_type": "subscriber",
                "customer_name": "Safe Int User",
                "duration_days": "invalid_days",
                "package_id": ""
            }, follow_redirects=True)
            self.assertEqual(r_key.status_code, 200)

            r_pkg = c.post("/admin/packages/create", data={
                "name": "Safe Test Pkg",
                "code": "safe_pkg_test",
                "duration_days": "",
                "price_pkr": "abc",
                "max_connections": ""
            }, follow_redirects=True)
            self.assertEqual(r_pkg.status_code, 200)

    def test_04_branded_error_handlers_and_theme_assets(self):
        """Verify 404 returns Obsidian Glass error page for web and JSON for /api/*."""
        r_web = self.client.get("/nonexistent-sabro-page-xyz")
        self.assertEqual(r_web.status_code, 404)
        self.assertIn(b"Page Not Found", r_web.data)
        self.assertIn(b"SABRO VISION", r_web.data)

        r_api = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(r_api.status_code, 404)
        self.assertEqual(r_api.get_json()["error"], "Endpoint not found")

        r_adm_login = self.client.get("/admin/login")
        self.assertEqual(r_adm_login.status_code, 200)
        self.assertIn(b"cinema-glass-card", r_adm_login.data)
        self.assertIn(b".glass-panel", r_adm_login.data)
        self.assertIn(b"sabro: {", r_adm_login.data)

        # Verify credentials modal renders dynamic origin rather than hardcoded localhost
        k = db.create_access_key("subscriber", "Modal Origin Test", duration_days=30)
        with app.test_client() as c:
            r_act = c.post("/activate", data={"key_code": k}, follow_redirects=True)
            self.assertEqual(r_act.status_code, 200)
            self.assertIn(b"window.location.origin", r_act.data)
            self.assertNotIn(b"http://127.0.0.1:8080/", r_act.data)

if __name__ == "__main__":
    unittest.main()
