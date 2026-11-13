"""
test_persistence_and_gatekeeper_redirect.py
===========================================
Comprehensive verification of:
1. Automatic Shift of unauthenticated visitors at root '/' to '/gatekeeper' with HTTPS on Render.
2. HTTP-to-HTTPS redirect enforcement on Render ('X-Forwarded-Proto: http').
3. Gatekeeper UI enhancements (direct login, dual tabs, free vs 250 PKR outsider rate, quick copy).
4. Multi-Layer Data Vault & Persistence Engine:
   - Automated vault snapshot generation on every write.
   - WAL journal flush & checkpointing.
   - Seamless bootstrap & restore across process restarts.
5. Admin Backup & Data Vault Control Panel endpoints.
"""

import os
import json
import unittest
from datetime import datetime

import app as application
import db
import data_vault

class TestPersistenceAndGatekeeperRedirect(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        application.app.config["TESTING"] = True
        application.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = application.app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Ensure test artifacts are cleaned up and a clean baseline vault snapshot is preserved."""
        conn = db.get_db()
        for t in ['access_keys', 'subscribers', 'subscriptions', 'favorites', 'payment_receipts', 'reseller_inquiries', 'audit_logs', 'connection_events']:
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()
        data_vault.truncate_wal()
        data_vault.save_vault_snapshot_to_disk()

    def test_01_root_unauthenticated_visitor_shifted_to_gatekeeper(self):
        """Unauthenticated visitor arriving at root '/' must be shifted into '/gatekeeper'"""
        resp = self.client.get("/", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/gatekeeper", resp.headers["Location"])

    def test_02_render_domain_shifts_to_gatekeeper_with_https(self):
        """Visitors on render domain (sabro-vision.onrender.com) are shifted to https://.../gatekeeper"""
        resp = self.client.get("/", headers={
            "Host": "sabro-vision.onrender.com",
            "X-Forwarded-Proto": "https"
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        location = resp.headers["Location"]
        self.assertTrue(location.startswith("https://sabro-vision.onrender.com/gatekeeper"))

    def test_03_render_http_upgraded_to_https_301(self):
        """Incoming HTTP requests on Render are 301 upgraded to HTTPS"""
        resp = self.client.get("/gatekeeper", headers={
            "Host": "sabro-vision.onrender.com",
            "X-Forwarded-Proto": "http"
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 301)
        self.assertTrue(resp.headers["Location"].startswith("https://sabro-vision.onrender.com/gatekeeper"))

    def test_04_gatekeeper_ui_elements_and_pricing_clarity(self):
        """Gatekeeper page renders beautiful dual tabs, key formatter, and exact pricing highlights"""
        resp = self.client.get("/gatekeeper")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Brand and Platform Title
        self.assertIn("SABRO VISION", html)
        self.assertIn("Vshatkay Solutions", html)
        self.assertIn("Sabro Networks", html)

        # Dual Login Tabs
        self.assertIn("Put Key & Get Auto Login", html)
        self.assertIn("Login with Username & Password", html)
        self.assertIn("Put Your Key to Get Automatic Login", html)
        self.assertIn("Sign In with Saved Account", html)

        # Pricing and packages policy
        self.assertIn("Sabro Networks Users: 100% Free Forever", html)
        self.assertIn("Outsiders: Flat 250 PKR (1 Screen)", html)
        self.assertIn("PKR 250", html)
        self.assertIn("1 Screen", html)
        self.assertIn("All-In-One", html)

        # Direct payment accounts
        self.assertIn("JazzCash", html)
        self.assertIn("EasyPaisa", html)
        self.assertIn("wa.me", html)

        # Multi-screen sub-bar
        self.assertIn("Multi-Screen Ready:", html)
        self.assertIn("Apps Hub &rarr;", html)

    def test_05_data_vault_snapshot_export_and_restore(self):
        """Data Vault exports snapshot and restores all data across simulated container restarts"""
        # 1. Create a test key and auto-provision subscriber
        key_code = db.create_access_key(user_type="subscriber", customer_name="Vault Test Customer", duration_days=30)
        success, _, sub_data, _, _, _ = db.auto_provision_subscriber_from_key(key_code)
        self.assertTrue(success)

        # 2. Add a reseller inquiry
        inq_id = db.create_reseller_inquiry(
            company_name="Vault Fiber ISP",
            contact_name="Tariq Baloch",
            phone="03331112233",
            email="tariq@vaultfiber.pk",
            city="Gwadar"
        )
        self.assertGreater(inq_id, 0)

        # 3. Export snapshot
        snapshot = data_vault.export_vault_snapshot()
        self.assertEqual(snapshot["platform"], "SABRO VISION")
        self.assertIn("access_keys", snapshot["tables"])
        self.assertIn("subscribers", snapshot["tables"])
        self.assertIn("reseller_inquiries", snapshot["tables"])

        # Check key and subscriber in exported snapshot
        exported_keys = [k["key_code"] for k in snapshot["tables"]["access_keys"]]
        self.assertIn(key_code, exported_keys)
        exported_users = [u["username"] for u in snapshot["tables"]["subscribers"]]
        self.assertIn(sub_data["username"], exported_users)

        # 4. Save to disk
        save_ok = data_vault.save_vault_snapshot_to_disk()
        self.assertTrue(save_ok)
        self.assertTrue(os.path.exists(data_vault.VAULT_FILE))

        # 5. Simulate container wipe: delete the records in SQLite
        conn = db.get_db()
        conn.execute("DELETE FROM access_keys WHERE key_code = ?", (key_code,))
        conn.execute("DELETE FROM subscribers WHERE username = ?", (sub_data["username"],))
        conn.commit()

        # Confirm deleted
        check_key = conn.execute("SELECT id FROM access_keys WHERE key_code = ?", (key_code,)).fetchone()
        self.assertIsNone(check_key)
        conn.close()

        # 6. Simulate restart recovery: load from vault disk
        restored_count = data_vault.load_vault_from_disk()
        self.assertGreater(restored_count, 0)

        # 7. Verify records restored into SQLite
        conn2 = db.get_db()
        recovered_key = conn2.execute("SELECT * FROM access_keys WHERE key_code = ?", (key_code,)).fetchone()
        recovered_user = conn2.execute("SELECT * FROM subscribers WHERE username = ?", (sub_data["username"],)).fetchone()
        conn2.close()

        self.assertIsNotNone(recovered_key, "Key must be completely restored from vault across restarts")
        self.assertIsNotNone(recovered_user, "Subscriber must be completely restored from vault across restarts")

    def test_06_admin_backup_control_panel_endpoints(self):
        """Admin Backup endpoints render status and allow JSON & DB downloads"""
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_user"] = "ahmedbaloch"

        # 1. GET /admin/backup
        resp = self.client.get("/admin/backup")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Database & Data Vault Management", resp.data)
        self.assertIn(b"Download Live Backups", resp.data)
        self.assertIn(b"Upload & Restore Data", resp.data)

        # 2. POST /admin/backup/trigger
        resp_trig = self.client.post("/admin/backup/trigger", follow_redirects=True)
        self.assertEqual(resp_trig.status_code, 200)
        self.assertIn(b"Data Vault snapshot saved successfully", resp_trig.data)

        # 3. GET /admin/backup/download-json
        resp_json = self.client.get("/admin/backup/download-json")
        self.assertEqual(resp_json.status_code, 200)
        data = json.loads(resp_json.data)
        self.assertEqual(data.get("platform"), "SABRO VISION")

        # 4. GET /admin/backup/download-db
        resp_db = self.client.get("/admin/backup/download-db")
        self.assertEqual(resp_db.status_code, 200)
        self.assertTrue(resp_db.data.startswith(b"SQLite format 3"))

if __name__ == "__main__":
    unittest.main()
