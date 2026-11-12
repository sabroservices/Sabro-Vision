"""
test_partner_and_pricing.py
===========================
Comprehensive Test Suite for:
1. Sabro Networks Fiber Users = 100% FREE Access (0 PKR, all 11,459 channels, 1 screen).
2. Non-Sabro / Outside Users = Flat 250 PKR for Every Single Package (1 Screen).
3. B2B White-Label & ISP Reseller Portal (/partner and /reseller).
4. Inquiry Form Submission & Storage in SQLite (reseller_inquiries).
5. Admin Management of B2B Partners (/admin/resellers).
"""

import unittest
import db
import app as application

class TestPartnerAndPricing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        application.app.config['TESTING'] = True
        application.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = application.app.test_client()

    def test_01_pricing_policy_verification(self):
        """Verify that basic package is 0 PKR (free) and all other packages are flat 250 PKR, 1 screen."""
        packages = db.get_packages(active_only=False)
        self.assertGreater(len(packages), 10, "Should have all tiered packages configured.")

        basic_pkg = [p for p in packages if p['code'] == 'basic']
        self.assertTrue(len(basic_pkg) == 1, "Basic package must exist")
        self.assertEqual(basic_pkg[0]['price_pkr'], 0, "Basic package must be 0 PKR (100% free for Sabro users)")
        self.assertEqual(basic_pkg[0]['max_connections'], 1, "Basic package must be 1 screen")

        for pkg in packages:
            self.assertEqual(pkg['max_connections'], 1, f"Package {pkg['code']} must be 1 screen")
            if pkg['code'] == 'basic':
                self.assertEqual(pkg['price_pkr'], 0)
            else:
                self.assertEqual(pkg['price_pkr'], 250, f"Package {pkg['code']} must be 250 PKR")

    def test_02_reseller_inquiry_db_crud(self):
        """Test database CRUD for reseller inquiries."""
        inquiry_id = db.create_reseller_inquiry(
            company_name="Test Fiber ISP Ltd",
            contact_name="Farhan Ahmed",
            phone="03001234567",
            email="farhan@testfiber.pk",
            city="Quetta",
            subscriber_count="500-1000",
            partner_type="white_label",
            notes="Testing B2B lead generation"
        )
        self.assertIsInstance(inquiry_id, int)
        self.assertGreater(inquiry_id, 0)

        inquiries = db.get_reseller_inquiries(limit=10)
        found = [i for i in inquiries if i['id'] == inquiry_id]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['company_name'], "Test Fiber ISP Ltd")
        self.assertEqual(found[0]['status'], "pending")

        # Update status to contacted
        db.update_reseller_inquiry_status(inquiry_id, "contacted")
        inquiries_contacted = db.get_reseller_inquiries(status="contacted")
        found_contacted = [i for i in inquiries_contacted if i['id'] == inquiry_id]
        self.assertEqual(len(found_contacted), 1)
        self.assertEqual(found_contacted[0]['status'], "contacted")

    def test_03_dashboard_analytics_includes_resellers(self):
        """Verify get_dashboard_analytics() returns reseller inquiry counters."""
        analytics = db.get_dashboard_analytics()
        self.assertIn("pending_resellers", analytics)
        self.assertIn("total_resellers", analytics)
        self.assertIsInstance(analytics["pending_resellers"], int)
        self.assertIsInstance(analytics["total_resellers"], int)

    def test_04_public_partner_portal_loads(self):
        """Verify /partner and /reseller load and render successfully."""
        resp1 = self.client.get("/partner")
        self.assertEqual(resp1.status_code, 200)
        self.assertIn(b"B2B ISP", resp1.data)
        self.assertIn(b"WHOLESALE RESELLER PORTAL", resp1.data)
        self.assertIn(b"Sabro Networks Users:", resp1.data)
        self.assertIn(b"100% FREE Access", resp1.data)
        self.assertIn(b"Only 250 PKR / Package", resp1.data)

        resp2 = self.client.get("/reseller")
        self.assertEqual(resp2.status_code, 200)

    def test_05_public_partner_form_submission(self):
        """Test submitting the public inquiry form via POST /partner."""
        post_data = {
            "company_name": "PakNet Broadband",
            "contact_name": "Bilal Sheikh",
            "phone": "03219876543",
            "email": "bilal@paknet.pk",
            "city": "Lahore",
            "subscriber_count": "1000-5000",
            "partner_type": "white_label",
            "notes": "Need custom Android TV app branding"
        }
        resp = self.client.post("/partner", data=post_data, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"PakNet Broadband", resp.data)

        # Check DB
        inquiries = db.get_reseller_inquiries(limit=5)
        matched = [i for i in inquiries if i['company_name'] == "PakNet Broadband"]
        self.assertTrue(len(matched) >= 1)

    def test_06_partner_api_submission(self):
        """Test JSON endpoint POST /api/partner/inquiry."""
        payload = {
            "company_name": "Falcon Fiber Cable",
            "contact_name": "Tariq Mahmood",
            "phone": "03335557788",
            "email": "tariq@falcon.com",
            "city": "Islamabad",
            "subscriber_count": "200-500",
            "partner_type": "reseller",
            "notes": "Looking for reseller panel demo"
        }
        resp = self.client.post("/api/partner/inquiry", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("inquiry_id", data)

    def test_07_public_packages_page_highlights_pricing_and_reseller(self):
        """Verify /packages shows Sabro free vs 250 PKR outsider and B2B wholesale card."""
        resp = self.client.get("/packages")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Sabro Networks Users: 100% FREE", resp.data)
        self.assertIn(b"Outsiders: Flat 250 PKR", resp.data)
        self.assertIn(b"Want to Resell or White-Label SABRO VISION", resp.data)
        self.assertTrue(b"/partner" in resp.data or b"/reseller" in resp.data)

    def test_08_gatekeeper_highlights_pricing_and_reseller(self):
        """Verify /gatekeeper shows Sabro free vs 250 PKR outsider and B2B wholesale card."""
        resp = self.client.get("/gatekeeper")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Sabro Networks Users: 100% Free Forever", resp.data)
        self.assertIn(b"Outsiders: Flat 250 PKR (1 Screen)", resp.data)
        self.assertIn(b"B2B Reseller", resp.data)
        self.assertIn(b"White-Label Opportunity", resp.data)

    def test_09_admin_resellers_protection_and_management(self):
        """Test that /admin/resellers is protected and allows status updates when authenticated."""
        # Unauthenticated access should redirect to login
        resp_unauth = self.client.get("/admin/resellers")
        self.assertEqual(resp_unauth.status_code, 302)
        self.assertIn("/admin/login", resp_unauth.headers["Location"])

        # Authenticated access with admin session
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_user"] = "ahmedbaloch"

        resp_admin = self.client.get("/admin/resellers")
        self.assertEqual(resp_admin.status_code, 200)
        self.assertIn(b"B2B Reseller", resp_admin.data)
        self.assertIn(b"White-Label Leads", resp_admin.data)
        self.assertIn(b"PakNet Broadband", resp_admin.data)

        # Update status
        inquiries = db.get_reseller_inquiries(limit=1)
        target_id = inquiries[0]['id']
        resp_update = self.client.post(
            f"/admin/resellers/status/{target_id}",
            data={"status": "approved"},
            follow_redirects=True
        )
        self.assertEqual(resp_update.status_code, 200)
        updated = [i for i in db.get_reseller_inquiries() if i['id'] == target_id][0]
        self.assertEqual(updated['status'], "approved")

        # Admin dashboard shows reseller badge
        resp_dash = self.client.get("/admin")
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn(b"B2B Resellers", resp_dash.data)

if __name__ == "__main__":
    unittest.main()
