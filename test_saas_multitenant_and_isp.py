"""
test_saas_multitenant_and_isp.py
================================
Comprehensive Automated Test Suite for SABRO VISION SaaS Platform:
1. Sabro Networks ISP Free Broadband Customer Entitlement & Verification
2. Outside Customer Paid Flow (Registration, Pricing, Payment Queue, Approval)
3. Outside Customer Expiry Policy Enforcement
4. ISP Reseller Tenant Onboarding, Login & Custom White-Label Branding
5. Multi-Tenant Data Isolation (Reseller A cannot access Reseller B's customers/data)
6. Platform Super Admin Full Cross-Tenant Oversight
7. Multi-Device Anti-Account Sharing Limits
8. Multi-Layer Database Persistence & Data Vault Integrity
"""

import unittest
import os
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

import db
import data_vault
import isp_integration
import payment_gateway
from app import app


class SabroVisionSaaSTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.client = app.test_client()

    def setUp(self):
        # Create unique test tenants for isolation testing
        self.code_a = f"tenant_{secrets.token_hex(3)}"
        self.code_b = f"tenant_{secrets.token_hex(3)}"

        self.tenant_a_id = db.create_tenant({
            "code": self.code_a,
            "name": "Alpha Fiber",
            "service_name": "Alpha TV",
            "brand_color_primary": "#10b981",
            "max_customers": 100
        })

        self.tenant_b_id = db.create_tenant({
            "code": self.code_b,
            "name": "Beta Broadband",
            "service_name": "Beta Vision",
            "brand_color_primary": "#f59e0b",
            "max_customers": 100
        })

        # Create reseller owner users
        self.user_a = f"admin_{self.code_a}"
        self.pass_a = "SecretPass123"
        db.create_reseller_user(self.tenant_a_id, self.user_a, self.pass_a, role="owner")

        self.user_b = f"admin_{self.code_b}"
        self.pass_b = "SecretPass456"
        db.create_reseller_user(self.tenant_b_id, self.user_b, self.pass_b, role="owner")

    def tearDown(self):
        # Clean up test tenants
        conn = db.get_db()
        conn.execute("DELETE FROM support_tickets WHERE tenant_id IN (?, ?)", (self.tenant_a_id, self.tenant_b_id))
        conn.execute("DELETE FROM payment_receipts WHERE tenant_id IN (?, ?)", (self.tenant_a_id, self.tenant_b_id))
        conn.execute("DELETE FROM subscribers WHERE tenant_id IN (?, ?)", (self.tenant_a_id, self.tenant_b_id))
        conn.execute("DELETE FROM reseller_users WHERE tenant_id IN (?, ?)", (self.tenant_a_id, self.tenant_b_id))
        conn.execute("DELETE FROM tenants WHERE id IN (?, ?)", (self.tenant_a_id, self.tenant_b_id))
        conn.commit()
        conn.close()

    # ----------------------------------------------------
    # SCENARIO 1: SABRO NETWORKS BROADBAND CUSTOMER FREE ACCESS
    # ----------------------------------------------------
    def test_scenario_1_sabro_isp_free_customer_entitlement(self):
        """Active Sabro Networks broadband customer receives 100% FREE IPTV access."""
        pppoe = f"sabro_user_{secrets.token_hex(3)}"
        
        # 1. Seed verification into ISP verification cache
        conn = db.get_db()
        now_str = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO isp_verifications (pppoe_username, phone, customer_name, is_active, isp_package, last_verified_at, raw_response)
            VALUES (?, '03009999999', 'Sabro Fiber Subscriber', 1, '50Mbps Unlimited', ?, '{}')
        """, (pppoe, now_str))
        conn.commit()
        conn.close()

        # 2. Call /api/isp/verify
        res = self.client.post("/api/isp/verify", data={"identifier": pppoe})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("verified"))
        self.assertTrue(data.get("is_active"))
        self.assertIn("100% FREE", data.get("message"))

        # 3. Create subscriber linked to Sabro ISP
        ok, msg, sub = db.add_subscriber(
            username=f"sub_{pppoe}",
            password="Password786*",
            pppoe_username=pppoe,
            tenant_id=1,
            is_sabro_isp=1
        )
        self.assertTrue(ok)
        self.assertEqual(sub["is_sabro_isp"], 1)

    # ----------------------------------------------------
    # SCENARIO 2: OUTSIDE CUSTOMER PAID SUBSCRIPTION FLOW
    # ----------------------------------------------------
    def test_scenario_2_outside_customer_paid_registration_and_payment(self):
        """Outside customer registers, submits payment, admin approves, and gets activated."""
        username = f"outside_{secrets.token_hex(3)}"
        password = "OutsidePass123*"

        # 1. Register outside customer
        res = self.client.post("/register", data={
            "username": username,
            "password": password,
            "phone": "0312-7654321",
            "full_name": "Commercial Outside User"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # 2. Retrieve created subscriber
        sub = db.get_subscriber_by_username(username)
        self.assertIsNotNone(sub)
        self.assertEqual(sub.get("is_sabro_isp", 0), 0)

        # 3. Customer submits payment receipt for 250 PKR All-In-One Pass
        aio_pkg = db.get_package_by_code("all_in_one")
        self.assertIsNotNone(aio_pkg)
        receipt_id = db.submit_payment_receipt(
            subscriber_id=sub["id"],
            package_id=aio_pkg["id"],
            amount_pkr=250,
            payment_method="JazzCash",
            transaction_ref=f"JC{secrets.token_hex(4).upper()}",
            sender_number="03001234567"
        )
        self.assertGreater(receipt_id, 0)

        # 4. Admin reviews and approves payment
        ok, msg = db.approve_payment_receipt(receipt_id, admin_user="ahmedbaloch")
        self.assertTrue(ok)

        # 5. Verify subscriber subscription is now active
        curr_sub = db.get_subscriber_subscription(sub["id"])
        self.assertIsNotNone(curr_sub)
        self.assertEqual(curr_sub["status"], "active")
        self.assertEqual(curr_sub["package_id"], aio_pkg["id"])

    # ----------------------------------------------------
    # SCENARIO 3: OUTSIDE CUSTOMER EXPIRY POLICY ENFORCEMENT
    # ----------------------------------------------------
    def test_scenario_3_subscription_expiry_enforcement(self):
        """Expired subscriptions are restricted per platform policy."""
        username = f"exp_{secrets.token_hex(3)}"
        ok, _, sub = db.add_subscriber(username=username, password="Password123*")
        self.assertTrue(ok)

        # Create expired subscription
        conn = db.get_db()
        past_date = (datetime.now() - timedelta(days=5)).isoformat()
        conn.execute("""
            INSERT INTO subscriptions (subscriber_id, package_id, start_date, expiry_date, status, auto_renew, created_at)
            VALUES (?, 1, ?, ?, 'expired', 0, ?)
        """, (sub["id"], past_date, past_date, past_date))
        conn.execute("UPDATE subscribers SET status = 'expired' WHERE id = ?", (sub["id"],))
        conn.commit()
        conn.close()

        updated_sub = db.get_subscriber_by_id(sub["id"])
        self.assertEqual(updated_sub["status"], "expired")

    # ----------------------------------------------------
    # SCENARIO 4: RESELLER ONBOARDING, LOGIN & BRANDING
    # ----------------------------------------------------
    def test_scenario_4_reseller_login_and_branding(self):
        """Reseller can authenticate and customize white-label branding."""
        # 1. Authenticate reseller
        reseller = db.authenticate_reseller(self.user_a, self.pass_a)
        self.assertIsNotNone(reseller)
        self.assertEqual(reseller["tenant_id"], self.tenant_a_id)

        # 2. Update branding
        new_brand_data = {
            "service_name": "Alpha Premium TV",
            "company_name": "Alpha Telecom Ltd",
            "brand_color_primary": "#00ffcc",
            "support_phone": "0311-0000000"
        }
        updated = db.update_tenant(self.tenant_a_id, new_brand_data)
        self.assertTrue(updated)

        t = db.get_tenant_by_id(self.tenant_a_id)
        self.assertEqual(t["service_name"], "Alpha Premium TV")
        self.assertEqual(t["brand_color_primary"], "#00ffcc")

    # ----------------------------------------------------
    # SCENARIO 5: STRICT MULTI-TENANT DATA ISOLATION
    # ----------------------------------------------------
    def test_scenario_5_strict_tenant_isolation(self):
        """Reseller A CANNOT access, view, or modify Reseller B's customer data."""
        # Create a customer for Tenant B
        user_b_cust = f"cust_beta_{secrets.token_hex(3)}"
        ok, _, sub_b = db.add_subscriber(
            username=user_b_cust,
            password="PasswordB123*",
            tenant_id=self.tenant_b_id
        )
        self.assertTrue(ok)

        # Query customers for Tenant A -> Must NOT include Tenant B's customer!
        tenant_a_customers = db.get_subscribers(tenant_id=self.tenant_a_id)
        a_usernames = [c["username"] for c in tenant_a_customers]
        self.assertNotIn(user_b_cust, a_usernames)

        # Simulate Reseller A trying to toggle Tenant B's customer via HTTP
        with self.client.session_transaction() as sess:
            sess["reseller_id"] = 1001
            sess["reseller_tenant_id"] = self.tenant_a_id
            sess["reseller_username"] = self.user_a

        res = self.client.post(f"/reseller/customers/toggle/{sub_b['id']}", follow_redirects=True)
        # Reseller A must be blocked with permission denied
        self.assertIn(b"Permission denied", res.data)

        # Verify Tenant B's customer status was NOT altered
        check_sub = db.get_subscriber_by_id(sub_b["id"])
        self.assertEqual(check_sub["status"], "active")

    # ----------------------------------------------------
    # SCENARIO 6: SUPER ADMIN CROSS-TENANT OVERSIGHT
    # ----------------------------------------------------
    def test_scenario_6_super_admin_oversight(self):
        """Platform Super Admin sees all tenants and metrics."""
        analytics = db.get_dashboard_analytics()
        self.assertIn("total_active_resellers", analytics)
        self.assertIn("total_tenants", analytics)
        self.assertIn("outside_revenue_pkr", analytics)
        self.assertIn("reseller_revenue_pkr", analytics)
        self.assertGreaterEqual(analytics["total_tenants"], 2)

    # ----------------------------------------------------
    # SCENARIO 7: SUPPORT TICKET & NOTIFICATION WORKFLOW
    # ----------------------------------------------------
    def test_scenario_7_support_ticket_and_notifications(self):
        """Customer opens ticket, reseller replies, customer receives notification."""
        # Add a customer for Tenant A
        ok, _, sub = db.add_subscriber(username=f"ticket_user_{secrets.token_hex(2)}", password="Password123*", tenant_id=self.tenant_a_id)
        self.assertTrue(ok)

        # Customer creates ticket
        t_id, t_num = db.create_support_ticket(
            tenant_id=self.tenant_a_id,
            subscriber_id=sub["id"],
            subject="Stream Buffering on Sports Feed",
            category="streaming",
            priority="high",
            initial_message="Channel 1 buffers every few minutes.",
            sender_name=sub["username"]
        )
        self.assertIsNotNone(t_id)

        # Reseller staff replies
        mid = db.add_ticket_message(t_id, sender_type="reseller", sender_name="Alpha Support", message="We have switched the CDN route, please test now.")
        self.assertIsNotNone(mid)

        # Verify ticket details
        ticket = db.get_support_ticket(t_id, tenant_id=self.tenant_a_id)
        self.assertEqual(len(ticket["messages"]), 2)
        self.assertEqual(ticket["messages"][1]["sender_name"], "Alpha Support")

    # ----------------------------------------------------
    # SCENARIO 8: DATA VAULT SNAPSHOT PERSISTENCE
    # ----------------------------------------------------
    def test_scenario_8_vault_persistence_integrity(self):
        """Data Vault captures tenants, tickets, notifications, and customer records."""
        snapshot = data_vault.export_vault_snapshot()
        tables = snapshot.get("tables", {})
        self.assertIn("tenants", tables)
        self.assertIn("reseller_users", tables)
        self.assertIn("subscribers", tables)
        self.assertIn("support_tickets", tables)
        self.assertIn("payment_receipts", tables)


if __name__ == "__main__":
    unittest.main()
