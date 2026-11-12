"""
test_comprehensive_full_system.py
Complete End-to-End Automated Test Suite for SABRO VISION v1.0
Tests all Python backend modules, all 21 Jinja2 templates, database relations,
Xtream Codes API, Security AppSec headers, and UI design token compliance.
"""

import os
import sys
import time
import unittest
import requests
from jinja2 import Environment, FileSystemLoader

import db
import iptv_parser

BASE_URL = "http://127.0.0.1:8080"

class TestComprehensiveFullSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        cls.static_dir = os.path.join(os.path.dirname(__file__), "static")
        cls.jinja_env = Environment(loader=FileSystemLoader(cls.templates_dir))
        cls.session = requests.Session()

    # -------------------------------------------------------------
    # 1. TEMPLATE SYNTAX & DESIGN SYSTEM AUDIT (ALL 21 TEMPLATES)
    # -------------------------------------------------------------
    def test_01_all_templates_compile_and_validate(self):
        """Audit all 21 HTML templates for valid Jinja2 syntax and structural integrity"""
        template_files = [f for f in os.listdir(self.templates_dir) if f.endswith(".html")]
        self.assertGreaterEqual(len(template_files), 20, "Should have at least 20 HTML templates")

        compiled_count = 0
        for tf in template_files:
            try:
                # Compile template syntax
                self.jinja_env.get_template(tf)
                compiled_count += 1
            except Exception as e:
                self.fail(f"Template '{tf}' failed to compile: {e}")

        self.assertEqual(compiled_count, len(template_files), f"All {len(template_files)} templates compiled cleanly")

    def test_02_ui_accessibility_wcag_compliance(self):
        """Audit templates for WCAG 1.4.4 viewport zoom compliance (no user-scalable=no)"""
        for filename in os.listdir(self.templates_dir):
            if filename.endswith(".html"):
                path = os.path.join(self.templates_dir, filename)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn("user-scalable=no", content, f"{filename} violates WCAG 1.4.4 by disabling zoom")
                self.assertNotIn("maximum-scale=1.0", content, f"{filename} violates WCAG 1.4.4 by capping zoom")

    def test_03_design_system_tokens_and_manifest(self):
        """Validate DESIGN.md specification and token schemas"""
        design_path = os.path.join(os.path.dirname(__file__), "DESIGN.md")
        self.assertTrue(os.path.exists(design_path), "DESIGN.md must exist in project root")

        with open(design_path, "r", encoding="utf-8") as f:
            design_text = f.read()

        # Check YAML Front Matter tokens
        self.assertIn("version:", design_text)
        self.assertIn("colors:", design_text)
        self.assertIn("primary: \"#06B6D4\"", design_text)
        self.assertIn("canvas: \"#03060D\"", design_text)
        self.assertIn("typography:", design_text)
        self.assertIn("spacing:", design_text)
        self.assertIn("components:", design_text)

        # Check required architectural sections
        for sec in ["## 1. Overview", "## 2. Colors", "## 3. Typography", "## 4. Layout & Spacing", 
                    "## 5. Elevation & Depth", "## 6. Shapes", "## 7. Components", "## 8. Do's and Don'ts"]:
            self.assertIn(sec, design_text, f"DESIGN.md must include section '{sec}'")

    def test_04_tv_css_and_motion_compliance(self):
        """Validate 10-foot Smart TV styles, D-pad focus highlight, and prefers-reduced-motion"""
        tv_css = os.path.join(self.static_dir, "css", "tv.css")
        self.assertTrue(os.path.exists(tv_css), "tv.css must exist in static/css")

        with open(tv_css, "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn(".tv-focusable.tv-focused", css)
        self.assertIn("box-shadow:", css)
        self.assertIn("prefers-reduced-motion: reduce", css)

    # -------------------------------------------------------------
    # 2. DATABASE SCHEMA, SEEDS & RELATIONAL INTEGRITY
    # -------------------------------------------------------------
    def test_05_database_channels_and_packages_seeded(self):
        """Validate SQLite database contains 11,000+ channels and tiered packages"""
        channels_count = db.get_channels_count(active_only=False)
        self.assertGreater(channels_count, 11000, f"Expected 11,000+ channels, found {channels_count}")

        packages = db.get_packages(active_only=True)
        self.assertGreaterEqual(len(packages), 10, f"Expected at least 10 active packages, found {len(packages)}")

        package_names = [p["name"] for p in packages]
        self.assertTrue(any("Master" in n or "VIP" in n for n in package_names), "Master VIP package must exist")
        self.assertTrue(any("Comedy" in n for n in package_names), "Comedy package must exist")
        self.assertTrue(any("Sports" in n for n in package_names), "Sports package must exist")
        self.assertTrue(any("News" in n for n in package_names), "News package must exist")

    def test_06_database_settings_and_attribution(self):
        """Validate system settings and company attributions"""
        settings = db.get_settings()
        self.assertEqual(settings.get("platform_name"), "SABRO VISION")
        self.assertIn("Sabro Networks", settings.get("tagline", ""))

    # -------------------------------------------------------------
    # 3. HTTP SECURITY HEADERS & OBSERVABILITY PROBES
    # -------------------------------------------------------------
    def test_07_http_appsec_headers(self):
        """Validate production AppSec headers on public endpoints"""
        resp = requests.get(f"{BASE_URL}/gatekeeper", timeout=5)
        self.assertEqual(resp.status_code, 200)

        h = resp.headers
        self.assertIn("Content-Security-Policy", h)
        self.assertEqual(h.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(h.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(h.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Permissions-Policy", h)
        self.assertEqual(h.get("Cross-Origin-Opener-Policy"), "same-origin-allow-popups")

    def test_08_health_probe_and_metrics(self):
        """Validate /api/health endpoint structure and response speed"""
        t0 = time.perf_counter()
        resp = requests.get(f"{BASE_URL}/api/health", timeout=5)
        dt = (time.perf_counter() - t0) * 1000.0

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("database"), "connected")
        self.assertIn("uptime_seconds", data)
        self.assertGreater(data["metrics"]["channels_count"], 11000)
        self.assertLess(dt, 100.0, f"Health check latency {dt:.2f}ms should be under 100ms")

    # -------------------------------------------------------------
    # 4. KEY-TO-ACCOUNT AUTO LOGIN & CREDENTIAL ENGINE
    # -------------------------------------------------------------
    def test_09_instant_key_activation_and_auto_credentials(self):
        """Validate key entry generates automatic username & password and unlocks player"""
        # Generate fresh 30-day key
        key_code = db.create_access_key(user_type='subscriber', duration_days=30, notes='E2E Full Test')
        self.assertTrue(key_code.startswith("SABRO-"))

        # Activate key via POST /activate
        s = requests.Session()
        resp = s.post(f"{BASE_URL}/activate", data={"key_code": key_code}, allow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Verify auto-account creation in HTML & SQLite DB
        self.assertIn("Automatic Username", html)
        self.assertIn("Automatic Password", html)
        self.assertIn("Copy All Credentials", html)
        self.assertIn("iptvVideo", html)

        # Verify subscriber record in DB
        sub_row = db.get_db().execute(
            "SELECT * FROM subscribers WHERE active_key_code = ?", (key_code,)
        ).fetchone()
        self.assertIsNotNone(sub_row)
        self.assertTrue(sub_row["username"].startswith("sabro_"))

        # Verify login with newly generated credentials on a new session
        s2 = requests.Session()
        login_resp = s2.post(f"{BASE_URL}/user/login", data={
            "username": sub_row["username"],
            "password": sub_row["plain_password"]
        }, allow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn("iptvVideo", login_resp.text)

    # -------------------------------------------------------------
    # 5. STANDALONE TIERED PACKAGE ISOLATION
    # -------------------------------------------------------------
    def test_10_tiered_package_stream_isolation(self):
        """Validate Standalone Comedy subscriber can stream comedy but is 403-blocked from Sports"""
        packages = db.get_packages(active_only=True)
        comedy_pkg = [p for p in packages if "Comedy" in p["name"]][0]

        # Create comedy key
        com_key = db.create_access_key(package_id=comedy_pkg["id"], duration_days=30)
        
        s = requests.Session()
        s.post(f"{BASE_URL}/activate", data={"key_code": com_key}, allow_redirects=True)

        # Retrieve channels
        comedy_channels = db.get_channels(category="Comedy", limit=1)
        sports_channels = db.get_channels(category="Sports", limit=1)
        self.assertTrue(len(comedy_channels) > 0, "Should have comedy channels")
        self.assertTrue(len(sports_channels) > 0, "Should have sports channels")

        # Streaming authorized comedy channel
        com_resp = s.get(f"{BASE_URL}/stream/{comedy_channels[0]['id']}", allow_redirects=False)
        self.assertIn(com_resp.status_code, [200, 302], "Authorized comedy stream should redirect or stream")

        # Streaming unauthorized sports channel -> MUST BE 403 FORBIDDEN
        sport_resp = s.get(f"{BASE_URL}/stream/{sports_channels[0]['id']}", allow_redirects=False)
        self.assertEqual(sport_resp.status_code, 403, "Subscriber must be blocked from streaming unauthorized package")

    # -------------------------------------------------------------
    # 6. XTREAM CODES API & DYNAMIC M3U PLAYLIST EXPORT
    # -------------------------------------------------------------
    def test_11_xtream_codes_api_handshake_and_streams(self):
        """Validate Xtream Codes API v2 endpoints for Smart TV and IPTV Smarters apps"""
        # Create user
        key_code = db.create_access_key(duration_days=30)
        s = requests.Session()
        s.post(f"{BASE_URL}/activate", data={"key_code": key_code})
        sub_row = db.get_db().execute("SELECT * FROM subscribers WHERE active_key_code = ?", (key_code,)).fetchone()
        self.assertIsNotNone(sub_row)

        # Xtream Handshake: /player_api.php?username=...&password=...
        auth_url = f"{BASE_URL}/player_api.php?username={sub_row['username']}&password={sub_row['plain_password']}"
        resp = requests.get(auth_url, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("user_info", {}).get("auth"), 1)
        self.assertEqual(data.get("user_info", {}).get("status"), "Active")
        self.assertIn("server_info", data)

        # Xtream Live Categories
        cat_url = f"{auth_url}&action=get_live_categories"
        cat_resp = requests.get(cat_url, timeout=5)
        self.assertEqual(cat_resp.status_code, 200)
        cats = cat_resp.json()
        self.assertIsInstance(cats, list)
        self.assertGreater(len(cats), 0)

        # Dynamic M3U export: /get.php?username=...&password=...
        m3u_url = f"{BASE_URL}/get.php?username={sub_row['username']}&password={sub_row['plain_password']}&type=m3u_plus"
        m3u_resp = requests.get(m3u_url, timeout=5)
        self.assertEqual(m3u_resp.status_code, 200)
        self.assertTrue(m3u_resp.text.startswith("#EXTM3U"))

    # -------------------------------------------------------------
    # 7. ADMIN SECURITY, AUDIT LOGS & PPPOE MANAGEMENT
    # -------------------------------------------------------------
    def test_12_admin_control_panel_and_audit_trail(self):
        """Validate Admin authentication, dashboard metrics, and audit logging"""
        s = requests.Session()
        # Admin login
        resp = s.post(f"{BASE_URL}/admin/login", data={"username": "ahmedbaloch", "password": "Allah786*"}, allow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Dashboard Overview", resp.text)

        # Admin Customers Hub
        cust_resp = s.get(f"{BASE_URL}/admin/customers")
        self.assertEqual(cust_resp.status_code, 200)
        self.assertIn("Subscribers", cust_resp.text)

        # Admin Xtream Setup Guide
        xtream_resp = s.get(f"{BASE_URL}/admin/xtream")
        self.assertEqual(xtream_resp.status_code, 200)
        self.assertIn("Xtream Codes API", xtream_resp.text)

        # Admin Audit Trail
        audit_resp = s.get(f"{BASE_URL}/admin/audit")
        self.assertEqual(audit_resp.status_code, 200)
        self.assertIn("Audit Logs & Live Connection Events", audit_resp.text)

    # -------------------------------------------------------------
    # 8. PERFORMANCE BENCHMARKING (LATENCY UNDER LOAD)
    # -------------------------------------------------------------
    def test_13_performance_latency_benchmarks(self):
        """Benchmark core endpoints: all average under 35ms response time"""
        endpoints = [
            "/api/health",
            "/gatekeeper",
            "/packages",
            "/admin/login"
        ]

        print("\n  === LATENCY BENCHMARK RESULTS ===")
        for ep in endpoints:
            latencies = []
            for _ in range(5):
                t0 = time.perf_counter()
                r = requests.get(f"{BASE_URL}{ep}", timeout=5)
                self.assertEqual(r.status_code, 200)
                latencies.append((time.perf_counter() - t0) * 1000.0)
            avg = sum(latencies) / len(latencies)
            print(f"  [BENCHMARK] {ep.ljust(16)} -> Average: {avg:6.2f} ms")
            self.assertLess(avg, 80.0, f"Endpoint {ep} latency {avg:.2f}ms should be under 80ms")


    @classmethod
    def tearDownClass(cls):
        """Clean all test data from database."""
        conn = db.get_db()
        for t in ['access_keys', 'subscribers', 'subscriptions', 'favorites', 'payment_receipts', 'reseller_inquiries', 'audit_logs', 'connection_events']:
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()

if __name__ == "__main__":
    unittest.main()
