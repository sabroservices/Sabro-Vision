import os
import unittest
from datetime import datetime, timedelta
from app import app
import db
import seeds
import iptv_parser

class TestSabroIPTV(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use isolated test database
        import tempfile
        cls.test_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.test_db_path = cls.test_db_file.name
        cls.test_db_file.close()

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

    def test_01_database_tables_and_seeds(self):
        """Verify categories, initial channels, and settings are seeded correctly."""
        categories = db.get_categories()
        self.assertGreater(len(categories), 0)
        category_names = [c["name"] for c in categories]
        self.assertIn("Sports", category_names)
        self.assertIn("News", category_names)

        channels = db.get_channels()
        self.assertGreater(len(channels), 0)
        channel_names = [ch["name"] for ch in channels]
        self.assertTrue(any("PTV Sports" in name or "Geo News" in name for name in channel_names))

        settings = db.get_settings()
        self.assertEqual(settings.get("platform_name"), "SABRO VISION")
        self.assertEqual(settings.get("currency"), "PKR")

    def test_02_gatekeeper_enforcement(self):
        """Unauthenticated visitor trying to access player must be redirected to /gatekeeper."""
        with app.test_client() as client:
            resp = client.get("/", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/gatekeeper", resp.headers["Location"])

            # Accessing gatekeeper page directly gives 200 OK
            gk_resp = client.get("/gatekeeper")
            self.assertEqual(gk_resp.status_code, 200)
            self.assertIn(b"VIP Access", gk_resp.data)
            self.assertIn(b"Sabro Networks Subscribers", gk_resp.data)
            self.assertIn(b"Monthly Pass", gk_resp.data)

    def test_03_key_activation_and_player_access(self):
        """Activate a free subscriber key and verify streaming access."""
        # Create a test key
        test_key = db.create_access_key(user_type="subscriber", customer_name="Test Fiber User", duration_days=30)
        
        with app.test_client() as client:
            # Activate key
            activate_resp = client.post("/activate", data={"key_code": test_key}, follow_redirects=True)
            self.assertEqual(activate_resp.status_code, 200)
            self.assertIn(b"Available Channels", activate_resp.data)
            self.assertIn(b"Sabro Fiber Pass", activate_resp.data)

            # Player page gives 200
            player_resp = client.get("/")
            self.assertEqual(player_resp.status_code, 200)
            self.assertIn(b"iptvVideo", player_resp.data)

    def test_04_outsider_paid_key(self):
        """Verify outsider paid key works and tracks user_type."""
        paid_key = db.create_access_key(user_type="outsider", customer_name="Outside Buyer", duration_days=30)
        
        with app.test_client() as client:
            activate_resp = client.post("/activate", data={"key_code": paid_key}, follow_redirects=True)
            self.assertEqual(activate_resp.status_code, 200)
            self.assertIn(b"VIP Monthly Pass", activate_resp.data)

    def test_05_expired_or_invalid_key_handling(self):
        """Verify invalid key gives error message and prevents access."""
        with app.test_client() as client:
            resp = client.post("/activate", data={"key_code": "INVALID-KEY-1234"}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid access key", activate_resp_data := resp.data)

    def test_06_admin_authentication_and_dashboard(self):
        """Test admin login, session protection, and stats."""
        with app.test_client() as client:
            # Unauthorized access to /admin redirects to login
            dash_unauth = client.get("/admin", follow_redirects=False)
            self.assertEqual(dash_unauth.status_code, 302)
            self.assertIn("/admin/login", dash_unauth.headers["Location"])

            # Login with ahmedbaloch admin credentials
            login_resp = client.post("/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"}, follow_redirects=True)
            self.assertEqual(login_resp.status_code, 200)
            self.assertIn(b"Admin Panel", login_resp.data)
            self.assertIn(b"Active Keys", login_resp.data)

            # Access keys management page
            keys_resp = client.get("/admin/keys")
            self.assertEqual(keys_resp.status_code, 200)
            self.assertIn(b"Access Keys", keys_resp.data)

    def test_07_bulk_key_generation_and_renewal(self):
        """Verify bulk generating 5 keys and 1-click renewal."""
        initial_stats = db.get_key_stats()
        keys = db.bulk_generate_keys(count=5, user_type="subscriber", duration_days=30)
        self.assertEqual(len(keys), 5)
        
        new_stats = db.get_key_stats()
        self.assertEqual(new_stats["total"], initial_stats["total"] + 5)

        # Activate one and renew it
        success, msg, data = db.activate_key(keys[0], device_token="test_device_1")
        self.assertTrue(success)
        key_id = data["id"]
        
        renew_ok, renew_msg = db.renew_key(key_id, extra_days=30)
        self.assertTrue(renew_ok)
        self.assertIn("+30 days", renew_msg)

    def test_08_channel_crud_and_favorites(self):
        """Test adding a custom channel, retrieving it, and toggling favorites."""
        ch_id = db.add_channel(
            name="Sabro Test Channel",
            stream_url="https://test.stream/live.m3u8",
            logo="",
            category="Sports"
        )
        self.assertIsNotNone(ch_id)

        ch = db.get_channel_by_id(ch_id)
        self.assertEqual(ch["name"], "Sabro Test Channel")

        # Toggle favorite
        is_fav = db.toggle_favorite("TEST-KEY-001", ch_id)
        self.assertTrue(is_fav)
        is_fav2 = db.toggle_favorite("TEST-KEY-001", ch_id)
        self.assertFalse(is_fav2)

        # Cleanup
        db.delete_channel(ch_id)
        self.assertIsNone(db.get_channel_by_id(ch_id))

    def test_09_m3u_parser(self):
        """Test parsing sample M3U playlist text."""
        sample_m3u = """#EXTM3U
#EXTINF:-1 tvg-id="geo" tvg-name="Geo News" tvg-logo="https://img.com/geo.png" group-title="Pakistan News",Geo News HD
https://cdn.example.com/geo/live.m3u8
#EXTINF:-1 tvg-id="ten" tvg-name="Ten Sports" tvg-logo="https://img.com/ten.png" group-title="Live Sports",Ten Sports Live
https://cdn.example.com/ten/stream.m3u8
"""
        parsed = iptv_parser.parse_m3u_content(sample_m3u)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "Geo News HD")
        self.assertEqual(parsed[0]["category"], "News")
        self.assertEqual(parsed[1]["name"], "Ten Sports Live")
        self.assertEqual(parsed[1]["category"], "Sports")

    def test_10_security_headers(self):
        """Verify essential HTTP security response headers."""
        resp = self.client.get("/gatekeeper")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(resp.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_11_unauthorized_stream_blocked(self):
        """Ensure stream endpoints reject requests without active key."""
        with app.test_client() as client:
            resp = client.get("/stream/1")
            self.assertEqual(resp.status_code, 401)
            self.assertIn(b"Access denied", resp.data)

            proxy_resp = client.get("/proxy?url=https://cdn.example.com/live.m3u8")
            self.assertEqual(proxy_resp.status_code, 401)

    def test_12_ssrf_protection(self):
        """Verify SSRF filters block loopback, metadata, and local network IPs."""
        # Authenticate first
        test_key = db.create_access_key(user_type="subscriber", duration_days=30)
        with app.test_client() as client:
            client.post("/activate", data={"key_code": test_key})

            # Try loopback SSRF
            ssrf1 = client.get("/proxy?url=http://127.0.0.1:22/admin")
            self.assertEqual(ssrf1.status_code, 403)
            self.assertIn(b"blocked by security policy", ssrf1.data)

            # Try AWS/Cloud metadata IP
            ssrf2 = client.get("/proxy?url=http://169.254.169.254/latest/meta-data/")
            self.assertEqual(ssrf2.status_code, 403)

            # Try private RFC1918 IP
            ssrf3 = client.get("/proxy?url=http://192.168.1.1/router")
            self.assertEqual(ssrf3.status_code, 403)

    def test_13_rate_limiting_activation(self):
        """Verify brute force attempts on /activate are blocked by rate limiter."""
        from app import RATE_LIMIT_STORE
        RATE_LIMIT_STORE["activate"].clear()

        with app.test_client() as client:
            # 10 invalid attempts
            for _ in range(10):
                client.post("/activate", data={"key_code": "WRONG-KEY"})

            # 11th attempt must be rate limited
            blocked_resp = client.post("/activate", data={"key_code": "WRONG-KEY"}, follow_redirects=True)
            self.assertIn(b"Too many failed activation attempts", blocked_resp.data)

            # Cleanup rate limit store
            RATE_LIMIT_STORE["activate"].clear()

    def test_14_admin_channels_pagination(self):
        """Test channel count helper and pagination logic."""
        total = db.get_channels_count()
        self.assertGreater(total, 0)
        p1 = db.get_channels(limit=5, offset=0, active_only=False)
        self.assertEqual(len(p1), 5)
        p2 = db.get_channels(limit=5, offset=5, active_only=False)
        self.assertEqual(len(p2), 5)
        self.assertNotEqual(p1[0]["id"], p2[0]["id"])

    def test_15_subscriber_registration_and_key_linking(self):
        """Test user account registration with initial key binding."""
        initial_key = db.create_access_key(user_type="subscriber", customer_name="Tariq Khan", duration_days=30)
        with app.test_client() as client:
            reg_resp = client.post("/register", data={
                "username": "tariqfiber",
                "password": "fiberpassword123",
                "phone": "03001234567",
                "full_name": "Tariq Khan",
                "key_code": initial_key
            }, follow_redirects=True)
            self.assertEqual(reg_resp.status_code, 200)
            self.assertIn(b"Available Channels", reg_resp.data)

            # Check subscriber in DB
            sub = db.authenticate_subscriber("tariqfiber", "fiberpassword123")
            self.assertTrue(sub[0])
            self.assertEqual(sub[2]["active_key_code"], initial_key)

    def test_16_subscriber_login_and_key_restoration(self):
        """Test user login with auto-restoration of saved access key."""
        with app.test_client() as client:
            # Login as the subscriber created above
            login_resp = client.post("/user/login", data={
                "username": "tariqfiber",
                "password": "fiberpassword123"
            }, follow_redirects=True)
            self.assertEqual(login_resp.status_code, 200)
            self.assertIn(b"Welcome back, tariqfiber", login_resp.data)

            # Verify player is immediately accessible without re-entering key
            player_resp = client.get("/")
            self.assertEqual(player_resp.status_code, 200)
            self.assertIn(b"iptvVideo", player_resp.data)

    def test_17_subscriber_key_vault_and_topup(self):
        """Test visiting /my-account and topping up with a new key."""
        with app.test_client() as client:
            client.post("/user/login", data={
                "username": "tariqfiber",
                "password": "fiberpassword123"
            }, follow_redirects=True)

            vault_resp = client.get("/my-account")
            self.assertEqual(vault_resp.status_code, 200)
            self.assertIn(b"Key Vault", vault_resp.data)
            self.assertIn(b"tariqfiber", vault_resp.data)

            # Top up with a new renewal key
            renewal_key = db.create_access_key(user_type="subscriber", customer_name="Tariq Khan", duration_days=15)
            topup_resp = client.post("/my-account", data={
                "action": "link_key",
                "key_code": renewal_key
            }, follow_redirects=True)
            self.assertEqual(topup_resp.status_code, 200)

            # Check that the subscriber active key updated
            auth_ok, _, sub = db.authenticate_subscriber("tariqfiber", "fiberpassword123")
            self.assertTrue(auth_ok)
            self.assertEqual(sub["active_key_code"], renewal_key)

    def test_18_subscriber_registration_validation(self):
        """Test subscriber registration input validation (short user, duplicate user, short pass)."""
        # Short username
        ok, msg, _ = db.create_subscriber("ab", "password123")
        self.assertFalse(ok)
        self.assertIn("at least 3 characters", msg)

        # Short password
        ok, msg, _ = db.create_subscriber("validuser", "123")
        self.assertFalse(ok)
        self.assertIn("at least 6 characters", msg)

        # Duplicate username
        ok, msg, _ = db.create_subscriber("tariqfiber", "password123")
        self.assertFalse(ok)
        self.assertIn("already taken", msg)

    def test_19_automatic_key_to_credentials_generation(self):
        """Test putting key generates automatic username & password and unlocks TV immediately."""
        auto_key = db.create_access_key(user_type="subscriber", customer_name="Auto Key User", duration_days=30)
        with app.test_client() as client:
            resp = client.post("/activate", data={"key_code": auto_key}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Your Account Is Ready", resp.data)
            self.assertIn(b"Automatic Username", resp.data)
            self.assertIn(b"Automatic Password", resp.data)

            # Verify in DB that subscriber was auto-provisioned
            conn = db.get_db()
            row = conn.execute("SELECT * FROM subscribers WHERE UPPER(active_key_code) = ?", (auto_key.upper(),)).fetchone()
            conn.close()
            self.assertIsNotNone(row)
            self.assertTrue(row["username"].startswith("sabro_"))
            self.assertTrue(row["plain_password"].startswith("sabro"))

    def test_20_auto_credentials_login_and_key_vault(self):
        """Test logging in with the automatically generated username and password."""
        auto_key = db.create_access_key(user_type="subscriber", customer_name="Auto User 2", duration_days=30)
        success, msg, sub_data, is_new, gen_pass, _ = db.auto_provision_subscriber_from_key(auto_key)
        self.assertTrue(success)
        self.assertTrue(is_new)
        self.assertIsNotNone(gen_pass)

        # Login using the auto-generated username and password
        with app.test_client() as client:
            login_resp = client.post("/user/login", data={
                "username": sub_data["username"],
                "password": gen_pass
            }, follow_redirects=True)
            self.assertEqual(login_resp.status_code, 200)

            # Visit Key Vault (/my-account)
            vault_resp = client.get("/my-account")
            self.assertEqual(vault_resp.status_code, 200)
            self.assertIn(sub_data["username"].encode(), vault_resp.data)
            self.assertIn(gen_pass.encode(), vault_resp.data)
            self.assertIn(auto_key.encode(), vault_resp.data)

    def test_21_xtream_codes_handshake_authentication(self):
        """Verify Xtream-Codes API v2 handshake (/player_api.php)."""
        key = db.create_access_key(user_type="subscriber", customer_name="Xtream User", duration_days=30)
        success, msg, sub_data, _, gen_pass, _ = db.auto_provision_subscriber_from_key(key)
        self.assertTrue(success)

        with app.test_client() as client:
            # 1. Invalid credentials test
            bad_resp = client.get("/player_api.php?username=baduser&password=badpass")
            self.assertEqual(bad_resp.status_code, 200)
            bad_json = bad_resp.get_json()
            self.assertEqual(bad_json["user_info"]["auth"], 0)

            # 2. Valid credentials handshake
            good_resp = client.get(f"/player_api.php?username={sub_data['username']}&password={gen_pass}")
            self.assertEqual(good_resp.status_code, 200)
            good_json = good_resp.get_json()
            self.assertIn("user_info", good_json)
            self.assertIn("server_info", good_json)
            self.assertEqual(good_json["user_info"]["auth"], 1)
            self.assertEqual(good_json["user_info"]["status"], "Active")
            self.assertEqual(good_json["server_info"]["timezone"], "Asia/Karachi")

    def test_22_xtream_codes_categories_and_streams(self):
        """Verify Xtream-Codes category and stream discovery endpoints."""
        key = db.create_access_key(user_type="subscriber", customer_name="XC Streamer", duration_days=30)
        _, _, sub_data, _, gen_pass, _ = db.auto_provision_subscriber_from_key(key)

        with app.test_client() as client:
            # Categories endpoint
            cat_resp = client.get(f"/player_api.php?username={sub_data['username']}&password={gen_pass}&action=get_live_categories")
            self.assertEqual(cat_resp.status_code, 200)
            cats = cat_resp.get_json()
            self.assertIsInstance(cats, list)
            self.assertGreater(len(cats), 0)
            self.assertIn("category_name", cats[0])

            # Streams endpoint
            stream_resp = client.get(f"/player_api.php?username={sub_data['username']}&password={gen_pass}&action=get_live_streams")
            self.assertEqual(stream_resp.status_code, 200)
            streams = stream_resp.get_json()
            self.assertIsInstance(streams, list)
            self.assertGreater(len(streams), 0)
            self.assertIn("stream_id", streams[0])
            self.assertIn("stream_type", streams[0])

    def test_23_xtream_live_stream_redirect_and_event_log(self):
        """Verify /live/<user>/<pass>/<stream_id>.m3u8 redirects and logs connection."""
        key = db.create_access_key(user_type="subscriber", customer_name="Live Playback User", duration_days=30)
        _, _, sub_data, _, gen_pass, _ = db.auto_provision_subscriber_from_key(key)

        channels = db.get_channels(limit=1)
        self.assertGreater(len(channels), 0)
        ch_id = channels[0]["id"]
        target_url = channels[0]["stream_url"]

        with app.test_client() as client:
            resp = client.get(f"/live/{sub_data['username']}/{gen_pass}/{ch_id}.m3u8", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn(target_url, resp.headers["Location"])

            # Check that connection event was logged
            events = db.get_connection_events(limit=5)
            self.assertGreater(len(events), 0)
            matched = any(e["username"] == sub_data["username"] for e in events)
            self.assertTrue(matched)

    def test_24_dynamic_m3u_export(self):
        """Verify dynamic M3U export at /get.php for external players."""
        key = db.create_access_key(user_type="subscriber", customer_name="M3U Export User", duration_days=30)
        _, _, sub_data, _, gen_pass, _ = db.auto_provision_subscriber_from_key(key)

        with app.test_client() as client:
            resp = client.get(f"/get.php?username={sub_data['username']}&password={gen_pass}&type=m3u_plus&output=ts")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("audio/x-mpegurl", resp.content_type)
            body = resp.data.decode("utf-8")
            self.assertTrue(body.startswith("#EXTM3U"))
            self.assertIn("#EXTINF:", body)
            self.assertIn(f"/live/{sub_data['username']}/{gen_pass}/", body)

    def test_25_customer_management_with_pppoe_and_fat(self):
        """Verify admin customer management with decoupled Connect PPPoE hook & FAT mapping."""
        with app.test_client() as client:
            # Login admin
            client.post("/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"})

            # Add customer with PPPoE reference
            add_resp = client.post("/admin/customers/add", data={
                "username": "customer_kalakot_99",
                "password": "Password123!",
                "full_name": "Rahim Baloch",
                "phone": "03219988776",
                "pppoe_username": "connect_pppoe_99",
                "zone": "Kalakot Sector 4",
                "fat_id": "FAT-K-09",
                "package_id": 2,
                "duration_days": 30
            }, follow_redirects=True)
            self.assertEqual(add_resp.status_code, 200)
            self.assertIn(b"customer_kalakot_99", add_resp.data)
            self.assertIn(b"connect_pppoe_99", add_resp.data)
            self.assertIn(b"FAT-K-09", add_resp.data)

    def test_26_payment_receipt_workflow(self):
        """Verify payment receipt submission, admin review, and automatic subscription activation."""
        # Provision subscriber
        key = db.create_access_key(user_type="subscriber", customer_name="Payer User", duration_days=30)
        _, _, sub_data, _, gen_pass, _ = db.auto_provision_subscriber_from_key(key)

        with app.test_client() as client:
            # Subscriber submits payment receipt
            client.post("/user/login", data={"username": sub_data["username"], "password": gen_pass})
            sub_resp = client.post("/payment/submit", data={
                "package_id": 2,
                "amount": "300",
                "payment_method": "EasyPaisa",
                "transaction_id": "EP-TRX-100234",
                "sender_account": "0312-3344556",
                "notes": "Sports package monthly"
            }, follow_redirects=True)
            self.assertEqual(sub_resp.status_code, 200)
            self.assertIn(b"submitted successfully", sub_resp.data)

            # Admin checks queue and approves
            client.post("/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"})
            payments_page = client.get("/admin/payments")
            self.assertEqual(payments_page.status_code, 200)
            self.assertIn(b"EP-TRX-100234", payments_page.data)

            # Get receipt ID from database
            pending = db.get_payment_receipts(status="pending")
            receipt = next((r for r in pending if r["transaction_ref"] == "EP-TRX-100234"), None)
            self.assertIsNotNone(receipt)

            # Admin approves
            appr_resp = client.post(f"/admin/payments/approve/{receipt['id']}", follow_redirects=True)
            self.assertEqual(appr_resp.status_code, 200)
            self.assertIn(b"Payment approved and subscription automatically activated", appr_resp.data)

            # Verify subscription is updated
            sub = db.get_subscriber_subscription(sub_data["id"])
            self.assertIsNotNone(sub)
            self.assertEqual(sub["package_id"], 2)

    def test_27_tiered_packages_and_audit_log(self):
        """Verify tiered packages exist and audit logging records actions."""
        packages = db.get_packages()
        self.assertGreaterEqual(len(packages), 5)
        pkg_names = [p["name"] for p in packages]
        self.assertIn("Basic Fiber Pass", pkg_names)
        self.assertIn("Sports & News Pass", pkg_names)
        self.assertIn("VIP Premium Cinema Pass", pkg_names)

        with app.test_client() as client:
            client.post("/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"})
            audit_page = client.get("/admin/audit")
            self.assertEqual(audit_page.status_code, 200)
            self.assertIn(b"Audit Trail", audit_page.data)
            self.assertIn(b"ahmedbaloch", audit_page.data)

    def test_28_smart_tv_webapp_and_pwa(self):
        """Verify Smart TV Leanback WebApp (/tv) and Mobile PWA manifest & service worker."""
        with app.test_client() as client:
            # 1. Unauthenticated /tv redirects to gatekeeper
            tv_unauth = client.get("/tv", follow_redirects=False)
            self.assertEqual(tv_unauth.status_code, 302)
            self.assertIn("/gatekeeper", tv_unauth.headers["Location"])

            # 2. Authenticated /tv access with valid key
            key = db.create_access_key(user_type="subscriber", customer_name="TV User", duration_days=30)
            client.post("/activate", data={"key_code": key})
            tv_resp = client.get("/tv")
            self.assertEqual(tv_resp.status_code, 200)
            self.assertIn(b"SMART TV LEANBACK", tv_resp.data)
            self.assertIn(b"tv_nav.js", tv_resp.data)

            # 3. PWA Manifest endpoint
            man_resp = client.get("/manifest.json")
            self.assertEqual(man_resp.status_code, 200)
            man_json = man_resp.get_json()
            self.assertEqual(man_json["short_name"], "Sabro Vision")
            self.assertEqual(man_json["display"], "standalone")

            # 4. Service Worker endpoint
            sw_resp = client.get("/sw.js")
            self.assertEqual(sw_resp.status_code, 200)
            self.assertIn(b"sabro-vision-v1", sw_resp.data)

    def test_29_channel_health_diagnostics_and_filtering(self):
        """Verify stream health diagnostics, single test API, and admin health dashboard."""
        channels = db.get_channels(limit=1)
        self.assertGreater(len(channels), 0)
        ch_id = channels[0]["id"]

        with app.test_client() as client:
            # 1. Test single channel API
            test_resp = client.get(f"/api/test-channel/{ch_id}")
            self.assertEqual(test_resp.status_code, 200)
            data = test_resp.get_json()
            self.assertIn("status", data)
            self.assertIn("latency_ms", data)
            self.assertIn(data["status"], ("online", "offline", "slow"))

            # 2. Health summary function in DB
            summary = db.get_channel_health_summary()
            self.assertIsInstance(summary, dict)
            self.assertIn("total", summary)
            self.assertIn("online", summary)
            self.assertGreater(summary["total"], 0)

            # 3. Admin Stream Health Center
            client.post("/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"})
            health_page = client.get("/admin/channels/health")
            self.assertEqual(health_page.status_code, 200)
            self.assertIn(b"Stream Health", health_page.data)
            self.assertIn(b"Total Catalog", health_page.data)

            # 4. Admin Toggle Offline Channels
            toggle_resp = client.post("/admin/channels/toggle-offline", data={"action": "disable"}, follow_redirects=True)
            self.assertEqual(toggle_resp.status_code, 200)
            self.assertIn(b"Successfully deactivated", toggle_resp.data)

    def test_30_tiered_package_category_isolation(self):
        """Verify 100% channel access control per package: All-Access Master VIP vs Standalone Comedy/Sports."""
        # 1. Verify packages exist in database
        packages = db.get_packages(active_only=False)
        pkg_codes = [p["code"] for p in packages]
        self.assertIn("master_vip", pkg_codes)
        self.assertIn("pkg_comedy", pkg_codes)
        self.assertIn("pkg_sports", pkg_codes)

        comedy_pkg = next(p for p in packages if p["code"] == "pkg_comedy")
        sports_pkg = next(p for p in packages if p["code"] == "pkg_sports")
        master_pkg = next(p for p in packages if p["code"] == "master_vip")

        # 2. Add test channels for Comedy and Sports
        comedy_ch_id = db.add_channel(name="Comedy Central Test", stream_url="https://example.com/comedy.m3u8", category="Comedy")
        sports_ch_id = db.add_channel(name="Super Sports Test", stream_url="https://example.com/sports.m3u8", category="Sports")
        comedy_ch = db.get_channel_by_id(comedy_ch_id)
        sports_ch = db.get_channel_by_id(sports_ch_id)

        # 3. Create access key for Comedy standalone package
        comedy_key = db.create_access_key(user_type="subscriber", customer_name="Comedy Lover", package_id=comedy_pkg["id"])
        
        # 4. Test DB access helper
        self.assertTrue(db.can_subscriber_access_channel(key_code=comedy_key, channel_obj=comedy_ch))
        self.assertFalse(db.can_subscriber_access_channel(key_code=comedy_key, channel_obj=sports_ch))

        # 5. Test Master VIP key access (All-Access)
        master_key = db.create_access_key(user_type="subscriber", customer_name="Master VIP User", package_id=master_pkg["id"])
        self.assertTrue(db.can_subscriber_access_channel(key_code=master_key, channel_obj=comedy_ch))
        self.assertTrue(db.can_subscriber_access_channel(key_code=master_key, channel_obj=sports_ch))

        with app.test_client() as client:
            # 6. Activate Comedy key and test web access isolation
            act_resp = client.post("/activate", data={"key_code": comedy_key}, follow_redirects=True)
            self.assertEqual(act_resp.status_code, 200)

            # Channels page: categories should only include Comedy
            home_resp = client.get("/")
            self.assertEqual(home_resp.status_code, 200)
            self.assertIn(b"Comedy Central Test", home_resp.data)
            self.assertNotIn(b"Super Sports Test", home_resp.data)

            # TV player: only Comedy
            tv_resp = client.get("/tv")
            self.assertEqual(tv_resp.status_code, 200)
            self.assertIn(b"Comedy Central Test", tv_resp.data)
            self.assertNotIn(b"Super Sports Test", tv_resp.data)

            # Watching outside package: redirects to /my-account with lock alert
            watch_denied = client.get(f"/watch/{sports_ch_id}", follow_redirects=False)
            self.assertEqual(watch_denied.status_code, 302)
            self.assertIn("/my-account", watch_denied.headers["Location"])

            # Streaming outside package: HTTP 403 Forbidden
            stream_denied = client.get(f"/stream/{sports_ch_id}")
            self.assertEqual(stream_denied.status_code, 403)
            self.assertIn(b"Package upgrade required", stream_denied.data)

            # 7. Test Xtream Codes API isolation
            # Get provisioned credentials
            krow = db.validate_key(comedy_key)[2]
            sub = db.get_db().execute("SELECT * FROM subscribers WHERE active_key_code = ?", (comedy_key,)).fetchone()
            xc_user = sub["username"]
            xc_pass = sub["plain_password"]

            # Xtream Categories: only Comedy category
            xc_cats = client.get(f"/player_api.php?username={xc_user}&password={xc_pass}&action=get_live_categories")
            self.assertEqual(xc_cats.status_code, 200)
            cat_names = [c["category_name"] for c in xc_cats.get_json()]
            self.assertIn("Comedy", cat_names)
            self.assertNotIn("Sports", cat_names)

            # Xtream Streams: only Comedy streams
            xc_streams = client.get(f"/player_api.php?username={xc_user}&password={xc_pass}&action=get_live_streams")
            self.assertEqual(xc_streams.status_code, 200)
            stream_names = [s["name"] for s in xc_streams.get_json()]
            self.assertIn("Comedy Central Test", stream_names)
            self.assertNotIn("Super Sports Test", stream_names)

            # Live Stream unauthorized: HTTP 403
            xc_live_denied = client.get(f"/live/{xc_user}/{xc_pass}/{sports_ch_id}.m3u8")
            self.assertEqual(xc_live_denied.status_code, 403)

            # M3U Playlist: only Comedy channel
            m3u_resp = client.get(f"/get.php?username={xc_user}&password={xc_pass}")
            self.assertEqual(m3u_resp.status_code, 200)
            self.assertIn(b"Comedy Central Test", m3u_resp.data)
            self.assertNotIn(b"Super Sports Test", m3u_resp.data)

            # 8. Packages public page gives 200 and lists tiers
            pkg_page = client.get("/packages")
            self.assertEqual(pkg_page.status_code, 200)
            self.assertIn(b"Sabro All-Access Master VIP", pkg_page.data)
            self.assertIn(b"Sabro Comedy Club Pass", pkg_page.data)
            self.assertIn(b"Sabro Sports Elite Pass", pkg_page.data)

if __name__ == "__main__":
    unittest.main()
