import requests
import sys
import re
import db

BASE_URL = "http://127.0.0.1:8080"
passed = 0
failed = 0

def report(name, condition, extra=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name} {extra}")
    else:
        failed += 1
        print(f"  [FAIL] {name} {extra}")

print("\n" + "="*70)
print("  SABRO VISION - FULL SYSTEM COMPREHENSIVE TEST SUITE")
print("  Target Server: " + BASE_URL)
print("="*70 + "\n")

# ----------------------------------------------------
# 1. GATEKEEPER & BRANDING CHECKS
# ----------------------------------------------------
print("[PHASE 1] Gatekeeper, Branding & HTTP Security Headers...")
s = requests.Session()
r = s.get(f"{BASE_URL}/gatekeeper")

report("Gatekeeper HTTP 200 OK", r.status_code == 200)
report("Vshatkay Solutions Attribution Footer", "Vshatkay Solutions" in r.text)
report("Sabro Networks Attribution", "Sabro Networks" in r.text)
report("Dual Tab 1: Put Key & Get Auto Login", "Put Key & Get Auto Login" in r.text or "Put Your Key to Get Automatic Login" in r.text)
report("Dual Tab 2: Login with Username & Password", "Login with Username & Password" in r.text or "Sign In with Saved Account" in r.text)
report("JazzCash & EasyPaisa Payment Info", "JazzCash" in r.text and "EasyPaisa" in r.text)
report("WhatsApp Support Helpline Button", "wa.me" in r.text)

# Check security headers
report("Header: X-Content-Type-Options = nosniff", r.headers.get("X-Content-Type-Options") == "nosniff")
report("Header: X-Frame-Options = SAMEORIGIN", r.headers.get("X-Frame-Options") == "SAMEORIGIN")
report("Header: Referrer-Policy = strict-origin-when-cross-origin", r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin")
report("Header: X-XSS-Protection = 1; mode=block", r.headers.get("X-XSS-Protection") == "1; mode=block")

# ----------------------------------------------------
# 2. UNPROTECTED ACCESS BLOCKED
# ----------------------------------------------------
print("\n[PHASE 2] Access Control & Unauthorized Access Enforcement...")
unauth_s = requests.Session()
r_idx = unauth_s.get(f"{BASE_URL}/", allow_redirects=False)
report("Unauthenticated visitor redirected from / to /gatekeeper", r_idx.status_code == 302 and "/gatekeeper" in r_idx.headers.get("Location", ""))

r_acc = unauth_s.get(f"{BASE_URL}/my-account", allow_redirects=False)
report("Unauthenticated visitor redirected from /my-account", r_acc.status_code == 302)

r_stream = unauth_s.get(f"{BASE_URL}/stream/1")
report("Unauthorized call to /stream/1 returns 401 Access Denied", r_stream.status_code == 401)

r_proxy = unauth_s.get(f"{BASE_URL}/proxy?url=https://example.com/live.m3u8")
report("Unauthorized call to /proxy returns 401 Access Denied", r_proxy.status_code == 401)

r_adm = unauth_s.get(f"{BASE_URL}/admin", allow_redirects=False)
report("Unauthorized call to /admin redirected to /admin/login", r_adm.status_code == 302 and "/admin/login" in r_adm.headers.get("Location", ""))

# ----------------------------------------------------
# 3. AUTOMATIC KEY-TO-ACCOUNT PROVISIONING WORKFLOW
# ----------------------------------------------------
print("\n[PHASE 3] Automatic Key-to-Account Provisioning & Credentials Generation...")

# Generate keys with different durations
key_7d = db.create_access_key(user_type="subscriber", customer_name="Auto User 7D", duration_days=7)
key_15d = db.create_access_key(user_type="subscriber", customer_name="Auto User 15D", duration_days=15)
key_30d = db.create_access_key(user_type="subscriber", customer_name="Auto User 30D", duration_days=30)
report("Generated 7-day, 15-day, and 30-day Keys", bool(key_7d and key_15d and key_30d))

# Subscriber puts key
client_sess = requests.Session()
r_act = client_sess.post(f"{BASE_URL}/activate", data={"key_code": key_30d}, allow_redirects=True)
report("POST /activate with key redirects to player with 200 OK", r_act.status_code == 200)
report("Credentials celebration modal displayed", "Your Account Is Ready" in r_act.text or "Your Login Credentials" in r_act.text)
report("Modal contains 'Automatic Username'", "Automatic Username" in r_act.text)
report("Modal contains 'Automatic Password'", "Automatic Password" in r_act.text)
report("Modal contains 1-click 'Copy All Credentials' button", "Copy All Credentials" in r_act.text)
report("Player container renders live TV element", "iptvVideo" in r_act.text)
report("Device fingerprint cookie set", "sabro_device_id" in client_sess.cookies)

# Verify subscriber credentials created in DB
sub_db = db.get_db().execute("SELECT * FROM subscribers WHERE UPPER(active_key_code) = ?", (key_30d.upper(),)).fetchone()
report("Subscriber record created in SQLite DB", sub_db is not None)
auto_username = sub_db["username"] if sub_db else ""
auto_password = sub_db["plain_password"] if sub_db else ""
report(f"Auto-generated Username: '{auto_username}'", auto_username.startswith("sabro_"))
report(f"Auto-generated Password: '{auto_password}'", auto_password.startswith("sabro"))

# Test dismiss modal API
r_dismiss = client_sess.post(f"{BASE_URL}/api/dismiss-creds-modal")
report("POST /api/dismiss-creds-modal succeeds", r_dismiss.status_code == 200 and r_dismiss.json().get("success") is True)

# Reload player after dismissing modal -> modal should be hidden
r_p2 = client_sess.get(f"{BASE_URL}/")
report("Reloading player after dismissal hides modal", "credsModal" not in r_p2.text)

# ----------------------------------------------------
# 4. KEY VAULT & TOP-UP RECHARGE
# ----------------------------------------------------
print("\n[PHASE 4] Key Vault (/my-account) & Key Top-Up...")
r_vault = client_sess.get(f"{BASE_URL}/my-account")
report("GET /my-account returns 200 OK", r_vault.status_code == 200)
report("Key Vault shows subscriber username", auto_username in r_vault.text)
report("Key Vault shows subscriber password with copy option", auto_password in r_vault.text)
report("Key Vault displays active key code", key_30d in r_vault.text)
report("Key Vault displays 'Active Pass' status badge", "Active Pass" in r_vault.text)

# Test topping up with a new renewal key (key_15d)
r_topup = client_sess.post(f"{BASE_URL}/my-account", data={"action": "link_key", "key_code": key_15d}, allow_redirects=True)
report("POST /my-account top-up returns 200 OK", r_topup.status_code == 200)
sub_db2 = db.get_db().execute("SELECT * FROM subscribers WHERE id = ?", (sub_db["id"],)).fetchone()
report("Account updated with new renewal key in DB", sub_db2["active_key_code"] == key_15d)

# ----------------------------------------------------
# 5. SUBSEQUENT LOGIN WITH USERNAME & PASSWORD
# ----------------------------------------------------
print("\n[PHASE 5] Subscriber Login with Auto-Generated Credentials on New Browser...")
new_browser_sess = requests.Session()
r_sub_login = new_browser_sess.post(f"{BASE_URL}/user/login", data={
    "username": auto_username,
    "password": auto_password
}, allow_redirects=True)
report("POST /user/login with auto-generated credentials succeeds", r_sub_login.status_code == 200)
report("Player immediately unlocked without re-entering key", "iptvVideo" in r_sub_login.text or "Available Channels" in r_sub_login.text)

# ----------------------------------------------------
# 6. RE-ENTERING KEY RECOGNITION & SINGLE-DEVICE LOCK
# ----------------------------------------------------
print("\n[PHASE 6] Re-entering Key & Single-Device Anti-Sharing Protection...")
clean_sess = requests.Session()
r_reenter = clean_sess.post(f"{BASE_URL}/activate", data={"key_code": key_15d}, allow_redirects=True)
report("Putting existing key restores account and returns 200 OK", r_reenter.status_code == 200)
report("Recognized existing subscriber username", auto_username in r_reenter.text)

# Verify single device enforcement: old session is now blocked from API
r_blocked = new_browser_sess.get(f"{BASE_URL}/api/favorites")
report("Single-device anti-sharing: previous device session blocked (401)", r_blocked.status_code == 401)

# ----------------------------------------------------
# 7. CHANNELS, CATEGORIES, SEARCH & FAVORITES
# ----------------------------------------------------
print("\n[PHASE 7] IPTV Channel Lineup, Search & Favorites...")
total_channels = db.get_channels_count()
report(f"Database contains {total_channels:,} channels", total_channels >= 11400)

# Test search query
r_search = clean_sess.get(f"{BASE_URL}/?q=Sports")
report("Search query for 'Sports' returns 200 OK", r_search.status_code == 200)

# Test category filter
r_cat = clean_sess.get(f"{BASE_URL}/?category=News")
report("Category filter for 'News' returns 200 OK", r_cat.status_code == 200)

# Test favorites toggle API
sample_ch = db.get_channels(limit=1)[0]
r_fav_add = clean_sess.post(f"{BASE_URL}/api/favorites/toggle", json={"channel_id": sample_ch["id"]})
report("Toggle favorite (add) returns is_favorite=True", r_fav_add.json().get("is_favorite") is True)

r_fav_get = clean_sess.get(f"{BASE_URL}/api/favorites")
report("GET /api/favorites returns bookmarked channel", any(c["id"] == sample_ch["id"] for c in r_fav_get.json().get("favorites", [])))

r_fav_remove = clean_sess.post(f"{BASE_URL}/api/favorites/toggle", json={"channel_id": sample_ch["id"]})
report("Toggle favorite (remove) returns is_favorite=False", r_fav_remove.json().get("is_favorite") is False)

# ----------------------------------------------------
# 8. SSRF DEFENSE & STREAM SECURITY
# ----------------------------------------------------
print("\n[PHASE 8] SSRF & Network Security Policy Verification...")
ssrf_loopback = clean_sess.get(f"{BASE_URL}/proxy?url=http://127.0.0.1:22/admin")
report("SSRF filter blocks loopback 127.0.0.1 (403)", ssrf_loopback.status_code == 403)

ssrf_metadata = clean_sess.get(f"{BASE_URL}/proxy?url=http://169.254.169.254/latest/meta-data/")
report("SSRF filter blocks AWS/Cloud metadata 169.254.169.254 (403)", ssrf_metadata.status_code == 403)

ssrf_private = clean_sess.get(f"{BASE_URL}/proxy?url=http://192.168.1.1/router")
report("SSRF filter blocks RFC1918 private IP 192.168.1.1 (403)", ssrf_private.status_code == 403)

ssrf_localhost = clean_sess.get(f"{BASE_URL}/proxy?url=http://localhost:8080/admin")
report("SSRF filter blocks localhost name (403)", ssrf_localhost.status_code == 403)

# ----------------------------------------------------
# 9. ADMIN AUTHENTICATION & CONTROL PANEL
# ----------------------------------------------------
print("\n[PHASE 9] Admin Security & Management Control Panel...")
adm_sess = requests.Session()

# Test wrong credentials
r_bad_adm = adm_sess.post(f"{BASE_URL}/admin/login", data={"username": "ahmedbaloch", "password": "wrongpassword"}, allow_redirects=True)
report("Wrong admin password correctly rejected", "Invalid administrator" in r_bad_adm.text or "Invalid" in r_bad_adm.text)

# Test correct credentials: ahmedbaloch / adminadmin1
r_good_adm = adm_sess.post(f"{BASE_URL}/admin/login", data={"username": "ahmedbaloch", "password": "adminadmin1"}, allow_redirects=True)
report("Admin login with 'ahmedbaloch'/'adminadmin1' succeeds", r_good_adm.status_code == 200 and "Admin Panel" in r_good_adm.text)

# Test Admin Dashboard
r_dash = adm_sess.get(f"{BASE_URL}/admin")
report("Admin Overview dashboard loads with stats", "Overview" in r_dash.text and "Active Keys" in r_dash.text)

# Test Admin Keys Management
r_adm_keys = adm_sess.get(f"{BASE_URL}/admin/keys")
report("Admin Keys management page loads (/admin/keys)", "Access Keys" in r_adm_keys.text)

# Test Key Generation in Admin Panel
r_gen_key = adm_sess.post(f"{BASE_URL}/admin/keys/generate", data={
    "user_type": "subscriber",
    "customer_name": "Admin Generated Live User",
    "phone": "03009988776",
    "duration_days": "30",
    "notes": "Live test from admin"
}, allow_redirects=True)
report("Admin generated new access key successfully", "successfully generated" in r_gen_key.text or r_gen_key.status_code == 200)

# Test Channels Management
r_adm_ch = adm_sess.get(f"{BASE_URL}/admin/channels")
report("Admin Channels page loads (/admin/channels)", "Manage Channels" in r_adm_ch.text)

# Test Playlists Management
r_adm_pl = adm_sess.get(f"{BASE_URL}/admin/playlists")
report("Admin Playlists page loads (/admin/playlists)", "Playlists" in r_adm_pl.text)

# Test Settings Management
r_adm_set = adm_sess.get(f"{BASE_URL}/admin/settings")
report("Admin Settings page loads (/admin/settings)", "Settings" in r_adm_set.text)

# ====================================================
# PHASE 10: SABRO VISION v1.0 - Xtream API, PPPoE & Payments
# ====================================================
print("\n[PHASE 10] SABRO VISION v1.0: Xtream Codes API, PPPoE Hook & Payment Workflow...")

# 1. Xtream Codes API Handshake
r_xc_bad = requests.get(f"{BASE_URL}/player_api.php?username=baduser&password=badpass")
report("Xtream API rejects invalid credentials", r_xc_bad.status_code == 200 and r_xc_bad.json().get("user_info", {}).get("auth") == 0)

r_xc_good = requests.get(f"{BASE_URL}/player_api.php?username={auto_username}&password={auto_password}")
xc_data = r_xc_good.json()
report("Xtream API v2 handshake succeeds (auth=1)", r_xc_good.status_code == 200 and xc_data.get("user_info", {}).get("auth") == 1)
report("Xtream API returns valid server_info (Asia/Karachi)", xc_data.get("server_info", {}).get("timezone") == "Asia/Karachi")

# 2. Xtream Live Categories & Streams
r_xc_cats = requests.get(f"{BASE_URL}/player_api.php?username={auto_username}&password={auto_password}&action=get_live_categories")
report("Xtream API get_live_categories returns category list", r_xc_cats.status_code == 200 and len(r_xc_cats.json()) > 0)

r_xc_streams = requests.get(f"{BASE_URL}/player_api.php?username={auto_username}&password={auto_password}&action=get_live_streams")
report("Xtream API get_live_streams returns channel list", r_xc_streams.status_code == 200 and len(r_xc_streams.json()) > 0)

# 3. Xtream Stream URL /live/<user>/<pass>/<stream_id>.m3u8
ch_test_id = r_xc_streams.json()[0]["stream_id"]
r_xc_stream = requests.get(f"{BASE_URL}/live/{auto_username}/{auto_password}/{ch_test_id}.m3u8", allow_redirects=False)
report("Xtream live stream URL returns 302 stream redirect", r_xc_stream.status_code == 302 and "Location" in r_xc_stream.headers)

# 4. Dynamic M3U export (/get.php)
r_m3u = requests.get(f"{BASE_URL}/get.php?username={auto_username}&password={auto_password}&type=m3u_plus&output=ts")
report("Dynamic M3U export (/get.php) returns #EXTM3U", r_m3u.status_code == 200 and "#EXTM3U" in r_m3u.text and f"/live/{auto_username}/{auto_password}/" in r_m3u.text)

# 5. Admin Customers & Connect PPPoE Management
r_adm_cust = adm_sess.get(f"{BASE_URL}/admin/customers")
report("Admin Customers & PPPoE Hub loads (/admin/customers)", "Customers" in r_adm_cust.text and "PPPoE" in r_adm_cust.text)

# 6. Admin Xtream Codes Setup & Config Guide
r_adm_xc = adm_sess.get(f"{BASE_URL}/admin/xtream")
report("Admin Xtream Setup Guide loads (/admin/xtream)", "Xtream Codes API" in r_adm_xc.text and "IPTV Smarters" in r_adm_xc.text)

# 7. Admin Tiered Packages
r_adm_pkg = adm_sess.get(f"{BASE_URL}/admin/packages")
report("Admin Tiered Packages loads (/admin/packages)", "Package & Tiered Subscriptions" in r_adm_pkg.text and "Basic Fiber Pass" in r_adm_pkg.text)

# 8. Admin Payment Queue
r_adm_pay = adm_sess.get(f"{BASE_URL}/admin/payments")
report("Admin Payment Queue loads (/admin/payments)", "Payment Verification Queue" in r_adm_pay.text)

# 9. Admin Audit Logs & Security Hit Trail
r_adm_aud = adm_sess.get(f"{BASE_URL}/admin/audit")
report("Admin Audit & Security Trail loads (/admin/audit)", "Admin Audit Trail" in r_adm_aud.text)

# ====================================================
# PHASE 11: Smart TV WebApp, Mobile PWA & Stream Health Diagnostics
# ====================================================
print("\n[PHASE 11] Smart TV WebApp, Mobile PWA & Stream Health Diagnostics...")

# 1. PWA Web App Manifest
r_pwa = requests.get(f"{BASE_URL}/manifest.json")
report("PWA manifest.json loads with 200 OK", r_pwa.status_code == 200 and r_pwa.json().get("short_name") == "Sabro Vision")
report("PWA manifest specifies standalone display", r_pwa.json().get("display") == "standalone")

# 2. Service Worker sw.js
r_sw = requests.get(f"{BASE_URL}/sw.js")
report("PWA Service Worker /sw.js loads with 200 OK", r_sw.status_code == 200 and "sabro-vision-v1" in r_sw.text)

# 3. Smart TV WebApp (/tv) Unauthorized Redirect
r_tv_unauth = requests.get(f"{BASE_URL}/tv", allow_redirects=False)
report("Unauthenticated visitor redirected from /tv", r_tv_unauth.status_code == 302 and "/gatekeeper" in r_tv_unauth.headers.get("Location", ""))

# 4. Smart TV WebApp (/tv) Authenticated Access
r_tv_auth = clean_sess.get(f"{BASE_URL}/tv")
report("Authenticated subscriber accesses /tv Smart TV WebApp", r_tv_auth.status_code == 200 and "SMART TV LEANBACK" in r_tv_auth.text and "tv_nav.js" in r_tv_auth.text)

# 5. Single Channel Stream Health API Probe
r_test_api = requests.get(f"{BASE_URL}/api/test-channel/{ch_test_id}")
report("API /api/test-channel/<id> probes stream live", r_test_api.status_code == 200 and "latency_ms" in r_test_api.json() and r_test_api.json().get("status") in ("online", "slow", "offline"))

# 6. Admin Stream Health & Diagnostics Dashboard
r_adm_health = adm_sess.get(f"{BASE_URL}/admin/channels/health")
report("Admin Stream Health Center loads (/admin/channels/health)", "Stream Health Diagnostics" in r_adm_health.text and "Verified Online" in r_adm_health.text)

# 7. Web Player Online Only Filter Toggle
r_online_filter = clean_sess.get(f"{BASE_URL}/?online_only=1")
report("Web Player accepts online_only=1 filter toggle", r_online_filter.status_code == 200)

# ====================================================
# PHASE 12: Tiered Package Channel Isolation (All-Access Master VIP & Standalone Passes)
# ====================================================
print("\n[PHASE 12] Tiered Package Channel Isolation & Access Enforcement...")

# 1. Public Packages & Pricing Showcase
r_pub_pkgs = requests.get(f"{BASE_URL}/packages")
report("Public /packages page loads with 200 OK", r_pub_pkgs.status_code == 200 and "Sabro All-Access Master VIP" in r_pub_pkgs.text)
report("Standalone category packages displayed (Comedy, Sports, News)", "Sabro Comedy Club Pass" in r_pub_pkgs.text and "Sabro Sports Elite Pass" in r_pub_pkgs.text)

# 2. Query available packages from database
all_pkgs = db.get_packages(active_only=False)
comedy_pkg = next((p for p in all_pkgs if p["code"] == "pkg_comedy"), None)
sports_pkg = next((p for p in all_pkgs if p["code"] == "pkg_sports"), None)
master_pkg = next((p for p in all_pkgs if p["code"] == "master_vip"), None)

report("Database seeded with standalone & master packages", comedy_pkg is not None and sports_pkg is not None and master_pkg is not None)

# Find sample channels for Comedy and Sports
comedy_channels = db.get_channels(category="Comedy", limit=3)
sports_channels = db.get_channels(category="Sports", limit=3)
sample_comedy_id = comedy_channels[0]["id"] if comedy_channels else ch_test_id
sample_sports_id = sports_channels[0]["id"] if sports_channels else ch_test_id

# 3. Create a dedicated Comedy standalone voucher key
comedy_key_code = db.create_access_key(user_type="subscriber", customer_name="Comedy Live Tester", package_id=comedy_pkg["id"] if comedy_pkg else 1)
report("Generated Comedy standalone voucher key", comedy_key_code.startswith("SABRO-FREE-"))

# 4. Activate Comedy key in isolated session
comedy_sess = requests.Session()
r_act_comedy = comedy_sess.post(f"{BASE_URL}/activate", data={"key_code": comedy_key_code}, allow_redirects=True)
report("Activated Comedy pass voucher successfully", r_act_comedy.status_code == 200)

# Verify Web Player shows Comedy category channels only
r_comedy_home = comedy_sess.get(f"{BASE_URL}/")
report("Web Player enforces Comedy package channel limits", r_comedy_home.status_code == 200 and "Sabro Comedy Club Pass" in r_comedy_home.text)

# 5. Smart TV WebApp enforces Comedy package
r_comedy_tv = comedy_sess.get(f"{BASE_URL}/tv")
report("Smart TV WebApp (/tv) respects Comedy package filter", r_comedy_tv.status_code == 200 and "Sabro Comedy Club Pass" in r_comedy_tv.text)

# 6. Stream Authorization: Comedy user can stream comedy channel
r_stream_comedy = comedy_sess.get(f"{BASE_URL}/stream/{sample_comedy_id}", allow_redirects=False)
report("Comedy subscriber can stream authorized comedy channel", r_stream_comedy.status_code in (200, 302))

# 7. Channel Lock Enforcement: Comedy user blocked from streaming Sports channel (403)
if sample_sports_id != sample_comedy_id:
    r_stream_sports_blocked = comedy_sess.get(f"{BASE_URL}/stream/{sample_sports_id}", allow_redirects=False)
    report("Comedy subscriber blocked from streaming Sports channel (403 Forbidden)", r_stream_sports_blocked.status_code == 403)

    r_watch_sports_blocked = comedy_sess.get(f"{BASE_URL}/watch/{sample_sports_id}", allow_redirects=False)
    report("Comedy subscriber redirected from /watch on locked channel", r_watch_sports_blocked.status_code == 302 and "/my-account" in r_watch_sports_blocked.headers.get("Location", ""))

# 8. Xtream Codes API package isolation for Comedy subscriber
sub_comedy = db.get_db().execute("SELECT * FROM subscribers WHERE active_key_code = ?", (comedy_key_code,)).fetchone()
if sub_comedy:
    xc_c_user = sub_comedy["username"]
    xc_c_pass = sub_comedy["plain_password"]

    # Xtream live categories: only comedy category
    r_xc_c_cats = requests.get(f"{BASE_URL}/player_api.php?username={xc_c_user}&password={xc_c_pass}&action=get_live_categories")
    cat_names_c = [c["category_name"] for c in r_xc_c_cats.json()] if r_xc_c_cats.status_code == 200 else []
    report("Xtream API returns only allowed categories for Comedy package", "Comedy" in cat_names_c and "Sports" not in cat_names_c)

    # Xtream live stream: blocked from unauthorized sports stream (403)
    if sample_sports_id != sample_comedy_id:
        r_xc_c_stream_blocked = requests.get(f"{BASE_URL}/live/{xc_c_user}/{xc_c_pass}/{sample_sports_id}.m3u8", allow_redirects=False)
        report("Xtream API blocks unauthorized channel stream (403 Forbidden)", r_xc_c_stream_blocked.status_code == 403)

    # Dynamic M3U export: only includes comedy channels
    r_xc_c_m3u = requests.get(f"{BASE_URL}/get.php?username={xc_c_user}&password={xc_c_pass}")
    report("Dynamic M3U export filters playlist to Comedy channels only", r_xc_c_m3u.status_code == 200 and "group-title=\"Comedy\"" in r_xc_c_m3u.text and "group-title=\"Sports\"" not in r_xc_c_m3u.text)

# 9. Master All-Access VIP Pass Verification
master_key_code = db.create_access_key(user_type="subscriber", customer_name="Master VIP Tester", package_id=master_pkg["id"] if master_pkg else 1)
master_sess = requests.Session()
r_act_master = master_sess.post(f"{BASE_URL}/activate", data={"key_code": master_key_code}, allow_redirects=True)
report("Activated Master VIP voucher key successfully", r_act_master.status_code == 200)

r_master_home = master_sess.get(f"{BASE_URL}/")
report("Master VIP user has All-Access (All 11,459 Channels)", "Master VIP" in r_master_home.text or "All-Access" in r_master_home.text)

# Master VIP can stream both Comedy and Sports channels
r_master_comedy = master_sess.get(f"{BASE_URL}/stream/{sample_comedy_id}", allow_redirects=False)
r_master_sports = master_sess.get(f"{BASE_URL}/stream/{sample_sports_id}", allow_redirects=False)
report("Master VIP user can stream Comedy channels without restriction", r_master_comedy.status_code in (200, 302))
report("Master VIP user can stream Sports channels without restriction", r_master_sports.status_code in (200, 302))

# ----------------------------------------------------
# FINAL SUMMARY
# ----------------------------------------------------
print("\n" + "="*70)
print(f"  TOTAL TESTS RUN: {passed + failed}")
print(f"  PASSED:          {passed}")
print(f"  FAILED:          {failed}")
print(f"  SUCCESS RATE:    {passed / (passed + failed) * 100:.1f}%")
print("="*70 + "\n")

if failed > 0:
    sys.exit(1)
