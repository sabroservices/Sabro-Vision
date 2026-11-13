import os
import secrets
import hmac
import hashlib
import time
import urllib.parse
import re
import csv
import io
import uuid
import socket
import ipaddress
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, Response, jsonify, send_file, make_response, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

import db
import seeds
import iptv_parser
import isp_integration
import payment_gateway
from flask import g

app = Flask(__name__)
app.url_map.strict_slashes = False
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Ensure DB schema and initial seeds are ready (works for both run.py and gunicorn app:app)
seeds.seed_database(force_reset=False)

# Bootstrap multi-layer persistence (restores vault state from disk across restarts)
import data_vault
data_vault.bootstrap_persistence()

APP_START_TIME = datetime.now()

@app.before_request
def enforce_https_and_gatekeeper_shift():
    # 1. Enforce HTTPS when running on Render or reverse proxy
    proto = request.headers.get("X-Forwarded-Proto", "").lower()
    host = request.headers.get("Host", "").lower()
    
    if proto == "http" and ("onrender.com" in host or not app.debug):
        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=301)

    # 2. Multi-Tenant SaaS: Dynamic Tenant Resolution
    tenant_obj = None
    tenant_slug = request.args.get("tenant")
    if tenant_slug:
        tenant_obj = db.get_tenant_by_code(tenant_slug)
        if tenant_obj:
            session["tenant_id"] = tenant_obj["id"]

    if not tenant_obj and session.get("reseller_tenant_id"):
        tenant_obj = db.get_tenant_by_id(session["reseller_tenant_id"])

    if not tenant_obj and session.get("tenant_id"):
        tenant_obj = db.get_tenant_by_id(session["tenant_id"])

    if not tenant_obj and host:
        tenant_obj = db.get_tenant_by_domain(host)

    if not tenant_obj:
        tenant_obj = db.get_tenant_by_id(1)

    g.tenant = tenant_obj or {
        "id": 1,
        "code": "sabro",
        "name": "Sabro Networks",
        "company_name": "Sabro Networks ISP",
        "service_name": "SABRO VISION",
        "tagline": "Ultra High-Definition IPTV Middleware - Sabro Networks",
        "brand_color_primary": "#00f0ff",
        "brand_color_secondary": "#6366f1",
        "status": "active"
    }

    # 3. Shift all visitors arriving at root "/" to /gatekeeper if unauthenticated
    if request.path == "/":
        key_code = session.get("key_code")
        device_token = request.cookies.get("sabro_device_id")
        is_valid = False
        if key_code:
            is_valid, _, _ = db.validate_key(key_code, device_token)
            
        if not is_valid:
            # Shift into /gatekeeper with full HTTPS scheme on Render
            scheme = "https" if ("onrender.com" in host or proto == "https") else request.scheme
            return redirect(url_for("gatekeeper", _external=True, _scheme=scheme), code=302)

@app.context_processor
def inject_global_template_context():
    t = getattr(g, "tenant", None) or db.get_tenant_by_id(1)
    notif_count = 0
    sub_id = session.get("subscriber_id")
    if sub_id:
        notif_list = db.get_notifications(tenant_id=t.get("id", 1), subscriber_id=sub_id, limit=5)
        notif_count = sum(1 for n in notif_list if not n.get("is_read"))
    return {
        "tenant": t,
        "current_tenant": t,
        "unread_notifications_count": notif_count
    }

# Persistent Secret Key
_settings = db.get_settings()
app.secret_key = os.environ.get("SECRET_KEY") or _settings.get("session_secret_key") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

def safe_int(value, default, min_val=None, max_val=None):
    """Safely parse integers from user input with optional bounds clamping."""
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if min_val is not None and parsed < min_val:
        return min_val
    if max_val is not None and parsed > max_val:
        return max_val
    return parsed

def generate_proxy_token(ttl_seconds=43200):
    """Generates a time-limited HMAC signature authorizing stateless Xtream /proxy requests."""
    exp = int(time.time()) + ttl_seconds
    secret_bytes = str(app.secret_key).encode("utf-8")
    sig = hmac.new(secret_bytes, str(exp).encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{exp}.{sig}"

def verify_proxy_token(token):
    """Verifies an HMAC proxy token issued by Xtream live stream routes."""
    if not token or "." not in token:
        return False
    try:
        exp_str, sig = token.split(".", 1)
        exp = int(exp_str)
        if time.time() > exp:
            return False
        secret_bytes = str(app.secret_key).encode("utf-8")
        expected = hmac.new(secret_bytes, exp_str.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False

# ----------------------------------------------------
# Security Response Headers & Rate Limiting
# ----------------------------------------------------
RATE_LIMIT_STORE = {
    "activate": {},
    "login": {}
}

def is_rate_limited(action_type, ip, max_attempts=8, window_seconds=300):
    now = datetime.now()
    window_start = now - timedelta(seconds=window_seconds)
    store = RATE_LIMIT_STORE.get(action_type, {})
    attempts = [t for t in store.get(ip, []) if t > window_start]
    store[ip] = attempts
    return len(attempts) >= max_attempts

def record_attempt(action_type, ip):
    now = datetime.now()
    if ip not in RATE_LIMIT_STORE[action_type]:
        RATE_LIMIT_STORE[action_type][ip] = []
    RATE_LIMIT_STORE[action_type][ip].append(now)

def clear_attempts(action_type, ip):
    RATE_LIMIT_STORE[action_type].pop(ip, None)

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
    if "Content-Security-Policy" not in response.headers:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: blob: data:; "
            "media-src * blob: data: http: https:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: blob:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "img-src * data: blob: https: http:; "
            "connect-src * blob: data: https: http:; "
            "font-src * data: https:; "
            "frame-ancestors 'self';"
        )
    return response

@app.route("/api/health")
def api_health():
    """
    Production health check endpoint for monitoring, uptime probes, and load balancers.
    Reports database connectivity, system metrics, channels, and package stats.
    """
    try:
        channels_count = db.get_channels_count(active_only=False)
        packages_count = len(db.get_packages())
        uptime = int((datetime.now() - APP_START_TIME).total_seconds())
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "platform": _settings.get("platform_name", "SABRO VISION"),
            "database": "connected",
            "uptime_seconds": uptime,
            "metrics": {
                "channels_count": channels_count,
                "packages_count": packages_count
            }
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }), 500

def is_safe_url(url):
    """
    SSRF Protection: Validates that the URL targets public web destinations only.
    Blocks private IP ranges (RFC 1918), loopback, link-local, cloud metadata, and internal services.
    """
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        
        hostname_clean = hostname.strip().lower()
        if hostname_clean in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"):
            return False
        if hostname_clean.endswith(".local") or hostname_clean.endswith(".internal"):
            return False

        # Resolve hostname to IPv4
        ip_str = socket.gethostbyname(hostname_clean)
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
        return True
    except Exception:
        return False

# ----------------------------------------------------
# Helpers & Context Processors
# ----------------------------------------------------
def get_device_token(req):
    token = req.cookies.get("sabro_device_id")
    if not token:
        token = str(uuid.uuid4())
    return token

def clean_whatsapp_phone(phone_str):
    if not phone_str:
        return ""
    digits = re.sub(r"\D", "", str(phone_str))
    if digits.startswith("0092"):
        digits = digits[2:]
    elif digits.startswith("0"):
        digits = "92" + digits[1:]
    elif digits.startswith("3") and len(digits) == 10:
        digits = "92" + digits
    if digits.startswith("920") and len(digits) == 13:
        digits = "92" + digits[3:]
    return digits

@app.context_processor
def inject_global_data():
    settings = db.get_settings()
    now = datetime.now()
    
    # Check if subscriber is authenticated
    current_key_info = None
    days_left = 0
    current_subscriber = None

    if session.get("subscriber_id"):
        current_subscriber = db.get_subscriber_by_id(session["subscriber_id"])

    if session.get("key_code"):
        is_valid, msg, key_data = db.validate_key(session["key_code"])
        if is_valid and key_data and key_data.get("expires_at"):
            exp = datetime.fromisoformat(key_data["expires_at"])
            days_left = max(0, (exp - now).days)
            current_key_info = {
                "key_code": key_data["key_code"],
                "user_type": key_data["user_type"],
                "expires_at": exp.strftime("%d %b %Y"),
                "days_left": days_left
            }

    return {
        "settings": settings,
        "clean_whatsapp": clean_whatsapp_phone(settings.get("whatsapp", "")),
        "current_key_info": current_key_info,
        "current_subscriber": current_subscriber,
        "is_admin": session.get("is_admin", False),
        "newly_generated_creds": session.get("newly_generated_creds"),
        "now": now
    }

def subscriber_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key_code = session.get("key_code")
        device_token = request.cookies.get("sabro_device_id")

        # If user is logged into account but key_code not in session, restore from account
        if not key_code and session.get("subscriber_id"):
            sub = db.get_subscriber_by_id(session["subscriber_id"])
            if sub and sub.get("active_key_code"):
                is_valid, msg, key_data = db.validate_key(sub["active_key_code"], device_token)
                if is_valid:
                    session["key_code"] = key_data["key_code"]
                    session["user_type"] = key_data["user_type"]
                    key_code = key_data["key_code"]

        if not key_code:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Access key required"}), 401
            return redirect(url_for("gatekeeper"))
            
        is_valid, msg, key_data = db.validate_key(key_code, device_token)
        if not is_valid:
            session.pop("key_code", None)
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": msg}), 401
            flash(msg, "warning")
            return redirect(url_for("gatekeeper"))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required to access control panel.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

def reseller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("reseller_id") or not session.get("reseller_tenant_id"):
            flash("Reseller login required to access partner console.", "danger")
            return redirect(url_for("reseller_login"))
        t_id = session.get("reseller_tenant_id")
        tenant = db.get_tenant_by_id(t_id)
        if not tenant or tenant.get("status") == "suspended":
            session.pop("reseller_id", None)
            session.pop("reseller_tenant_id", None)
            flash("This reseller account is suspended. Contact Sabro Networks support.", "danger")
            return redirect(url_for("reseller_login"))
        g.reseller_tenant = tenant
        g.reseller_tenant_id = t_id
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------
# Gatekeeper & Direct Sign-In Routes
# ----------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def direct_login():
    if request.method == "POST":
        if request.form.get("key_code"):
            return activate()
        return user_login()
    settings = db.get_settings()
    return render_template("gatekeeper.html", settings=settings)

@app.route("/gatekeeper")
def gatekeeper():
    if session.get("key_code") and request.args.get("switch") != "1":
        device_token = request.cookies.get("sabro_device_id")
        is_valid, _, _ = db.validate_key(session["key_code"], device_token)
        if is_valid:
            return redirect(url_for("index"))

    settings = db.get_settings()
    return render_template("gatekeeper.html", settings=settings)

@app.route("/activate", methods=["POST"])
def activate():
    client_ip = request.remote_addr or "127.0.0.1"

    if is_rate_limited("activate", client_ip, max_attempts=10, window_seconds=300):
        flash("Too many failed activation attempts. Please wait 5 minutes before trying again.", "error")
        return redirect(url_for("gatekeeper"))

    key_code = request.form.get("key_code", "").strip()
    if not key_code:
        flash("Please enter your Sabro Vision access key.", "error")
        return redirect(url_for("gatekeeper"))

    # Obtain or create device token
    device_token = request.cookies.get("sabro_device_id")
    new_device = False
    if not device_token:
        device_token = str(uuid.uuid4())
        new_device = True

    # Automatic Key-to-Account Provisioning System:
    # User puts key -> Gets automatic username & password to login easily anytime!
    success, msg, sub_data, is_new, gen_pass, key_data = db.auto_provision_subscriber_from_key(key_code, device_token)
    
    if not success:
        record_attempt("activate", client_ip)
        flash(msg, "error")
        return redirect(url_for("gatekeeper"))

    clear_attempts("activate", client_ip)
    session["key_code"] = key_data["key_code"]
    session["user_type"] = key_data["user_type"]
    if sub_data:
        session["subscriber_id"] = sub_data["id"]
        session["subscriber_username"] = sub_data["username"]

    # Save credentials into session so the user gets the popup on the screen
    session["newly_generated_creds"] = {
        "username": sub_data["username"] if sub_data else "",
        "password": gen_pass or (sub_data.get("plain_password") if sub_data else "") or "Saved in your account",
        "key_code": key_data["key_code"],
        "is_new": is_new,
        "expires_at": key_data.get("expires_at", "")[:10] if key_data.get("expires_at") else ""
    }

    if is_new:
        flash(f"🎉 Account created automatically! Username: '{sub_data['username']}' | Password: '{gen_pass}'", "success")
    else:
        flash(f"Welcome back, {sub_data['username']}! Logged in automatically.", "success")

    resp = make_response(redirect(url_for("index")))
    if new_device:
        # Save device token cookie for 1 year
        resp.set_cookie("sabro_device_id", device_token, max_age=365*24*3600, httponly=True, samesite="Lax")
    return resp

@app.route("/api/dismiss-creds-modal", methods=["POST"])
def dismiss_creds_modal():
    session.pop("newly_generated_creds", None)
    return jsonify({"success": True})

@app.route("/user/login", methods=["POST"])
def user_login():
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited("login", client_ip, max_attempts=8, window_seconds=300):
        flash("Too many failed login attempts. Please wait 5 minutes.", "error")
        return redirect(url_for("gatekeeper"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("gatekeeper"))

    ok, msg, sub_data = db.authenticate_subscriber(username, password)
    if not ok:
        record_attempt("login", client_ip)
        flash(msg, "error")
        return redirect(url_for("gatekeeper"))

    clear_attempts("login", client_ip)
    session["subscriber_id"] = sub_data["id"]
    session["subscriber_username"] = sub_data["username"]

    device_token = request.cookies.get("sabro_device_id")
    new_device = False
    if not device_token:
        device_token = str(uuid.uuid4())
        new_device = True

    # If subscriber has an active key linked, auto-load it
    redirect_target = url_for("my_account")
    if sub_data.get("active_key_code"):
        # Authenticated user verified password; sync device lock to this browser/device session
        if device_token:
            db.sync_subscriber_device(sub_data["active_key_code"], device_token)

        is_valid, key_msg, key_data = db.validate_key(sub_data["active_key_code"], device_token)
        if is_valid:
            session["key_code"] = key_data["key_code"]
            session["user_type"] = key_data["user_type"]
            flash(f"Welcome back, {sub_data['username']}! Your monthly pass is active.", "success")
            redirect_target = url_for("index")
        else:
            flash(f"Welcome back! {key_msg} Please top up your account.", "warning")
    else:
        flash(f"Welcome back, {sub_data['username']}! Link your monthly access key below.", "info")

    resp = make_response(redirect(redirect_target))
    if new_device:
        resp.set_cookie("sabro_device_id", device_token, max_age=365*24*3600, httponly=True, samesite="Lax")
    return resp

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("subscriber_id"):
        return redirect(url_for("my_account"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        phone = request.form.get("phone", "").strip()
        full_name = request.form.get("full_name", "").strip()
        key_code = request.form.get("key_code", "").strip()

        device_token = request.cookies.get("sabro_device_id")
        new_device = False
        if not device_token:
            device_token = str(uuid.uuid4())
            new_device = True

        ok, msg, sub_data = db.create_subscriber(
            username=username,
            password=password,
            phone=phone,
            full_name=full_name,
            key_code=key_code,
            device_token=device_token
        )

        if not ok:
            flash(msg, "error")
            return render_template("register.html", username=username, phone=phone, full_name=full_name, key_code=key_code)

        session["subscriber_id"] = sub_data["id"]
        session["subscriber_username"] = sub_data["username"]

        if sub_data.get("active_key_code"):
            is_valid, _, key_data = db.validate_key(sub_data["active_key_code"], device_token)
            if is_valid:
                session["key_code"] = key_data["key_code"]
                session["user_type"] = key_data["user_type"]

        flash(msg, "success")
        redirect_target = url_for("index") if session.get("key_code") else url_for("my_account")
        resp = make_response(redirect(redirect_target))
        if new_device:
            resp.set_cookie("sabro_device_id", device_token, max_age=365*24*3600, httponly=True, samesite="Lax")
        return resp

    return render_template("register.html")

@app.route("/my-account", methods=["GET", "POST"])
def my_account():
    if not session.get("subscriber_id"):
        flash("Please log in to access your subscriber account.", "info")
        return redirect(url_for("gatekeeper"))

    sub = db.get_subscriber_by_id(session["subscriber_id"])
    if not sub:
        session.clear()
        return redirect(url_for("gatekeeper"))

    device_token = request.cookies.get("sabro_device_id")

    # Handle Top-up / Key linking
    if request.method == "POST":
        action = request.form.get("action")
        if action == "link_key":
            new_key = request.form.get("key_code", "").strip()
            if not new_key:
                flash("Please enter an access key code.", "error")
            else:
                ok, msg, updated_sub = db.link_key_to_subscriber(sub["id"], new_key, device_token)
                if ok:
                    sub = updated_sub
                    session["key_code"] = sub["active_key_code"]
                    flash(msg, "success")
                    return redirect(url_for("index"))
                else:
                    flash(f"Key Error: {msg}", "error")

    # Get key details if present
    key_details = None
    if sub.get("active_key_code"):
        _, _, kdata = db.validate_key(sub["active_key_code"], device_token)
        key_details = kdata

    # Package information & tier limits
    is_all, allowed_cats, pkg_name = db.get_subscriber_allowed_categories(subscriber_id=sub["id"])
    all_packages = db.get_packages(active_only=True)

    return render_template(
        "account.html",
        subscriber=sub,
        key_details=key_details,
        package_name=pkg_name,
        is_all_access=is_all,
        allowed_categories_list=list(allowed_cats),
        all_packages=all_packages
    )

@app.route("/logout")
def logout():
    session.pop("key_code", None)
    session.pop("user_type", None)
    session.pop("subscriber_id", None)
    session.pop("subscriber_username", None)
    flash("You have safely logged out of your Sabro Vision account.", "info")
    return redirect(url_for("gatekeeper"))

# ----------------------------------------------------
# Player & Main Client Routes
# ----------------------------------------------------
@app.route("/")
@subscriber_required
def index():
    selected_category = request.args.get("category", "All")
    search_query = request.args.get("q", "").strip()
    channel_id_arg = request.args.get("channel_id")
    online_only = request.args.get("online_only", "0") == "1"
    fav_only = request.args.get("fav_only", "0") == "1"

    sub_id = session.get("subscriber_id")
    key_code = session.get("key_code")
    is_all, allowed_cats, pkg_name = db.get_subscriber_allowed_categories(subscriber_id=sub_id, key_code=key_code)
    allowed_filter = None if is_all else allowed_cats

    categories = db.get_categories(allowed_categories=allowed_filter)
    total_channel_count = db.get_channels_count(active_only=True, allowed_categories=allowed_filter)

    # If displaying all without search, limit to 150 channels for optimal browser speed
    limit = 150 if (selected_category == "All" and not search_query and not fav_only) else None

    health_filter = "online" if online_only else None
    channels = db.get_channels(
        category=selected_category if selected_category != "All" else None,
        search=search_query if search_query else None,
        health_status=health_filter,
        allowed_categories=allowed_filter,
        limit=limit
    )

    # Get favorites for current key
    favorites = db.get_favorites(session.get("key_code", ""))
    fav_ids = [f["id"] for f in favorites]

    if fav_only:
        channels = [ch for ch in channels if ch["id"] in fav_ids]

    # Determine initial active channel for the player
    active_channel = None
    if channel_id_arg:
        try:
            active_channel = db.get_channel_by_id(int(channel_id_arg))
        except (ValueError, TypeError):
            pass
            
    if not active_channel and channels:
        active_channel = channels[0]

    return render_template(
        "player.html",
        categories=categories,
        channels=channels,
        total_channel_count=total_channel_count,
        active_channel=active_channel,
        selected_category=selected_category,
        search_query=search_query,
        favorites=favorites,
        fav_ids=fav_ids,
        online_only=online_only,
        fav_only=fav_only,
        package_name=pkg_name,
        is_all_access=is_all,
        allowed_categories_list=list(allowed_cats)
    )

@app.route("/watch/<int:channel_id>")
@subscriber_required
def watch(channel_id):
    channel = db.get_channel_by_id(channel_id)
    if not channel or not channel["is_active"]:
        flash("Channel is currently unavailable.", "error")
        return redirect(url_for("index"))

    sub_id = session.get("subscriber_id")
    key_code = session.get("key_code")
    if not session.get("is_admin") and not db.can_subscriber_access_channel(subscriber_id=sub_id, key_code=key_code, channel_obj=channel):
        flash(f"⚠️ Channel Locked: '{channel['name']}' ({channel['category']}) is not included in your active package. Please upgrade your pass in My Account!", "warning")
        return redirect(url_for("my_account"))

    is_all, allowed_cats, _ = db.get_subscriber_allowed_categories(subscriber_id=sub_id, key_code=key_code)
    allowed_filter = None if is_all else allowed_cats

    channels = db.get_channels(allowed_categories=allowed_filter)
    categories = db.get_categories(allowed_categories=allowed_filter)
    favorites = db.get_favorites(session.get("key_code", ""))
    fav_ids = [f["id"] for f in favorites]

    return render_template(
        "watch.html",
        active_channel=channel,
        channels=channels,
        categories=categories,
        favorites=favorites,
        fav_ids=fav_ids
    )

@app.route("/api/channels")
@subscriber_required
def api_channels():
    category = request.args.get("category", "All")
    search = request.args.get("q", "")
    sub_id = session.get("subscriber_id")
    key_code = session.get("key_code")
    is_all, allowed_cats, _ = db.get_subscriber_allowed_categories(subscriber_id=sub_id, key_code=key_code)
    allowed_filter = None if is_all else allowed_cats

    channels = db.get_channels(
        category=category if category != "All" else None,
        search=search if search else None,
        allowed_categories=allowed_filter
    )
    return jsonify({"success": True, "channels": channels})

@app.route("/api/favorite/toggle", methods=["POST"])
@app.route("/api/favorites/toggle", methods=["POST"])
@subscriber_required
def api_favorite_toggle():
    data = request.get_json(silent=True) or {}
    channel_id = safe_int(data.get("channel_id"), 0, min_val=1)
    if not channel_id:
        return jsonify({"success": False, "error": "Invalid or missing Channel ID"}), 400
        
    is_fav = db.toggle_favorite(session.get("key_code"), channel_id)
    return jsonify({"success": True, "is_favorite": is_fav})

@app.route("/api/favorites", methods=["GET"])
@subscriber_required
def api_favorites():
    favs = db.get_favorites(session.get("key_code", ""))
    return jsonify({"success": True, "favorites": favs})

# ----------------------------------------------------
# Streaming Reverse Proxy & CORS Bypass Engine
# ----------------------------------------------------
PROXY_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 VLC/3.0.18",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}

def verify_stream_authorization():
    """Ensures only users with an active key, admin session, or valid signed Xtream token can stream."""
    if session.get("is_admin"):
        return True, ""
    xt_token = request.args.get("xt")
    if xt_token and verify_proxy_token(xt_token):
        return True, ""
    key_code = session.get("key_code")
    if not key_code:
        return False, "Access denied: Active monthly access key required."
    device_token = request.cookies.get("sabro_device_id")
    is_valid, msg, _ = db.validate_key(key_code, device_token)
    if not is_valid:
        return False, f"Access denied: {msg}"
    return True, ""

@app.route("/stream/<int:channel_id>")
def stream_channel(channel_id):
    """
    Proxies stream for a given channel to guarantee CORS bypass and avoid SSL mixed content.
    Protected by monthly access key session verification and package category authorization.
    """
    has_access, err_msg = verify_stream_authorization()
    if not has_access:
        return err_msg, 401

    channel = db.get_channel_by_id(channel_id)
    if not channel or not channel["is_active"]:
        return "Channel stream not found", 404

    # Package Tier Enforcement
    if not session.get("is_admin"):
        sub_id = session.get("subscriber_id")
        key_code = session.get("key_code")
        if not db.can_subscriber_access_channel(subscriber_id=sub_id, key_code=key_code, channel_obj=channel):
            return "Package upgrade required for this channel", 403

    target_url = channel["stream_url"]
    return proxy_stream_request(target_url)

@app.route("/proxy")
def proxy_url():
    """
    Proxies sub-manifests and video chunks (.m3u8, .ts, etc.).
    Protected by monthly access key session verification and SSRF filter.
    """
    has_access, err_msg = verify_stream_authorization()
    if not has_access:
        return err_msg, 401

    target_url = request.args.get("url")
    if not target_url:
        return "Target URL missing", 400
    xt_token = request.args.get("xt")
    return proxy_stream_request(target_url, xt_token=xt_token)

def proxy_stream_request(target_url, xt_token=None):
    # Strict SSRF validation
    if not is_safe_url(target_url):
        return "Access denied: Request to private or internal destination blocked by security policy.", 403

    req = None
    try:
        current_url = target_url
        # Manually follow redirects (max 4 hops) with SSRF validation on every hop
        for _ in range(4):
            if not is_safe_url(current_url):
                return "Access denied: Redirect to private or internal destination blocked by security policy.", 403
            parsed_target = urllib.parse.urlparse(current_url)
            origin_ref = f"{parsed_target.scheme}://{parsed_target.netloc}/"
            headers = dict(PROXY_HEADERS)
            headers["Referer"] = origin_ref

            req = requests.get(current_url, headers=headers, stream=True, timeout=(4, 12), allow_redirects=False)
            if req.status_code in (301, 302, 303, 307, 308) and req.headers.get("Location"):
                next_url = urllib.parse.urljoin(current_url, req.headers["Location"])
                req.close()
                req = None
                current_url = next_url
                continue
            break

        if req is None:
            return "Too many upstream redirects", 502

        # Check if response is M3U8 playlist text
        content_type = req.headers.get("Content-Type", "")
        ctype_lower = content_type.lower()
        url_lower = current_url.lower()
        if "mpegurl" in ctype_lower or url_lower.endswith(".m3u8") or ".m3u8?" in url_lower:
            playlist_text = req.text
            req.close()
            req = None
            base_url = req.url if req else current_url
            xt_suffix = f"&xt={urllib.parse.quote(xt_token)}" if xt_token else ""

            # Rewrite relative chunk & sub-playlist URLs to point through our secure /proxy endpoint
            rewritten_lines = []
            for line in playlist_text.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    full_uri = urllib.parse.urljoin(base_url, stripped)
                    proxied_uri = f"/proxy?url={urllib.parse.quote(full_uri)}{xt_suffix}"
                    rewritten_lines.append(proxied_uri)
                elif stripped.startswith("#EXT-X-KEY:") and 'URI="' in stripped:
                    match = re.search(r'URI="([^"]+)"', stripped)
                    if match:
                        key_uri = urllib.parse.urljoin(base_url, match.group(1))
                        proxied_key = f"/proxy?url={urllib.parse.quote(key_uri)}{xt_suffix}"
                        rewritten_lines.append(stripped.replace(match.group(1), proxied_key))
                    else:
                        rewritten_lines.append(line)
                else:
                    rewritten_lines.append(line)

            response_data = "\n".join(rewritten_lines)
            resp = Response(response_data, status=200, mimetype="application/vnd.apple.mpegurl")
            resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            return resp

        # Otherwise, stream binary chunks (.ts, audio, video segments) and always close upstream socket
        upstream_req = req
        req = None
        def generate():
            try:
                for chunk in upstream_req.iter_content(chunk_size=65536):
                    if chunk:
                        yield chunk
            finally:
                try:
                    upstream_req.close()
                except Exception:
                    pass

        resp = Response(generate(), status=upstream_req.status_code, content_type=content_type or "application/octet-stream")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        return resp

    except Exception as e:
        if req is not None:
            try:
                req.close()
            except Exception:
                pass
        return f"Stream Gateway Error: {str(e)}", 502

# ----------------------------------------------------
# Admin Authentication & Control Panel
# ----------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    client_ip = request.remote_addr or "127.0.0.1"

    if request.method == "POST":
        if is_rate_limited("login", client_ip, max_attempts=5, window_seconds=300):
            flash("Too many failed admin login attempts. Please wait 5 minutes.", "error")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = db.get_db()
        admin = conn.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if admin and check_password_hash(admin["password_hash"], password):
            clear_attempts("login", client_ip)
            session["is_admin"] = True
            session["admin_user"] = admin["username"]
            flash(f"Welcome to Sabro Vision Admin Panel, {username}!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            record_attempt("login", client_ip)
            flash("Invalid administrator username or password.", "error")

    return render_template("login.html")



@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_user", None)
    flash("Admin logged out successfully.", "info")
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    analytics = db.get_dashboard_analytics()
    stats = db.get_key_stats()
    conn = db.get_db()
    recent_keys = conn.execute("SELECT * FROM access_keys ORDER BY id DESC LIMIT 6").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", analytics=analytics, stats=stats, recent_keys=[dict(k) for k in recent_keys])

# --- Key Management ---
@app.route("/admin/keys")
@admin_required
def admin_keys():
    filter_type = request.args.get("type", "all")
    filter_status = request.args.get("status", "all")
    search = request.args.get("q", "").strip()

    conn = db.get_db()
    query = """
        SELECT k.*, p.name as package_name, p.allowed_categories
        FROM access_keys k
        LEFT JOIN packages p ON p.id = k.package_id
        WHERE 1=1
    """
    params = []

    if filter_type != "all":
        query += " AND k.user_type = ?"
        params.append(filter_type)
    if filter_status != "all":
        query += " AND k.status = ?"
        params.append(filter_status)
    if search:
        query += " AND (k.key_code LIKE ? OR k.customer_name LIKE ? OR k.phone LIKE ?)"
        wild = f"%{search}%"
        params.extend([wild, wild, wild])

    query += " ORDER BY k.id DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    keys = [dict(r) for r in rows]
    stats = db.get_key_stats()
    settings = db.get_settings()
    packages = db.get_packages(active_only=True)
    host_url = request.host_url.rstrip("/")

    return render_template(
        "admin_keys.html", 
        keys=keys, 
        stats=stats,
        settings=settings,
        packages=packages,
        host_url=host_url,
        filter_type=filter_type,
        filter_status=filter_status,
        search=search
    )

@app.route("/admin/keys/create", methods=["POST"])
@app.route("/admin/keys/generate", methods=["POST"])
@admin_required
def admin_create_key():
    user_type = request.form.get("user_type", "subscriber")
    customer_name = request.form.get("customer_name", "").strip()
    phone = request.form.get("phone", "").strip()
    duration_days = safe_int(request.form.get("duration_days"), 30, min_val=1, max_val=3650)
    package_id = safe_int(request.form.get("package_id"), 0, min_val=1) or None
    notes = request.form.get("notes", "").strip()

    key_code = db.create_access_key(
        user_type=user_type,
        customer_name=customer_name,
        phone=phone,
        duration_days=duration_days,
        notes=notes,
        package_id=package_id
    )
    flash(f"New {user_type.capitalize()} Access Key created: {key_code}", "success")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/bulk", methods=["POST"])
@admin_required
def admin_bulk_keys():
    count = safe_int(request.form.get("count"), 10, min_val=1, max_val=500)
    user_type = request.form.get("user_type", "subscriber")
    duration_days = safe_int(request.form.get("duration_days"), 30, min_val=1, max_val=3650)
    package_id = safe_int(request.form.get("package_id"), 0, min_val=1) or None
    notes = request.form.get("notes", "Bulk Generated").strip()

    generated = db.bulk_generate_keys(count=count, user_type=user_type, duration_days=duration_days, notes=notes, package_id=package_id)
    flash(f"Successfully generated {len(generated)} new {user_type.capitalize()} keys!", "success")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/renew/<int:key_id>", methods=["POST"])
@admin_required
def admin_renew_key(key_id):
    extra_days = safe_int(request.form.get("extra_days"), 30, min_val=1, max_val=3650)
    success, msg = db.renew_key(key_id, extra_days=extra_days)
    if success:
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/revoke/<int:key_id>", methods=["POST"])
@admin_required
def admin_revoke_key(key_id):
    db.revoke_key(key_id)
    flash("Key has been revoked.", "warning")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/reset-device/<int:key_id>", methods=["POST"])
@admin_required
def admin_reset_device(key_id):
    db.reset_device_lock(key_id)
    flash("Device binding reset. Key can now be activated on a new device.", "info")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/delete/<int:key_id>", methods=["POST"])
@admin_required
def admin_delete_key(key_id):
    db.delete_key(key_id)
    flash("Key deleted permanently.", "info")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/export")
@admin_required
def admin_export_keys():
    conn = db.get_db()
    rows = conn.execute("SELECT * FROM access_keys ORDER BY id DESC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Key Code", "Type", "Customer", "Phone", "Days", "Status", "Created At", "Expires At", "Notes"])
    
    for r in rows:
        writer.writerow([
            r["id"], r["key_code"], r["user_type"], r["customer_name"], 
            r["phone"], r["duration_days"], r["status"], r["created_at"], 
            r["expires_at"], r["notes"]
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=sabro_iptv_keys.csv"}
    )

# --- Channel & Playlist Management ---
@app.route("/admin/channels")
@admin_required
def admin_channels():
    category = request.args.get("category")
    search = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    per_page = 50
    offset = (page - 1) * per_page

    total_count = db.get_channels_count(category=category, search=search, active_only=False)
    channels = db.get_channels(category=category, search=search, active_only=False, limit=per_page, offset=offset)
    categories = db.get_categories()
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    return render_template(
        "admin_channels.html",
        channels=channels,
        categories=categories,
        selected_category=category,
        search=search,
        page=page,
        total_pages=total_pages,
        total_count=total_count
    )

@app.route("/admin/channels/add", methods=["POST"])
@admin_required
def admin_add_channel():
    name = request.form.get("name", "").strip()
    stream_url = request.form.get("stream_url", "").strip()
    logo = request.form.get("logo", "").strip()
    category = request.form.get("category", "Entertainment").strip()
    group_title = request.form.get("group_title", "").strip()
    stream_type = request.form.get("stream_type", "hls").strip()

    if not name or not stream_url:
        flash("Channel name and stream URL are required.", "error")
        return redirect(url_for("admin_channels"))

    db.add_channel(name, stream_url, logo, category, group_title, stream_type)
    flash(f"Channel '{name}' added successfully!", "success")
    return redirect(url_for("admin_channels"))

@app.route("/admin/channels/edit/<int:channel_id>", methods=["POST"])
@admin_required
def admin_edit_channel(channel_id):
    name = request.form.get("name", "").strip()
    stream_url = request.form.get("stream_url", "").strip()
    logo = request.form.get("logo", "").strip()
    category = request.form.get("category", "Entertainment").strip()
    group_title = request.form.get("group_title", "").strip()
    is_active = 1 if request.form.get("is_active") == "1" else 0
    stream_type = request.form.get("stream_type", "hls").strip()

    db.update_channel(channel_id, name, stream_url, logo, category, group_title, is_active, stream_type)
    flash(f"Channel '{name}' updated.", "success")
    return redirect(url_for("admin_channels"))

@app.route("/admin/channels/delete/<int:channel_id>", methods=["POST"])
@admin_required
def admin_delete_channel(channel_id):
    db.delete_channel(channel_id)
    flash("Channel removed.", "info")
    return redirect(url_for("admin_channels"))

@app.route("/admin/playlists")
@admin_required
def admin_playlists():
    conn = db.get_db()
    playlists = conn.execute("SELECT * FROM playlists ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("admin_playlists.html", playlists=[dict(p) for p in playlists])

@app.route("/admin/playlists/import-url", methods=["POST"])
@admin_required
def admin_import_m3u_url():
    url = request.form.get("url", "").strip()
    name = request.form.get("name", "Imported M3U").strip()
    
    if not url:
        flash("M3U URL is required.", "error")
        return redirect(url_for("admin_playlists"))

    try:
        count = iptv_parser.import_m3u_url(url, playlist_name=name)
        flash(f"Successfully imported {count} channels from M3U URL!", "success")
    except Exception as e:
        flash(f"Error importing M3U playlist: {str(e)}", "error")
        
    return redirect(url_for("admin_channels"))

@app.route("/admin/playlists/upload-file", methods=["POST"])
@admin_required
def admin_upload_m3u_file():
    if "m3u_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("admin_playlists"))
        
    file = request.files["m3u_file"]
    name = request.form.get("name", file.filename or "Uploaded M3U").strip()
    
    if not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("admin_playlists"))

    try:
        content = file.read().decode("utf-8", errors="ignore")
        channels = iptv_parser.parse_m3u_content(content)
        count = iptv_parser.save_imported_channels(channels, playlist_name=name)
        flash(f"Successfully imported {count} channels from uploaded file!", "success")
    except Exception as e:
        flash(f"Error reading M3U file: {str(e)}", "error")

    return redirect(url_for("admin_channels"))

@app.route("/admin/playlists/xtream", methods=["POST"])
@admin_required
def admin_import_xtream():
    server = request.form.get("server", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not server or not username or not password:
        flash("Server URL, Username, and Password are all required.", "error")
        return redirect(url_for("admin_playlists"))

    try:
        count = iptv_parser.import_xtream_codes(server, username, password)
        flash(f"Successfully connected Xtream Codes & imported {count} live channels!", "success")
    except Exception as e:
        flash(f"Xtream Codes connection failed: {str(e)}", "error")

    return redirect(url_for("admin_channels"))

# --- Settings & Customization ---
@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        fields = [
            "platform_name", "tagline", "currency", "monthly_price",
            "phone", "whatsapp", "jazzcash_title", "jazzcash_number",
            "easypaisa_title", "easypaisa_number", "bank_name",
            "bank_account_title", "bank_account_number", "announcement"
        ]
        for f in fields:
            val = request.form.get(f, "").strip()
            db.update_setting(f, val)

        # Admin password update if supplied
        new_password = request.form.get("new_admin_password", "").strip()
        if new_password:
            conn = db.get_db()
            pw_hash = generate_password_hash(new_password)
            conn.execute("UPDATE admin_users SET password_hash = ? WHERE username = ?", (pw_hash, session.get("admin_user", "admin")))
            conn.commit()
            conn.close()
            flash("Admin password updated successfully!", "info")

        flash("Platform settings updated successfully!", "success")
        return redirect(url_for("admin_settings"))

    settings = db.get_settings()
    return render_template("admin_settings.html", settings=settings)

# ----------------------------------------------------
# SABRO VISION v1.0 - Xtream Codes API v2 Compatibility
# (Powers IPTV Smarters Pro, TiviMate, XCIPTV, OTT Navigator)
# ----------------------------------------------------
@app.route("/player_api.php", methods=["GET", "POST"])
def player_api():
    username = request.args.get("username") or request.form.get("username")
    password = request.args.get("password") or request.form.get("password")
    action = request.args.get("action") or request.form.get("action")

    if not username or not password:
        json_data = request.get_json(silent=True) or {}
        username = username or json_data.get("username")
        password = password or json_data.get("password")
        action = action or json_data.get("action")

    client_ip = request.remote_addr or "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "IPTV App")

    is_valid, user_info, err_msg = db.authenticate_xtream(username or "", password or "")
    if not is_valid:
        db.log_connection(username or "unknown", client_ip, user_agent, action="AUTH_FAILED")
        return jsonify({
            "user_info": {
                "auth": 0,
                "status": "Disabled",
                "message": err_msg or "Invalid username or password"
            }
        })

    db.log_connection(username, client_ip, user_agent, action=action or "AUTH_SUCCESS")

    if not action:
        host_url = request.host_url.rstrip("/")
        parsed = urllib.parse.urlparse(host_url)
        port_str = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        server_info = {
            "url": parsed.hostname or "127.0.0.1",
            "port": port_str,
            "https_port": port_str if parsed.scheme == "https" else "443",
            "server_protocol": parsed.scheme or "http",
            "rtmp_port": "8880",
            "timezone": "Asia/Karachi",
            "timestamp_now": int(datetime.now().timestamp()),
            "time_now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return jsonify({
            "user_info": user_info,
            "server_info": server_info
        })

    sub_id = user_info.get("subscriber_id")
    is_all, allowed_cats, _ = db.get_subscriber_allowed_categories(subscriber_id=sub_id)
    allowed_filter = None if is_all else allowed_cats

    if action == "get_live_categories":
        cats = db.get_xtream_live_categories(allowed_categories=allowed_filter)
        return jsonify(cats)

    if action == "get_live_streams":
        cat_id = request.args.get("category_id") or request.form.get("category_id")
        streams = db.get_xtream_live_streams(category_id=cat_id, allowed_categories=allowed_filter)
        return jsonify(streams)

    if action in ("get_vod_categories", "get_vod_streams", "get_series_categories", "get_series"):
        return jsonify([])

    if action == "get_short_epg":
        return jsonify({"epg_listings": []})

    if action == "get_simple_data_table":
        streams = db.get_xtream_live_streams(allowed_categories=allowed_filter)
        return jsonify({"total_items": len(streams), "data": streams})

    return jsonify({"error": "Unknown action"}), 400

@app.route("/live/<username>/<password>/<path:stream_req>")
def xtream_live_stream(username, password, stream_req):
    clean_stream_id = stream_req.split(".")[0]
    try:
        ch_id = int(clean_stream_id)
    except ValueError:
        return "Invalid stream identifier", 400

    is_valid, user_info, err = db.authenticate_xtream(username, password)
    if not is_valid:
        return f"Unauthorized: {err}", 401

    channel = db.get_channel_by_id(ch_id)
    if not channel or not channel["is_active"]:
        return "Channel not available", 404

    sub_id = user_info.get("subscriber_id")
    if not db.can_subscriber_access_channel(subscriber_id=sub_id, channel_obj=channel):
        return "Forbidden: This channel is outside your active package tier. Please upgrade your pass.", 403

    db.log_connection(username, request.remote_addr, request.headers.get("User-Agent"), stream_id=ch_id, action="STREAM_LIVE")

    settings = db.get_settings()
    if settings.get("stream_proxy_enabled") == "1":
        return redirect(url_for("proxy_url", url=channel["stream_url"], xt=generate_proxy_token()))
    else:
        return redirect(channel["stream_url"])

@app.route("/get.php")
def get_m3u():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    
    is_valid, user_info, err = db.authenticate_xtream(username, password)
    if not is_valid:
        return f"#EXTM3U\n#ERROR: {err}\n", 401, {"Content-Type": "text/plain"}

    sub_id = user_info.get("subscriber_id")
    is_all, allowed_cats, _ = db.get_subscriber_allowed_categories(subscriber_id=sub_id)
    allowed_filter = None if is_all else allowed_cats

    channels = db.get_channels(active_only=True, allowed_categories=allowed_filter)
    host_url = request.host_url.rstrip("/")

    lines = ["#EXTM3U"]
    for ch in channels:
        ch_name = (ch["name"] or "Channel").replace('"', '')
        ch_keys = ch.keys()
        logo = ch["logo"] if "logo" in ch_keys and ch["logo"] else ""
        group = ch["category"] if "category" in ch_keys and ch["category"] else "General"
        epg_id = ch["epg_channel_id"] if "epg_channel_id" in ch_keys and ch["epg_channel_id"] else ch_name.lower().replace(" ", ".")
        stream_link = f"{host_url}/live/{username}/{password}/{ch['id']}.m3u8"
        lines.append(f'#EXTINF:-1 tvg-id="{epg_id}" tvg-name="{ch_name}" tvg-logo="{logo}" group-title="{group}",{ch_name}')
        lines.append(stream_link)

    playlist_content = "\n".join(lines)
    return Response(
        playlist_content,
        mimetype="audio/x-mpegurl",
        headers={"Content-Disposition": 'attachment; filename="sabro_vision.m3u"'}
    )

# ----------------------------------------------------
# SABRO VISION v1.0 - Payment Submission Route
# ----------------------------------------------------
@app.route("/payment/submit", methods=["GET", "POST"])
def submit_payment():
    if not session.get("subscriber_id"):
        flash("Please log in to submit your payment receipt.", "info")
        return redirect(url_for("gatekeeper"))

    sub = db.get_subscriber_by_id(session["subscriber_id"])
    packages = db.get_packages(active_only=True)
    settings = db.get_settings()

    if request.method == "POST":
        package_id = safe_int(request.form.get("package_id"), 0, min_val=1) or None
        amount_pkr = request.form.get("amount_pkr") or request.form.get("amount") or "150"
        payment_method = request.form.get("payment_method", "JazzCash")
        transaction_ref = (request.form.get("transaction_ref") or request.form.get("transaction_id") or "").strip()
        sender_number = (request.form.get("sender_number") or request.form.get("sender_account") or "").strip()
        notes = request.form.get("notes", "").strip()

        if not transaction_ref:
            flash("Please enter your transaction ID / reference code.", "error")
            return render_template("payment_submit.html", subscriber=sub, packages=packages, settings=settings)

        amt = safe_int(amount_pkr, 150, min_val=0)

        db.submit_payment_receipt(
            subscriber_id=sub["id"],
            package_id=package_id,
            amount_pkr=amt,
            payment_method=payment_method,
            transaction_ref=transaction_ref,
            sender_number=sender_number,
            notes=notes
        )

        flash("Payment receipt submitted successfully! Our billing team will verify and activate your pass shortly.", "success")
        return redirect(url_for("my_account"))

    return render_template("payment_submit.html", subscriber=sub, packages=packages, settings=settings)

# ----------------------------------------------------
# SABRO VISION v1.0 - Customer Management & Sector Mapping
# ----------------------------------------------------
@app.route("/admin/customers")
@admin_required
def admin_customers():
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "all")
    zone = request.args.get("zone", "all")
    page = safe_int(request.args.get("page"), 1, min_val=1)
    per_page = 30
    offset = (page - 1) * per_page

    subscribers = db.get_subscribers(search=search, status=status, zone=zone, limit=per_page, offset=offset)
    total_count = db.get_subscribers_count(search=search, status=status, zone=zone)
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    packages = db.get_packages(active_only=True)

    return render_template(
        "admin_customers.html",
        subscribers=subscribers,
        total_count=total_count,
        page=page,
        total_pages=total_pages,
        search=search,
        status=status,
        zone=zone,
        packages=packages
    )

@app.route("/admin/customers/add", methods=["POST"])
@admin_required
def admin_add_customer():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    full_name = request.form.get("full_name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    pppoe_username = request.form.get("pppoe_username", "").strip()
    zone = request.form.get("zone", "").strip()
    fat_id = request.form.get("fat_id", "").strip()
    package_id = request.form.get("package_id")
    notes = request.form.get("notes", "").strip()

    ok, msg, sub_data = db.add_subscriber(
        username=username,
        password=password,
        full_name=full_name,
        phone=phone,
        email=email,
        pppoe_username=pppoe_username,
        zone=zone,
        fat_id=fat_id,
        package_id=int(package_id) if package_id else None,
        notes=notes
    )

    if ok:
        db.log_audit(session.get("admin_user"), "CREATE_CUSTOMER", f"Created customer {username} (FAT: {fat_id}, PPPoE: {pppoe_username})")
        flash(f"Customer {username} created successfully with Xtream credentials!", "success")
    else:
        flash(f"Error: {msg}", "error")

    return redirect(url_for("admin_customers"))

@app.route("/admin/customers/update/<int:sub_id>", methods=["POST"])
@admin_required
def admin_update_customer(sub_id):
    full_name = request.form.get("full_name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    pppoe_username = request.form.get("pppoe_username", "").strip()
    zone = request.form.get("zone", "").strip()
    fat_id = request.form.get("fat_id", "").strip()
    status = request.form.get("status", "active")
    notes = request.form.get("notes", "").strip()

    db.update_subscriber(sub_id, full_name, phone, pppoe_username, zone, fat_id, email, status, notes)
    db.log_audit(session.get("admin_user"), "UPDATE_CUSTOMER", f"Updated customer ID #{sub_id} ({status})")
    flash("Customer details updated successfully!", "success")
    return redirect(url_for("admin_customers"))

@app.route("/admin/customers/renew/<int:sub_id>", methods=["POST"])
@admin_required
def admin_renew_customer(sub_id):
    package_id = safe_int(request.form.get("package_id"), 1, min_val=1)
    extra_days = safe_int(request.form.get("days"), 30, min_val=1, max_val=3650)
    ok, msg = db.activate_subscriber_subscription(sub_id, package_id, days=extra_days)
    if ok:
        db.log_audit(session.get("admin_user"), "RENEW_SUBSCRIPTION", f"Renewed customer #{sub_id} for +{extra_days} days")
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin_customers"))

@app.route("/admin/customers/delete/<int:sub_id>", methods=["POST"])
@admin_required
def admin_delete_customer(sub_id):
    db.delete_subscriber(sub_id)
    db.log_audit(session.get("admin_user"), "DELETE_CUSTOMER", f"Deleted customer ID #{sub_id}")
    flash("Customer deleted permanently.", "info")
    return redirect(url_for("admin_customers"))

# ----------------------------------------------------
# SABRO VISION v1.0 - Xtream Codes Generator & Credentials
# ----------------------------------------------------
@app.route("/admin/xtream")
@admin_required
def admin_xtream():
    subscribers = db.get_subscribers(limit=50)
    settings = db.get_settings()
    host_url = request.host_url.rstrip("/")
    parsed = urllib.parse.urlparse(host_url)
    port_str = str(parsed.port or (443 if parsed.scheme == "https" else 80))

    return render_template(
        "admin_xtream.html",
        subscribers=subscribers,
        settings=settings,
        host_url=host_url,
        server_host=parsed.hostname or "127.0.0.1",
        server_port=port_str
    )

# ----------------------------------------------------
# SABRO VISION v1.0 - Packages & Tiered Subscriptions
# ----------------------------------------------------
@app.route("/admin/packages")
@admin_required
def admin_packages():
    packages = db.get_packages(active_only=False)
    return render_template("admin_packages.html", packages=packages)

@app.route("/admin/packages/create", methods=["POST"])
@admin_required
def admin_create_package():
    name = request.form.get("name", "").strip()
    code = request.form.get("code", "").strip()
    duration_days = safe_int(request.form.get("duration_days"), 30, min_val=1, max_val=3650)
    price_pkr = safe_int(request.form.get("price_pkr"), 150, min_val=0)
    max_connections = safe_int(request.form.get("max_connections"), 1, min_val=1, max_val=20)
    allowed_categories = request.form.get("allowed_categories", "all").strip()
    description = request.form.get("description", "").strip()

    if not name or not code:
        flash("Package name and unique code are required.", "error")
        return redirect(url_for("admin_packages"))

    db.add_package(name, code, duration_days, price_pkr, max_connections, description, allowed_categories=allowed_categories)
    db.log_audit(session.get("admin_user"), "CREATE_PACKAGE", f"Created package '{name}' ({price_pkr} PKR, {duration_days}d)")
    flash(f"Package '{name}' created successfully!", "success")
    return redirect(url_for("admin_packages"))

@app.route("/admin/packages/update/<int:pkg_id>", methods=["POST"])
@admin_required
def admin_update_package(pkg_id):
    name = request.form.get("name", "").strip()
    duration_days = safe_int(request.form.get("duration_days"), 30, min_val=1, max_val=3650)
    price_pkr = safe_int(request.form.get("price_pkr"), 150, min_val=0)
    max_connections = safe_int(request.form.get("max_connections"), 1, min_val=1, max_val=20)
    is_active = safe_int(request.form.get("is_active"), 1, min_val=0, max_val=1)
    allowed_categories = request.form.get("allowed_categories", "all").strip()
    description = request.form.get("description", "").strip()

    db.update_package(pkg_id, name, duration_days, price_pkr, max_connections, is_active, description, allowed_categories=allowed_categories)
    db.log_audit(session.get("admin_user"), "UPDATE_PACKAGE", f"Updated package ID #{pkg_id}")
    flash(f"Package '{name}' updated successfully!", "success")
    return redirect(url_for("admin_packages"))

@app.route("/packages")
def public_packages():
    packages = db.get_packages(active_only=True)
    settings = db.get_settings()
    clean_whatsapp = re.sub(r"[^\d]", "", settings.get("whatsapp", "")) if settings.get("whatsapp") else ""
    if clean_whatsapp.startswith("0"):
        clean_whatsapp = "92" + clean_whatsapp[1:]
    return render_template("packages.html", packages=packages, settings=settings, clean_whatsapp=clean_whatsapp)

# ----------------------------------------------------
# SABRO VISION v1.0 - Multi-Device & Apps Ecosystem
# ----------------------------------------------------
@app.route("/devices")
@app.route("/apps")
def multi_device_apps():
    settings = db.get_settings()
    clean_whatsapp = re.sub(r"[^\d]", "", settings.get("whatsapp", "")) if settings.get("whatsapp") else ""
    if clean_whatsapp.startswith("0"):
        clean_whatsapp = "92" + clean_whatsapp[1:]
    
    sub_id = session.get("subscriber_id")
    sub = db.get_subscriber_by_id(sub_id) if sub_id else None
    server_base = request.host_url.rstrip("/")
    return render_template("apps.html", settings=settings, clean_whatsapp=clean_whatsapp, sub=sub, server_base=server_base)

# ----------------------------------------------------
# SABRO VISION v1.0 - B2B Reseller & White-Label Portal
# ----------------------------------------------------
@app.route("/reseller", methods=["GET", "POST"])
@app.route("/partner", methods=["GET", "POST"])
def partner_portal():
    settings = db.get_settings()
    clean_whatsapp = re.sub(r"[^\d]", "", settings.get("whatsapp", "")) if settings.get("whatsapp") else ""
    if clean_whatsapp.startswith("0"):
        clean_whatsapp = "92" + clean_whatsapp[1:]

    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        contact_name = request.form.get("contact_name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        city = request.form.get("city", "").strip()
        subscriber_count = request.form.get("subscriber_count", "").strip()
        partner_type = request.form.get("partner_type", "white_label").strip()
        notes = request.form.get("notes", "").strip()

        if not company_name or not contact_name or not phone:
            flash("Please fill in Company Name, Contact Person, and Phone Number.", "error")
            return redirect(url_for("partner_portal") + "#partnerForm")

        new_id = db.create_reseller_inquiry(
            company_name=company_name,
            contact_name=contact_name,
            phone=phone,
            email=email,
            city=city,
            subscriber_count=subscriber_count,
            partner_type=partner_type,
            notes=notes
        )
        flash(f"Thank you, {contact_name}! Your White-Label & Reseller inquiry #{new_id} for '{company_name}' has been received. Our B2B team will contact you shortly on WhatsApp.", "success")
        return redirect(url_for("partner_portal") + "#partnerForm")

    return render_template("partner.html", settings=settings, clean_whatsapp=clean_whatsapp)

@app.route("/api/partner/inquiry", methods=["POST"])
def api_partner_inquiry():
    data = request.get_json(silent=True) or request.form
    company_name = (data.get("company_name") or "").strip()
    contact_name = (data.get("contact_name") or "").strip()
    phone = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip()
    city = (data.get("city") or "").strip()
    subscriber_count = (data.get("subscriber_count") or "").strip()
    partner_type = (data.get("partner_type") or "white_label").strip()
    notes = (data.get("notes") or "").strip()

    if not company_name or not contact_name or not phone:
        return jsonify({"success": False, "error": "Company Name, Contact Person, and Phone are required."}), 400

    new_id = db.create_reseller_inquiry(
        company_name=company_name,
        contact_name=contact_name,
        phone=phone,
        email=email,
        city=city,
        subscriber_count=subscriber_count,
        partner_type=partner_type,
        notes=notes
    )
    return jsonify({
        "success": True,
        "inquiry_id": new_id,
        "message": f"Inquiry #{new_id} recorded successfully. Our team will contact you on WhatsApp."
    })

@app.route("/admin/resellers")
@admin_required
def admin_resellers():
    status = request.args.get("status", "all")
    filter_status = None if status == "all" else status
    inquiries = db.get_reseller_inquiries(status=filter_status, limit=100)

    all_inquiries = db.get_reseller_inquiries(status=None, limit=500)
    stats = {
        "total": len(all_inquiries),
        "pending": sum(1 for x in all_inquiries if x.get("status") == "pending"),
        "contacted": sum(1 for x in all_inquiries if x.get("status") == "contacted"),
        "approved": sum(1 for x in all_inquiries if x.get("status") == "approved"),
        "rejected": sum(1 for x in all_inquiries if x.get("status") == "rejected"),
    }
    tenants = db.get_tenants()
    tenant_metrics = {t['id']: db.get_tenant_metrics(t['id']) for t in tenants}
    settings = db.get_settings()
    return render_template(
        "admin_resellers.html",
        inquiries=inquiries,
        stats=stats,
        current_status=status,
        pending_count=stats["pending"],
        tenants=tenants,
        tenant_metrics=tenant_metrics,
        settings=settings
    )

@app.route("/admin/resellers/status/<int:inquiry_id>", methods=["POST"])
@admin_required
def admin_update_reseller_status(inquiry_id):
    new_status = request.form.get("status", "contacted").strip()
    db.update_reseller_inquiry_status(inquiry_id, new_status)
    db.log_audit(session.get("admin_user"), "UPDATE_RESELLER_INQUIRY", f"Changed inquiry #{inquiry_id} status to '{new_status}'")
    flash(f"Inquiry #{inquiry_id} status updated to '{new_status}' successfully.", "success")
    return redirect(url_for("admin_resellers"))

# ----------------------------------------------------
# SABRO VISION v1.0 - Payment Verification Queue
# ----------------------------------------------------
@app.route("/admin/payments")
@admin_required
def admin_payments():
    status = request.args.get("status", "all")
    receipts = db.get_payment_receipts(status=status, limit=100)
    return render_template("admin_payments.html", receipts=receipts, current_status=status)

@app.route("/admin/payments/approve/<int:receipt_id>", methods=["POST"])
@admin_required
def admin_approve_payment(receipt_id):
    notes = request.form.get("notes", "Payment verified")
    ok, msg = db.approve_payment_receipt(receipt_id, session.get("admin_user"), notes=notes)
    if ok:
        flash(msg, "success")
    else:
        flash(f"Error: {msg}", "error")
    return redirect(url_for("admin_payments"))

@app.route("/admin/payments/reject/<int:receipt_id>", methods=["POST"])
@admin_required
def admin_reject_payment(receipt_id):
    notes = request.form.get("notes", "Rejected by administrator")
    ok, msg = db.reject_payment_receipt(receipt_id, session.get("admin_user"), notes=notes)
    if ok:
        flash(msg, "info")
    else:
        flash(f"Error: {msg}", "error")
    return redirect(url_for("admin_payments"))

# ----------------------------------------------------
# SABRO VISION v1.0 - Audit Logs & Connection Events
# ----------------------------------------------------
@app.route("/admin/audit")
@admin_required
def admin_audit():
    audit_logs = db.get_audit_logs(limit=100)
    conn_events = db.get_connection_events(limit=100)
    return render_template("admin_audit.html", audit_logs=audit_logs, conn_events=conn_events)

# ----------------------------------------------------
# SABRO VISION v1.0 - Data Vault & Backup Management
# ----------------------------------------------------
@app.route("/admin/backup")
@admin_required
def admin_backup():
    import data_vault
    db_size = 0
    if os.path.exists(db.DB_PATH):
        db_size = round(os.path.getsize(db.DB_PATH) / (1024 * 1024), 2)
    
    conn = db.get_db()
    counts = {
        "key_count": conn.execute("SELECT COUNT(*) FROM access_keys").fetchone()[0],
        "subscribers": conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()[0],
        "channels": conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0],
        "payments": conn.execute("SELECT COUNT(*) FROM payment_receipts").fetchone()[0],
        "inquiries": conn.execute("SELECT COUNT(*) FROM reseller_inquiries").fetchone()[0],
    }
    conn.close()

    storage_mode = "Persistent Volume" if os.environ.get("DATABASE_PATH") else "Local Vault Engine"
    vault_exists = os.path.exists(data_vault.VAULT_FILE)

    return render_template(
        "admin_backup.html",
        db_path=db.DB_PATH,
        db_size_mb=db_size,
        storage_mode=storage_mode,
        vault_exists=vault_exists,
        counts=counts
    )

@app.route("/admin/backup/trigger", methods=["POST"])
@admin_required
def admin_trigger_backup():
    import data_vault
    data_vault.save_vault_snapshot_to_disk()
    data_vault.sync_to_github_if_configured()
    flash("Database WAL checkpointed and Data Vault snapshot saved successfully!", "success")
    return redirect(url_for("admin_backup"))

@app.route("/admin/backup/download-db")
@admin_required
def admin_download_db():
    import data_vault
    data_vault.checkpoint_wal()
    filename = f"sabro_iptv_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(db.DB_PATH, as_attachment=True, download_name=filename)

@app.route("/admin/backup/download-json")
@admin_required
def admin_download_json():
    import data_vault
    data_vault.save_vault_snapshot_to_disk()
    filename = f"sabro_vault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return send_file(data_vault.VAULT_FILE, as_attachment=True, download_name=filename)

@app.route("/admin/backup/restore", methods=["POST"])
@admin_required
def admin_restore_backup():
    import data_vault
    file = request.files.get("backup_file")
    if not file or not file.filename:
        flash("Please select a valid backup file (.json).", "error")
        return redirect(url_for("admin_backup"))

    filename = file.filename.lower()
    if filename.endswith(".json"):
        import json
        try:
            snapshot = json.load(file.stream)
            count = data_vault.import_vault_snapshot(snapshot)
            flash(f"Successfully restored {count} records into database from JSON vault!", "success")
        except Exception as e:
            flash(f"Error restoring JSON vault: {str(e)}", "error")
    else:
        flash("Unsupported file format. Please upload a .json vault snapshot.", "error")

    return redirect(url_for("admin_backup"))

# ----------------------------------------------------
# SABRO VISION v1.0 - PWA Manifest & Service Worker
# ----------------------------------------------------
@app.route("/manifest.json")
def pwa_manifest():
    manifest_path = os.path.join(app.root_path, "static", "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content, mimetype="application/manifest+json")

@app.route("/sw.js")
def pwa_service_worker():
    sw_path = os.path.join(app.root_path, "static", "sw.js")
    with open(sw_path, "r", encoding="utf-8") as f:
        content = f.read()
    response = Response(content, mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    return response

# ----------------------------------------------------
# SABRO VISION v1.0 - Smart TV Leanback WebApp (/tv)
# ----------------------------------------------------
@app.route("/tv")
@subscriber_required
def tv_player():
    category = request.args.get("category", "all")
    online_only = request.args.get("online_only", "0") == "1"

    sub_id = session.get("subscriber_id")
    key_code = session.get("key_code")
    is_all, allowed_cats, pkg_name = db.get_subscriber_allowed_categories(subscriber_id=sub_id, key_code=key_code)
    allowed_filter = None if is_all else allowed_cats

    health_filter = "online" if online_only else None
    channels = db.get_channels(category=category, active_only=True, health_status=health_filter, allowed_categories=allowed_filter, limit=180)
    categories = db.get_categories(allowed_categories=allowed_filter)
    settings = db.get_settings()
    total_count = db.get_channels_count(active_only=True, allowed_categories=allowed_filter)

    return render_template(
        "tv_player.html",
        channels=channels,
        categories=categories,
        selected_category=category,
        online_only=online_only,
        total_channels_count=total_count,
        package_name=pkg_name,
        is_all_access=is_all,
        allowed_categories_list=list(allowed_cats),
        settings=settings
    )

# ----------------------------------------------------
# SABRO VISION v1.0 - Stream Health Diagnostics API & Admin
# ----------------------------------------------------
@app.route("/api/test-channel/<int:channel_id>")
def api_test_channel(channel_id):
    ch = db.get_channel_by_id(channel_id)
    if not ch:
        return jsonify({"error": "Channel not found"}), 404
    # Guard against literal loopback/private targets while allowing dead external hostnames to report offline
    parsed = urllib.parse.urlparse(ch["stream_url"] or "")
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254") or host.endswith((".local", ".internal")):
        return jsonify({"error": "Blocked by security policy"}), 403
    try:
        ip_obj = ipaddress.ip_address(socket.gethostbyname(host))
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return jsonify({"error": "Blocked by security policy"}), 403
    except socket.gaierror:
        pass  # Unresolvable external hostnames will cleanly report as 'offline'
    is_online, code, ms, reason = db.test_single_stream(ch["stream_url"])
    status = "online" if is_online else "offline"
    if is_online and ms > 2500:
        status = "slow"
    db.update_channel_health(channel_id, status, ms)
    return jsonify({
        "channel_id": channel_id,
        "name": ch["name"],
        "status": status,
        "is_online": is_online,
        "status_code": code,
        "latency_ms": ms,
        "reason": reason
    })

@app.route("/admin/channels/health")
@admin_required
def admin_channels_health():
    summary = db.get_channel_health_summary()
    recent_checked = db.get_channels(limit=40)
    return render_template("admin_channel_health.html", summary=summary, channels=recent_checked)

@app.route("/admin/channels/toggle-offline", methods=["POST"])
@admin_required
def admin_toggle_offline():
    action = request.form.get("action", "disable")
    enable = (action == "enable")
    affected = db.bulk_toggle_offline_channels(enable=enable)
    verb = "re-enabled" if enable else "deactivated"
    flash(f"Successfully {verb} {affected} offline channels.", "success")
    return redirect(url_for("admin_channels"))

@app.route("/admin/channels/test-batch", methods=["POST"])
@admin_required
def admin_test_batch():
    category = request.form.get("category", "all")
    limit = request.form.get("limit", "100")
    try:
        lim = int(limit)
    except ValueError:
        lim = 100
    res = db.batch_test_channels(category=category if category != "all" else None, limit=lim, max_workers=40)
    flash(f"Tested {res['tested']} channels: {res['online']} Online, {res['offline']} Offline.", "success")
    return redirect(url_for("admin_channels"))

# ====================================================
# SABRO NETWORKS ISP INTEGRATION & FREE VERIFICATION
# ====================================================
@app.route("/api/isp/verify", methods=["GET", "POST"])
def api_isp_verify():
    """
    Verifies if a customer has an active broadband internet subscription with Sabro Networks.
    Active broadband users receive Sabro Vision 100% FREE without purchasing a paid pass.
    """
    if request.method == "POST":
        identifier = request.form.get("identifier") or request.form.get("pppoe_username") or request.form.get("phone") or ""
    else:
        identifier = request.args.get("identifier") or request.args.get("pppoe_username") or request.args.get("phone") or ""

    if not identifier:
        return jsonify({"success": False, "error": "Identifier required (PPPoE username or phone)"}), 400

    client = isp_integration.get_isp_client(db.get_settings())
    res = client.verify_subscriber(identifier, db.get_db())

    if res.get("verified") and res.get("is_active"):
        # Auto-link or auto-provision free account if logged in
        if session.get("subscriber_id"):
            db.link_subscriber_to_isp(session["subscriber_id"], res.get("pppoe_username", identifier))
            # Auto-assign basic free pass
            basic_pkg = db.get_package_by_code("basic")
            if basic_pkg:
                db.activate_subscriber_subscription(session["subscriber_id"], basic_pkg["id"], days=365)
        return jsonify({
            "success": True,
            "verified": True,
            "is_active": True,
            "message": "Verified active Sabro Networks customer! 100% FREE IPTV access granted.",
            "data": res
        })
    else:
        return jsonify({
            "success": False,
            "verified": False,
            "is_active": False,
            "message": res.get("message", "Broadband subscription not found or inactive."),
            "data": res
        }), 404

@app.route("/admin/customers/verify-isp/<int:sub_id>", methods=["POST"])
@admin_required
def admin_verify_isp_subscriber(sub_id):
    sub = db.get_subscriber_by_id(sub_id)
    if not sub:
        flash("Subscriber not found.", "error")
        return redirect(url_for("admin_customers"))
    
    action = request.form.get("action", "link")
    if action == "link":
        pppoe = request.form.get("pppoe_username", sub.get("pppoe_username") or sub["username"])
        db.link_subscriber_to_isp(sub_id, pppoe, is_sabro_isp=1, isp_status="verified_active")
        basic_pkg = db.get_package_by_code("basic")
        if basic_pkg:
            db.activate_subscriber_subscription(sub_id, basic_pkg["id"], days=365)
        flash(f"Subscriber '{sub['username']}' verified as active Sabro Networks customer (100% FREE Access Activated).", "success")
    else:
        db.unlink_subscriber_from_isp(sub_id)
        flash(f"Sabro Networks ISP entitlement removed for subscriber '{sub['username']}'.", "info")
    return redirect(url_for("admin_customers"))

# ====================================================
# WHITE-LABEL RESELLER & ISP SAAS ROUTES
# ====================================================
@app.route("/reseller/login", methods=["GET", "POST"])
def reseller_login():
    if session.get("reseller_id") and session.get("reseller_tenant_id"):
        return redirect(url_for("reseller_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = db.authenticate_reseller(username, password)
        if user:
            session["reseller_id"] = user["id"]
            session["reseller_tenant_id"] = user["tenant_id"]
            session["reseller_username"] = user["username"]
            session["reseller_role"] = user["role"]
            flash(f"Welcome back to {user.get('service_name', 'Reseller Console')}!", "success")
            return redirect(url_for("reseller_dashboard"))
        flash("Invalid reseller username or password.", "danger")

    return render_template("reseller_login.html")

@app.route("/reseller/logout")
def reseller_logout():
    session.pop("reseller_id", None)
    session.pop("reseller_tenant_id", None)
    session.pop("reseller_username", None)
    session.pop("reseller_role", None)
    flash("Signed out from reseller console.", "info")
    return redirect(url_for("reseller_login"))

@app.route("/reseller/dashboard")
@reseller_required
def reseller_dashboard():
    tenant_id = g.reseller_tenant_id
    metrics = db.get_tenant_metrics(tenant_id)
    customers = db.get_subscribers(limit=10, tenant_id=tenant_id)
    return render_template("reseller_dashboard.html", metrics=metrics, customers=customers, tenant=g.reseller_tenant)

@app.route("/reseller/customers")
@reseller_required
def reseller_customers():
    tenant_id = g.reseller_tenant_id
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "all")
    customers = db.get_subscribers(search=search if search else None, status=status, limit=200, tenant_id=tenant_id)
    packages = db.get_packages(tenant_id=tenant_id)
    return render_template("reseller_customers.html", customers=customers, packages=packages, search=search, tenant=g.reseller_tenant)

@app.route("/reseller/customers/add", methods=["POST"])
@reseller_required
def reseller_add_customer():
    tenant_id = g.reseller_tenant_id
    metrics = db.get_tenant_metrics(tenant_id)
    max_cust = g.reseller_tenant.get("max_customers", 500)
    if metrics["total_customers"] >= max_cust:
        flash(f"Tenant customer limit reached ({metrics['total_customers']}/{max_cust}). Contact Sabro Networks to upgrade.", "danger")
        return redirect(url_for("reseller_customers"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    full_name = request.form.get("full_name", "").strip()
    phone = request.form.get("phone", "").strip()
    pppoe = request.form.get("pppoe_username", "").strip()
    pkg_id = request.form.get("package_id")

    ok, msg, sub_data = db.add_subscriber(
        username=username,
        password=password,
        full_name=full_name,
        phone=phone,
        pppoe_username=pppoe,
        package_id=int(pkg_id) if pkg_id else None,
        tenant_id=tenant_id
    )
    if ok:
        flash(f"Customer '{username}' created successfully!", "success")
    else:
        flash(f"Could not create customer: {msg}", "danger")
    return redirect(url_for("reseller_customers"))

@app.route("/reseller/customers/toggle/<int:sub_id>", methods=["POST"])
@reseller_required
def reseller_toggle_customer(sub_id):
    tenant_id = g.reseller_tenant_id
    sub = db.get_subscriber_by_id(sub_id)
    if not sub or sub.get("tenant_id") != tenant_id:
        flash("Permission denied. Customer does not belong to your tenant.", "danger")
        return redirect(url_for("reseller_customers"))

    new_status = "suspended" if sub["status"] == "active" else "active"
    db.update_subscriber(sub_id, full_name=sub["full_name"], phone=sub["phone"], pppoe_username=sub.get("pppoe_username") or "", zone=sub.get("zone") or "", fat_id=sub.get("fat_id") or "", email=sub.get("email") or "", status=new_status, notes=sub.get("notes") or "")
    flash(f"Customer status updated to {new_status.upper()}.", "success")
    return redirect(url_for("reseller_customers"))

@app.route("/reseller/packages")
@reseller_required
def reseller_packages():
    tenant_id = g.reseller_tenant_id
    pkgs = db.get_packages(active_only=False, tenant_id=tenant_id)
    return render_template("reseller_packages.html", packages=pkgs, tenant=g.reseller_tenant)

@app.route("/reseller/packages/create", methods=["POST"])
@reseller_required
def reseller_create_package():
    tenant_id = g.reseller_tenant_id
    name = request.form.get("name", "").strip()
    code = f"{g.reseller_tenant['code']}_{request.form.get('code', '').strip().lower()}"
    price = safe_int(request.form.get("price_pkr"), 250, min_val=0)
    duration = safe_int(request.form.get("duration_days"), 30, min_val=1)
    max_conn = safe_int(request.form.get("max_connections"), 1, min_val=1, max_val=10)
    allowed_cats = request.form.get("allowed_categories", "all").strip()
    description = request.form.get("description", "").strip()

    db.add_package(name, code, duration_days=duration, price_pkr=price, max_connections=max_conn, description=description, allowed_categories=allowed_cats, tenant_id=tenant_id)
    flash(f"Custom package '{name}' created successfully!", "success")
    return redirect(url_for("reseller_packages"))

@app.route("/reseller/payments")
@reseller_required
def reseller_payments():
    tenant_id = g.reseller_tenant_id
    receipts = db.get_payment_receipts(status=None, limit=100, tenant_id=tenant_id)
    return render_template("reseller_payments.html", receipts=receipts, tenant=g.reseller_tenant)

@app.route("/reseller/payments/approve/<int:receipt_id>", methods=["POST"])
@reseller_required
def reseller_approve_payment(receipt_id):
    tenant_id = g.reseller_tenant_id
    ok, msg = db.approve_payment_receipt(receipt_id, admin_user=session.get("reseller_username", "Reseller"), tenant_id=tenant_id)
    if ok:
        flash(msg, "success")
    else:
        flash(msg, "danger")
    return redirect(url_for("reseller_payments"))

@app.route("/reseller/payments/reject/<int:receipt_id>", methods=["POST"])
@reseller_required
def reseller_reject_payment(receipt_id):
    tenant_id = g.reseller_tenant_id
    notes = request.form.get("notes", "Rejected by reseller staff")
    ok, msg = db.reject_payment_receipt(receipt_id, admin_user=session.get("reseller_username", "Reseller"), notes=notes, tenant_id=tenant_id)
    flash(msg, "info")
    return redirect(url_for("reseller_payments"))

@app.route("/reseller/branding")
@reseller_required
def reseller_branding():
    return render_template("reseller_branding.html", tenant=g.reseller_tenant)

@app.route("/reseller/branding/update", methods=["POST"])
@reseller_required
def reseller_update_branding():
    tenant_id = g.reseller_tenant_id
    data = {
        "service_name": request.form.get("service_name", "").strip(),
        "company_name": request.form.get("company_name", "").strip(),
        "logo_url": request.form.get("logo_url", "").strip(),
        "tagline": request.form.get("tagline", "").strip(),
        "brand_color_primary": request.form.get("brand_color_primary_text") or request.form.get("brand_color_primary") or "#00f0ff",
        "brand_color_secondary": request.form.get("brand_color_secondary_text") or request.form.get("brand_color_secondary") or "#6366f1",
        "support_phone": request.form.get("support_phone", "").strip(),
        "support_email": request.form.get("support_email", "").strip(),
        "welcome_message": request.form.get("welcome_message", "").strip()
    }
    db.update_tenant(tenant_id, data)
    flash("White-label branding and contact settings updated successfully!", "success")
    return redirect(url_for("reseller_branding"))

@app.route("/reseller/tickets")
@reseller_required
def reseller_tickets():
    tenant_id = g.reseller_tenant_id
    status = request.args.get("status", "all")
    tickets = db.get_support_tickets(tenant_id=tenant_id, status=status)
    return render_template("reseller_tickets.html", tickets=tickets, tenant=g.reseller_tenant)

@app.route("/reseller/tickets/<int:ticket_id>")
@reseller_required
def reseller_ticket_detail(ticket_id):
    tenant_id = g.reseller_tenant_id
    ticket = db.get_support_ticket(ticket_id, tenant_id=tenant_id)
    if not ticket:
        flash("Ticket not found or permission denied.", "danger")
        return redirect(url_for("reseller_tickets"))
    return render_template("reseller_ticket_detail.html", ticket=ticket, tenant=g.reseller_tenant)

@app.route("/reseller/tickets/reply/<int:ticket_id>", methods=["POST"])
@reseller_required
def reseller_reply_ticket(ticket_id):
    tenant_id = g.reseller_tenant_id
    ticket = db.get_support_ticket(ticket_id, tenant_id=tenant_id)
    if not ticket:
        flash("Ticket not found or permission denied.", "danger")
        return redirect(url_for("reseller_tickets"))

    message = request.form.get("message", "").strip()
    new_status = request.form.get("status", "in_progress")
    if message:
        db.add_ticket_message(ticket_id, sender_type="reseller", sender_name=session.get("reseller_username", "Support"), message=message)
        db.update_ticket_status(ticket_id, new_status)
        if ticket.get("subscriber_id"):
            db.create_notification(tenant_id, ticket["subscriber_id"], "New Support Reply", f"Our support team replied to your ticket '{ticket['subject']}'.", "info")
        flash("Reply sent to customer.", "success")
    return redirect(url_for("reseller_ticket_detail", ticket_id=ticket_id))

@app.route("/reseller/staff")
@reseller_required
def reseller_staff():
    tenant_id = g.reseller_tenant_id
    staff = db.get_reseller_users(tenant_id)
    return render_template("reseller_staff.html", staff_users=staff, tenant=g.reseller_tenant)

@app.route("/reseller/staff/add", methods=["POST"])
@reseller_required
def reseller_add_staff():
    tenant_id = g.reseller_tenant_id
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "staff")
    try:
        db.create_reseller_user(tenant_id, username, password, full_name=full_name, role=role)
        flash(f"Staff account '{username}' created successfully!", "success")
    except Exception as e:
        flash(f"Could not create staff account: {e}", "danger")
    return redirect(url_for("reseller_staff"))

@app.route("/reseller/reports/export-customers")
@reseller_required
def reseller_export_customers():
    tenant_id = g.reseller_tenant_id
    customers = db.get_subscribers(limit=5000, tenant_id=tenant_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Full Name", "Phone", "PPPoE Username", "Package", "Status", "Expiry Date"])
    for c in customers:
        writer.writerow([c.get("id"), c.get("username"), c.get("full_name"), c.get("phone"), c.get("pppoe_username"), c.get("package_name"), c.get("status"), c.get("sub_expiry")])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=customers_{g.reseller_tenant.get('code')}.csv"})

# ====================================================
# CUSTOMER PORTAL, SUPPORT TICKETS & BILLING HISTORY
# ====================================================
@app.route("/portal")
def customer_portal():
    return redirect(url_for("my_account"))

@app.route("/support/tickets")
def customer_tickets():
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return redirect(url_for("gatekeeper"))
    tenant_id = getattr(g, "tenant", {}).get("id", 1)
    tickets = db.get_support_tickets(tenant_id=tenant_id, subscriber_id=sub_id)
    return render_template("support_tickets.html", tickets=tickets)

@app.route("/support/tickets/new", methods=["POST"])
def customer_create_ticket():
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return redirect(url_for("gatekeeper"))
    tenant_id = getattr(g, "tenant", {}).get("id", 1)
    sub = db.get_subscriber_by_id(sub_id)
    subject = request.form.get("subject", "").strip()
    category = request.form.get("category", "general")
    priority = request.form.get("priority", "medium")
    message = request.form.get("message", "").strip()
    if not subject or not message:
        flash("Subject and message are required.", "danger")
        return redirect(url_for("customer_tickets"))

    t_id, t_num = db.create_support_ticket(tenant_id, sub_id, subject, category, priority, message, sender_name=sub.get("username") if sub else "Subscriber")
    flash(f"Support ticket {t_num} opened successfully! Our team will respond shortly.", "success")
    return redirect(url_for("customer_ticket_detail", ticket_id=t_id))

@app.route("/support/tickets/<int:ticket_id>")
def customer_ticket_detail(ticket_id):
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return redirect(url_for("gatekeeper"))
    ticket = db.get_support_ticket(ticket_id, subscriber_id=sub_id)
    if not ticket:
        flash("Ticket not found or permission denied.", "danger")
        return redirect(url_for("customer_tickets"))
    return render_template("support_ticket_detail.html", ticket=ticket)

@app.route("/support/tickets/reply/<int:ticket_id>", methods=["POST"])
def customer_reply_ticket(ticket_id):
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return redirect(url_for("gatekeeper"))
    ticket = db.get_support_ticket(ticket_id, subscriber_id=sub_id)
    if not ticket:
        flash("Ticket not found or permission denied.", "danger")
        return redirect(url_for("customer_tickets"))

    message = request.form.get("message", "").strip()
    if message:
        sub = db.get_subscriber_by_id(sub_id)
        db.add_ticket_message(ticket_id, sender_type="customer", sender_name=sub.get("username") if sub else "Subscriber", message=message)
        flash("Reply added.", "success")
    return redirect(url_for("customer_ticket_detail", ticket_id=ticket_id))

@app.route("/payment/history")
def customer_payment_history():
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return redirect(url_for("gatekeeper"))
    conn = db.get_db()
    rows = conn.execute("SELECT * FROM payment_receipts WHERE subscriber_id = ? ORDER BY id DESC", (sub_id,)).fetchall()
    conn.close()
    return render_template("payment_history.html", receipts=[dict(r) for r in rows])

@app.route("/api/notifications")
def api_get_notifications():
    sub_id = session.get("subscriber_id")
    if not sub_id:
        return jsonify({"notifications": []})
    tenant_id = getattr(g, "tenant", {}).get("id", 1)
    notifs = db.get_notifications(tenant_id=tenant_id, subscriber_id=sub_id, limit=10)
    return jsonify({"notifications": notifs})

@app.route("/api/notifications/read/<int:notif_id>", methods=["POST"])
def api_mark_notification_read(notif_id):
    sub_id = session.get("subscriber_id")
    db.mark_notification_read(notif_id, subscriber_id=sub_id)
    return jsonify({"success": True})

# ====================================================
# SUPER ADMIN SAAS TENANT CONTROL
# ====================================================
@app.route("/admin/resellers/convert/<int:inquiry_id>", methods=["POST"])
@admin_required
def admin_convert_reseller(inquiry_id):
    inquiries = db.get_reseller_inquiries(status=None, limit=1000)
    target = next((x for x in inquiries if x["id"] == inquiry_id), None)
    if not target:
        flash("Inquiry not found.", "error")
        return redirect(url_for("admin_resellers"))

    raw_code = re.sub(r"[^a-zA-Z0-9]", "", target["company_name"]).lower()[:12] or f"partner{inquiry_id}"
    code = raw_code
    counter = 1
    while db.get_tenant_by_code(code):
        code = f"{raw_code}{counter}"
        counter += 1

    temp_password = f"Sabro{secrets.token_hex(3)}"
    tenant_id = db.create_tenant({
        "code": code,
        "name": target["company_name"],
        "company_name": target["company_name"],
        "service_name": f"{target['company_name']} TV",
        "contact_name": target["contact_name"],
        "phone": target["phone"],
        "email": target.get("email", ""),
        "welcome_message": f"Welcome to {target['company_name']} IPTV, powered by Sabro Networks.",
        "status": "active",
        "max_customers": 500
    })
    
    owner_username = f"admin_{code}"
    db.create_reseller_user(tenant_id, owner_username, temp_password, full_name=target["contact_name"], email=target.get("email", ""), phone=target["phone"], role="owner")
    db.update_reseller_inquiry_status(inquiry_id, "approved")
    db.log_audit(session.get("admin_user", "admin"), "CONVERT_RESELLER", f"Converted inquiry #{inquiry_id} ({target['company_name']}) to Tenant #{tenant_id} ('{code}'). Owner: {owner_username}")
    
    flash(f"🎉 Tenant #{tenant_id} ('{code}') created! Reseller Login: Username: {owner_username} | Temporary Password: {temp_password}", "success")
    return redirect(url_for("admin_resellers"))

@app.route("/admin/tenants/create", methods=["POST"])
@admin_required
def admin_create_tenant():
    name = request.form.get("name", "").strip()
    code = re.sub(r"[^a-zA-Z0-9_]", "", request.form.get("code", "").strip().lower())
    if not code or db.get_tenant_by_code(code):
        flash("Tenant code must be unique and alphanumeric.", "error")
        return redirect(url_for("admin_resellers"))

    service_name = request.form.get("service_name") or f"{name} TV"
    tenant_id = db.create_tenant({
        "code": code,
        "name": name,
        "company_name": name,
        "service_name": service_name,
        "status": "active",
        "max_customers": safe_int(request.form.get("max_customers"), 500)
    })
    
    owner_user = request.form.get("owner_username") or f"admin_{code}"
    owner_pass = request.form.get("owner_password") or f"Sabro{secrets.token_hex(3)}"
    db.create_reseller_user(tenant_id, owner_user, owner_pass, full_name=name, role="owner")
    db.log_audit(session.get("admin_user", "admin"), "CREATE_TENANT", f"Created Tenant #{tenant_id} ('{code}'). Owner: {owner_user}")
    
    flash(f"Tenant '{name}' created successfully! Credentials: Username: {owner_user} | Password: {owner_pass}", "success")
    return redirect(url_for("admin_resellers"))

@app.route("/admin/tenants/toggle/<int:tenant_id>", methods=["POST"])
@admin_required
def admin_toggle_tenant(tenant_id):
    if tenant_id == 1:
        flash("Cannot suspend master Sabro Networks tenant.", "error")
        return redirect(url_for("admin_resellers"))
    tenant = db.get_tenant_by_id(tenant_id)
    if not tenant:
        flash("Tenant not found.", "error")
        return redirect(url_for("admin_resellers"))
    new_status = "suspended" if tenant["status"] == "active" else "active"
    db.update_tenant(tenant_id, {"status": new_status})
    db.log_audit(session.get("admin_user", "admin"), "TOGGLE_TENANT", f"Updated Tenant #{tenant_id} status to '{new_status}'")
    flash(f"Tenant #{tenant_id} '{tenant['name']}' status changed to {new_status.upper()}.", "success")
    return redirect(url_for("admin_resellers"))

# ----------------------------------------------------
# Global Error Handlers
# ----------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404
    return render_template("error.html", code=404, title="Page Not Found", message="The requested Sabro Vision stream or page does not exist or has moved."), 404

@app.errorhandler(500)
def internal_server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal server error"}), 500
    return render_template("error.html", code=500, title="Gateway Error", message="A temporary service interruption occurred. Please try again in a moment."), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
