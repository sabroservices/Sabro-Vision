import sqlite3
import os
import shutil
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BUNDLED_DB_PATH = os.path.join(os.path.dirname(__file__), "sabro_iptv.db")
DB_PATH = os.environ.get("DATABASE_PATH") or BUNDLED_DB_PATH

def get_db():
    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn

def notify_vault_write():
    """Flushes SQLite WAL and syncs vault snapshot to disk and remote cloud backends."""
    try:
        import data_vault
        data_vault.on_write_event()
    except Exception:
        pass

def init_db(force_reset=False):
    if force_reset and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except OSError:
            pass
    elif (
        not force_reset
        and os.path.abspath(DB_PATH) != os.path.abspath(BUNDLED_DB_PATH)
        and not os.path.exists(DB_PATH)
        and os.path.exists(BUNDLED_DB_PATH)
    ):
        db_dir = os.path.dirname(os.path.abspath(DB_PATH))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        shutil.copy2(BUNDLED_DB_PATH, DB_PATH)

    conn = get_db()
    cursor = conn.cursor()

    # 1. Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    # 2. Access Keys Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE NOT NULL,
        user_type TEXT NOT NULL DEFAULT 'subscriber', -- 'subscriber' (Free) or 'outsider' (Paid)
        customer_name TEXT,
        phone TEXT,
        duration_days INTEGER DEFAULT 30,
        created_at TEXT NOT NULL,
        activated_at TEXT,
        expires_at TEXT,
        status TEXT NOT NULL DEFAULT 'unused', -- 'unused', 'active', 'expired', 'revoked'
        max_devices INTEGER DEFAULT 1,
        device_token TEXT,
        package_id INTEGER,
        notes TEXT
    )
    """)

    cursor.execute("PRAGMA table_info(access_keys)")
    ak_cols = [c[1] for c in cursor.fetchall()]
    if "package_id" not in ak_cols:
        cursor.execute("ALTER TABLE access_keys ADD COLUMN package_id INTEGER")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_code ON access_keys (key_code)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_status ON access_keys (status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_expires ON access_keys (expires_at)")

    # 3. Categories Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        icon TEXT DEFAULT 'tv',
        sort_order INTEGER DEFAULT 0,
        is_hidden INTEGER DEFAULT 0
    )
    """)

    # 4. Channels Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        logo TEXT,
        stream_url TEXT NOT NULL,
        group_title TEXT,
        category TEXT DEFAULT 'Entertainment',
        is_active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        stream_type TEXT DEFAULT 'hls', -- 'hls', 'ts', 'mp4'
        playlist_id INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE SET NULL
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_category ON channels (category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_active ON channels (is_active)")

    # 5. Playlists Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS playlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'm3u', -- 'm3u' or 'xtream'
        source_url TEXT,
        username TEXT,
        password TEXT,
        channel_count INTEGER DEFAULT 0,
        last_synced_at TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 6. Admin Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        created_at TEXT NOT NULL
    )
    """)

    # 7. Favorites Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT NOT NULL,
        channel_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(key_code, channel_id),
        FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE
    )
    """)

    # 8. Subscribers Table (SABRO VISION Customers & PPPoE Hook)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        phone TEXT,
        full_name TEXT,
        email TEXT,
        pppoe_username TEXT, -- Connect Communications BRAS / PPPoE correlation
        zone TEXT,           -- e.g. Kalakot Sector 1, Kalakot Sector 2, Lyari Central
        fat_id TEXT,         -- e.g. FAT-KKT-08-P02 (Fiber distribution terminal)
        active_key_code TEXT,
        package_id INTEGER,
        status TEXT DEFAULT 'active', -- 'active', 'expired', 'suspended'
        created_at TEXT NOT NULL,
        last_login_at TEXT,
        plain_password TEXT,
        notes TEXT
    )
    """)

    # Dynamic Non-Destructive Migrations for Existing Database
    cursor.execute("PRAGMA table_info(subscribers)")
    sub_cols = [c[1] for c in cursor.fetchall()]
    migration_fields = [
        ("plain_password", "TEXT"),
        ("pppoe_username", "TEXT"),
        ("zone", "TEXT"),
        ("fat_id", "TEXT"),
        ("email", "TEXT"),
        ("status", "TEXT DEFAULT 'active'"),
        ("package_id", "INTEGER"),
        ("notes", "TEXT")
    ]
    for col_name, col_def in migration_fields:
        if col_name not in sub_cols:
            cursor.execute(f"ALTER TABLE subscribers ADD COLUMN {col_name} {col_def}")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_username ON subscribers (username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_key ON subscribers (active_key_code)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_pppoe ON subscribers (pppoe_username)")

    # 9. Packages Table (SABRO VISION Tiered Subscriptions)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        duration_days INTEGER DEFAULT 30,
        price_pkr INTEGER DEFAULT 250,
        max_connections INTEGER DEFAULT 1,
        is_active INTEGER DEFAULT 1,
        description TEXT,
        allowed_categories TEXT DEFAULT 'all',
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("PRAGMA table_info(packages)")
    pkg_cols = [c[1] for c in cursor.fetchall()]
    if "allowed_categories" not in pkg_cols:
        cursor.execute("ALTER TABLE packages ADD COLUMN allowed_categories TEXT DEFAULT 'all'")

    # 10. Subscriptions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscriber_id INTEGER NOT NULL,
        package_id INTEGER NOT NULL,
        start_date TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        status TEXT DEFAULT 'active', -- 'active', 'expired', 'suspended'
        auto_renew INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
        FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_expiry ON subscriptions (expiry_date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_status ON subscriptions (status)")

    # 11. Payment Receipts & Workflow Queue Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS payment_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscriber_id INTEGER,
        package_id INTEGER,
        amount_pkr INTEGER NOT NULL,
        payment_method TEXT NOT NULL, -- 'JazzCash', 'EasyPaisa', 'Meezan Bank', 'Cash Collection'
        transaction_ref TEXT,
        sender_number TEXT,
        proof_image TEXT,
        status TEXT DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
        reviewer_admin TEXT,
        reviewed_at TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(subscriber_id) REFERENCES subscribers(id) ON DELETE SET NULL,
        FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE SET NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_receipt_status ON payment_receipts (status)")

    # 12. Audit Logs Table (Admin Actions & RBAC)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs (created_at)")

    # 13. Connection Events Table (Live Device / App Tracking)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS connection_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        client_ip TEXT,
        user_agent TEXT,
        stream_id INTEGER,
        action TEXT DEFAULT 'PLAY',
        created_at TEXT NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_time ON connection_events (created_at)")

    # 14. Reseller & White-Label ISP Inquiries Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reseller_inquiries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name TEXT NOT NULL,
        contact_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT,
        city TEXT,
        subscriber_count TEXT,
        partner_type TEXT DEFAULT 'white_label',
        notes TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reseller_status ON reseller_inquiries (status)")

    cursor.execute("PRAGMA table_info(channels)")
    ch_cols = [c[1] for c in cursor.fetchall()]
    if "epg_channel_id" not in ch_cols:
        cursor.execute("ALTER TABLE channels ADD COLUMN epg_channel_id TEXT")
    if "health_status" not in ch_cols:
        cursor.execute("ALTER TABLE channels ADD COLUMN health_status TEXT DEFAULT 'unknown'")
    if "response_time_ms" not in ch_cols:
        cursor.execute("ALTER TABLE channels ADD COLUMN response_time_ms INTEGER DEFAULT 0")
    if "last_checked_at" not in ch_cols:
        cursor.execute("ALTER TABLE channels ADD COLUMN last_checked_at TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channels_health ON channels(health_status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channels_active_health ON channels(is_active, health_status)")

    # 15. Schema Migrations Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS schema_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """)

    # 16. Multi-Tenant SaaS: Tenants Table (Sabro Networks + White-Label ISPs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        company_name TEXT,
        service_name TEXT NOT NULL DEFAULT 'SABRO VISION',
        tagline TEXT,
        custom_domain TEXT UNIQUE,
        subdomain TEXT UNIQUE,
        logo_url TEXT,
        brand_color_primary TEXT DEFAULT '#ff6b00',
        brand_color_secondary TEXT DEFAULT '#f59e0b',
        contact_name TEXT,
        email TEXT,
        phone TEXT,
        whatsapp TEXT,
        welcome_message TEXT,
        support_email TEXT,
        support_phone TEXT,
        status TEXT DEFAULT 'active', -- 'active', 'suspended', 'pending'
        max_customers INTEGER DEFAULT 500,
        max_active_subs INTEGER DEFAULT 500,
        max_devices_per_user INTEGER DEFAULT 1,
        allowed_features TEXT DEFAULT 'all',
        created_at TEXT NOT NULL,
        notes TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_code ON tenants (code)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_status ON tenants (status)")

    # 17. Multi-Tenant SaaS: Reseller Administrators & Staff Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reseller_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        phone TEXT,
        role TEXT DEFAULT 'owner', -- 'owner', 'staff'
        status TEXT DEFAULT 'active', -- 'active', 'suspended'
        created_at TEXT NOT NULL,
        last_login_at TEXT,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reseller_username ON reseller_users (username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reseller_tenant ON reseller_users (tenant_id)")

    # 18. Multi-Tenant Support Tickets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_number TEXT UNIQUE NOT NULL,
        tenant_id INTEGER DEFAULT 1,
        subscriber_id INTEGER,
        subject TEXT NOT NULL,
        category TEXT DEFAULT 'general', -- 'general', 'billing', 'streaming', 'account'
        priority TEXT DEFAULT 'medium', -- 'low', 'medium', 'high', 'urgent'
        status TEXT DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'closed'
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_tenant ON support_tickets (tenant_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_subscriber ON support_tickets (subscriber_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets (status)")

    # 19. Support Ticket Messages Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ticket_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL, -- 'customer', 'reseller', 'admin'
        sender_name TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ticket_messages_tid ON ticket_messages (ticket_id)")

    # 20. Platform & Tenant Notifications Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER DEFAULT 1,
        subscriber_id INTEGER,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info', -- 'info', 'success', 'warning', 'danger'
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
        FOREIGN KEY(subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_tenant ON notifications (tenant_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_sub ON notifications (subscriber_id)")

    # 21. Sabro Networks ISP Real-time Verification Cache Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS isp_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pppoe_username TEXT UNIQUE NOT NULL,
        phone TEXT,
        customer_name TEXT,
        is_active INTEGER DEFAULT 1,
        isp_package TEXT,
        last_verified_at TEXT NOT NULL,
        raw_response TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_isp_pppoe ON isp_verifications (pppoe_username)")

    # Multi-Tenant Column Migrations for Existing Tables
    # A. Subscribers Table Migrations
    cursor.execute("PRAGMA table_info(subscribers)")
    s_cols = [c[1] for c in cursor.fetchall()]
    if "tenant_id" not in s_cols:
        cursor.execute("ALTER TABLE subscribers ADD COLUMN tenant_id INTEGER DEFAULT 1")
    if "is_sabro_isp" not in s_cols:
        cursor.execute("ALTER TABLE subscribers ADD COLUMN is_sabro_isp INTEGER DEFAULT 0")
    if "isp_status" not in s_cols:
        cursor.execute("ALTER TABLE subscribers ADD COLUMN isp_status TEXT DEFAULT 'unlinked'")
    if "isp_verified_at" not in s_cols:
        cursor.execute("ALTER TABLE subscribers ADD COLUMN isp_verified_at TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_tenant ON subscribers (tenant_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_is_isp ON subscribers (is_sabro_isp)")

    # B. Packages Table Migrations
    cursor.execute("PRAGMA table_info(packages)")
    p_cols = [c[1] for c in cursor.fetchall()]
    if "tenant_id" not in p_cols:
        cursor.execute("ALTER TABLE packages ADD COLUMN tenant_id INTEGER")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pkg_tenant ON packages (tenant_id)")

    # C. Access Keys Table Migrations
    cursor.execute("PRAGMA table_info(access_keys)")
    ak_cols_all = [c[1] for c in cursor.fetchall()]
    if "tenant_id" not in ak_cols_all:
        cursor.execute("ALTER TABLE access_keys ADD COLUMN tenant_id INTEGER DEFAULT 1")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ak_tenant ON access_keys (tenant_id)")

    # D. Payment Receipts Table Migrations
    cursor.execute("PRAGMA table_info(payment_receipts)")
    pr_cols = [c[1] for c in cursor.fetchall()]
    if "tenant_id" not in pr_cols:
        cursor.execute("ALTER TABLE payment_receipts ADD COLUMN tenant_id INTEGER DEFAULT 1")
    if "invoice_number" not in pr_cols:
        cursor.execute("ALTER TABLE payment_receipts ADD COLUMN invoice_number TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_receipt_tenant ON payment_receipts (tenant_id)")

    # Ensure Master Tenant 1 (Sabro Networks) exists
    now_str = datetime.now().isoformat()
    cursor.execute("""
        INSERT OR IGNORE INTO tenants (
            id, code, name, company_name, service_name, tagline,
            brand_color_primary, brand_color_secondary, status, created_at, notes
        ) VALUES (
            1, 'sabro', 'Sabro Networks', 'Sabro Networks ISP', 'SABRO VISION',
            'Ultra High-Definition IPTV Middleware - Sabro Networks',
            '#ff6b00', '#f59e0b', 'active', ?, 'Master platform tenant for Sabro Networks'
        )
    """, (now_str,))


    # Seed strictly 2 official packages:
    # 1. Sabro Broadband All-Access Pass: 0 PKR, all categories, 2 screens (code='basic')
    # 2. Sabro Vision Commercial Pass: 150 PKR, all categories, 1 screen (code='all_in_one')
    now_str = datetime.now().isoformat()
    official_pkgs = [
        ("Sabro Broadband All-Access Pass", "basic", 30, 0, 2, 1, "Complimentary 100% FREE with Sabro Networks Fiber Broadband. 2 Screens. All 11,459+ channels unlocked with zero charges.", "all"),
        ("Sabro Vision Commercial Pass", "all_in_one", 30, 150, 1, 1, "Commercial All-Access Pass for outside customers. Stream all 11,459+ live channels, sports, and movies in 1080p Full HD on 1 screen. Flat 150 PKR.", "all")
    ]

    for p in official_pkgs:
        cursor.execute("""
            INSERT INTO packages (name, code, duration_days, price_pkr, max_connections, is_active, description, allowed_categories, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET
                name = excluded.name,
                price_pkr = excluded.price_pkr,
                max_connections = excluded.max_connections,
                allowed_categories = excluded.allowed_categories,
                description = excluded.description,
                is_active = 1
        """, (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], now_str))

    # Deactivate all legacy packages so ONLY the 2 official packages remain active
    cursor.execute("UPDATE packages SET is_active = 0 WHERE code NOT IN ('basic', 'all_in_one')")
    cursor.execute("UPDATE packages SET name = 'Sabro Vision Commercial Pass', price_pkr = 150, allowed_categories = 'all', max_connections = 1, is_active = 1 WHERE code = 'all_in_one'")
    cursor.execute("UPDATE packages SET name = 'Sabro Broadband All-Access Pass', price_pkr = 0, allowed_categories = 'all', max_connections = 2, is_active = 1 WHERE code = 'basic'")

    conn.commit()
    conn.close()

# ----------------------------------------------------
# Settings Helpers
# ----------------------------------------------------
def get_settings():
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    settings = {r["key"]: r["value"] for r in rows}
    
    # Defaults
    settings.setdefault("platform_name", "SABRO VISION")
    settings.setdefault("tagline", "Ultra High-Definition IPTV Middleware - Sabro Networks")
    settings.setdefault("version", "v1.0")
    settings.setdefault("isp_partner", "Connect Communications")
    settings.setdefault("currency", "PKR")
    settings.setdefault("monthly_price", "150")
    settings.setdefault("phone", "0300-1234567")
    settings.setdefault("whatsapp", "923001234567")
    settings.setdefault("jazzcash_title", "Sabro Networks")
    settings.setdefault("jazzcash_number", "0300-1234567")
    settings.setdefault("easypaisa_title", "Sabro Networks")
    settings.setdefault("easypaisa_number", "0300-1234567")
    settings.setdefault("bank_name", "Meezan Bank")
    settings.setdefault("bank_account_title", "Sabro Networks IPTV")
    settings.setdefault("bank_account_number", "0101-0105678901")
    settings.setdefault("stream_proxy_enabled", "1")

    # ISP Integration Settings (Sabro Networks Broadband Entitlement)
    settings.setdefault("sabro_isp_api_url", "")
    settings.setdefault("sabro_isp_api_key", "")
    settings.setdefault("sabro_isp_auto_verify", "1")
    settings.setdefault("sabro_isp_free_screens", "2")
    settings.setdefault("sabro_isp_status", "manual_fallback")

    # Outside Customer & Multi-Screen Pricing Settings
    settings.setdefault("outside_customer_default_price", "150")
    settings.setdefault("outside_customer_default_screens", "1")
    settings.setdefault("expiry_grace_period_days", "0")
    settings.setdefault("on_expiry_action", "block_stream")
    settings.setdefault("maintenance_mode", "0")

    # Persistent secure session key
    if "session_secret_key" not in settings:
        secret = secrets.token_hex(32)
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('session_secret_key', ?)", (secret,))
        conn.commit()
        conn.close()
        settings["session_secret_key"] = secret

    return settings

def update_setting(key, value):
    conn = get_db()
    conn.execute("""
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, str(value)))
    conn.commit()
    conn.close()
    notify_vault_write()

# ----------------------------------------------------
# Key Management & Voucher Helpers
# ----------------------------------------------------
def generate_key_code(user_type='subscriber', prefix=None):
    if not prefix:
        prefix = "SABRO-FREE" if user_type == 'subscriber' else "SABRO-PAID"
    token = secrets.token_hex(3).upper()
    token2 = secrets.token_hex(2).upper()
    return f"{prefix}-{token}-{token2}"

def create_access_key(user_type='subscriber', customer_name='', phone='', duration_days=30, max_devices=1, notes='', package_id=None):
    conn = get_db()
    now_str = datetime.now().isoformat()
    key_code = generate_key_code(user_type)
    
    conn.execute("""
        INSERT INTO access_keys 
        (key_code, user_type, customer_name, phone, duration_days, created_at, status, max_devices, notes, package_id)
        VALUES (?, ?, ?, ?, ?, ?, 'unused', ?, ?, ?)
    """, (key_code, user_type, customer_name, phone, int(duration_days), now_str, int(max_devices), notes, int(package_id) if package_id else None))
    
    conn.commit()
    conn.close()
    notify_vault_write()
    return key_code

def bulk_generate_keys(count=10, user_type='subscriber', duration_days=30, notes='', package_id=None):
    conn = get_db()
    now_str = datetime.now().isoformat()
    generated_keys = []
    
    for _ in range(count):
        key_code = generate_key_code(user_type)
        conn.execute("""
            INSERT INTO access_keys 
            (key_code, user_type, duration_days, created_at, status, max_devices, notes, package_id)
            VALUES (?, ?, ?, ?, 'unused', 1, ?, ?)
        """, (key_code, user_type, int(duration_days), now_str, notes, int(package_id) if package_id else None))
        generated_keys.append(key_code)
        
    conn.commit()
    conn.close()
    notify_vault_write()
    return generated_keys

def validate_key(key_code, device_token=None):
    """
    Checks if key exists and is valid.
    Returns (is_valid: bool, status_message: str, key_row_dict: dict)
    """
    if not key_code:
        return False, "Access key is required.", None

    clean_key = key_code.strip().upper()
    conn = get_db()
    row = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (clean_key,)).fetchone()
    
    if not row:
        conn.close()
        return False, "Invalid access key. Please verify your code.", None

    key_data = dict(row)
    now = datetime.now()

    # Check revoked
    if key_data["status"] == "revoked":
        conn.close()
        return False, "This access key has been deactivated by administrator.", key_data

    # Check expiration if active
    if key_data["status"] == "active" and key_data["expires_at"]:
        exp_time = datetime.fromisoformat(key_data["expires_at"])
        if now > exp_time:
            # Mark expired
            conn.execute("UPDATE access_keys SET status = 'expired' WHERE id = ?", (key_data["id"],))
            conn.commit()
            conn.close()
            key_data["status"] = "expired"
            return False, f"Your access key expired on {exp_time.strftime('%Y-%m-%d %H:%M')}. Please renew your monthly pass.", key_data

    # Check device lock if active
    if key_data["status"] == "active" and device_token and key_data["device_token"]:
        if key_data["device_token"] != device_token:
            # If max_devices is 1 and device doesn't match
            if key_data["max_devices"] <= 1:
                conn.close()
                return False, "This key is bound to another device. Single-device license policy.", key_data

    conn.close()
    return True, "Key is valid.", key_data

def activate_key(key_code, device_token):
    """
    Activates an unused key for 30 days starting right now, or re-validates an already active key.
    """
    clean_key = key_code.strip().upper()
    conn = get_db()
    row = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (clean_key,)).fetchone()
    
    if not row:
        conn.close()
        return False, "Invalid access key.", None

    key_data = dict(row)
    now = datetime.now()

    if key_data["status"] == "revoked":
        conn.close()
        return False, "This access key has been revoked by admin.", None

    if key_data["status"] == "expired":
        conn.close()
        return False, "This access key has expired. Please contact Sabro Vision for renewal.", None

    if key_data["status"] == "unused":
        # Calculate expiration
        days = key_data["duration_days"] or 30
        expires = now + timedelta(days=days)
        
        conn.execute("""
            UPDATE access_keys
            SET status = 'active',
                activated_at = ?,
                expires_at = ?,
                device_token = ?
            WHERE id = ?
        """, (now.isoformat(), expires.isoformat(), device_token, key_data["id"]))
        conn.commit()
        
        updated_row = conn.execute("SELECT * FROM access_keys WHERE id = ?", (key_data["id"],)).fetchone()
        conn.close()
        return True, f"Key activated successfully! Valid for {days} days until {expires.strftime('%Y-%m-%d')}.", dict(updated_row)

    if key_data["status"] == "active":
        # Already active, verify expiration
        exp_time = datetime.fromisoformat(key_data["expires_at"])
        if now > exp_time:
            conn.execute("UPDATE access_keys SET status = 'expired' WHERE id = ?", (key_data["id"],))
            conn.commit()
            conn.close()
            return False, "This access key has expired.", None
        
        # If no device bound yet, bind this device
        if not key_data["device_token"]:
            conn.execute("UPDATE access_keys SET device_token = ? WHERE id = ?", (device_token, key_data["id"]))
            conn.commit()
        elif key_data["device_token"] != device_token and key_data["max_devices"] <= 1:
            conn.close()
            return False, "This key is locked to another device.", None

        conn.close()
        days_left = max(0, (exp_time - now).days)
        return True, f"Session verified. {days_left} days remaining on this pass.", key_data

    conn.close()
    return False, "Unable to activate key.", None

def renew_key(key_id, extra_days=30):
    conn = get_db()
    row = conn.execute("SELECT * FROM access_keys WHERE id = ?", (key_id,)).fetchone()
    if not row:
        conn.close()
        return False, "Key not found"
        
    now = datetime.now()
    if row["expires_at"]:
        curr_exp = datetime.fromisoformat(row["expires_at"])
        base_time = max(curr_exp, now)
    else:
        base_time = now

    new_exp = base_time + timedelta(days=extra_days)
    conn.execute("""
        UPDATE access_keys 
        SET expires_at = ?, status = 'active'
        WHERE id = ?
    """, (new_exp.isoformat(), key_id))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True, f"Key renewed until {new_exp.strftime('%Y-%m-%d')} (+{extra_days} days)"

def revoke_key(key_id):
    conn = get_db()
    conn.execute("UPDATE access_keys SET status = 'revoked' WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def delete_key(key_id):
    conn = get_db()
    conn.execute("DELETE FROM access_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def reset_device_lock(key_id):
    conn = get_db()
    conn.execute("UPDATE access_keys SET device_token = NULL WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def get_key_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM access_keys").fetchone()["c"]
    active = conn.execute("SELECT COUNT(*) as c FROM access_keys WHERE status = 'active'").fetchone()["c"]
    unused = conn.execute("SELECT COUNT(*) as c FROM access_keys WHERE status = 'unused'").fetchone()["c"]
    expired = conn.execute("SELECT COUNT(*) as c FROM access_keys WHERE status = 'expired'").fetchone()["c"]
    subscribers = conn.execute("SELECT COUNT(*) as c FROM access_keys WHERE user_type = 'subscriber'").fetchone()["c"]
    outsiders = conn.execute("SELECT COUNT(*) as c FROM access_keys WHERE user_type = 'outsider'").fetchone()["c"]
    channels_count = conn.execute("SELECT COUNT(*) as c FROM channels WHERE is_active = 1").fetchone()["c"]
    conn.close()
    return {
        "total": total,
        "active": active,
        "unused": unused,
        "expired": expired,
        "subscribers": subscribers,
        "outsiders": outsiders,
        "channels": channels_count
    }

# ----------------------------------------------------
# Channel & Category Helpers
# ----------------------------------------------------
def parse_allowed_categories(raw_val):
    """
    Parses allowed_categories from package model or parameter.
    Returns:
        None if 'all', '*', '', or None (meaning 100% unrestricted catalog access).
        A set of lowercase category strings (e.g. {'comedy'} or {'news', 'business'}).
    """
    if not raw_val:
        return None
    if isinstance(raw_val, (set, list, tuple)):
        clean = {str(c).strip().lower() for c in raw_val if str(c).strip()}
        return None if ("all" in clean or "*" in clean or not clean) else clean
    s = str(raw_val).strip()
    if s.lower() in ("all", "*", ""):
        return None
    cats = {p.strip().lower() for p in s.split(",") if p.strip()}
    if "all" in cats or "*" in cats or not cats:
        return None
    return cats

def get_subscriber_allowed_categories(subscriber_id=None, key_code=None):
    """
    Determines the package tier and allowed categories for a subscriber or access key.
    Returns: (is_all: bool, allowed_categories_set: set[str], package_name: str)
    """
    conn = get_db()
    pkg = None

    if subscriber_id:
        sub_row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (subscriber_id,)).fetchone()
        if sub_row:
            sub_dict = dict(sub_row)
            # Check active subscription first
            active_sub = conn.execute("""
                SELECT s.*, p.name as pkg_name, p.allowed_categories
                FROM subscriptions s
                JOIN packages p ON p.id = s.package_id
                WHERE s.subscriber_id = ? AND s.status = 'active'
                ORDER BY s.id DESC LIMIT 1
            """, (subscriber_id,)).fetchone()
            if active_sub:
                pkg = {
                    "name": active_sub["pkg_name"],
                    "allowed_categories": active_sub["allowed_categories"]
                }
            elif sub_dict.get("package_id"):
                pkg_row = conn.execute("SELECT * FROM packages WHERE id = ?", (sub_dict["package_id"],)).fetchone()
                if pkg_row:
                    pkg = dict(pkg_row)
            elif sub_dict.get("active_key_code"):
                key_code = sub_dict["active_key_code"]

    if not pkg and key_code:
        clean_k = key_code.strip().upper()
        krow = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (clean_k,)).fetchone()
        if krow:
            kdata = dict(krow)
            if kdata.get("package_id"):
                pkg_row = conn.execute("SELECT * FROM packages WHERE id = ?", (kdata["package_id"],)).fetchone()
                if pkg_row:
                    pkg = dict(pkg_row)
            else:
                # Check if subscriber with package is bound to key
                sub_bound = conn.execute("SELECT * FROM subscribers WHERE UPPER(active_key_code) = ?", (clean_k,)).fetchone()
                if sub_bound and sub_bound["package_id"]:
                    pkg_row = conn.execute("SELECT * FROM packages WHERE id = ?", (sub_bound["package_id"],)).fetchone()
                    if pkg_row:
                        pkg = dict(pkg_row)

    conn.close()

    if not pkg:
        return True, set(), "Sabro All-Access Master VIP"

    raw_val = pkg.get("allowed_categories")
    cat_set = parse_allowed_categories(raw_val)
    if cat_set is None:
        return True, set(), pkg.get("name", "Sabro All-Access Master VIP")

    return False, cat_set, pkg.get("name", "Custom Package")

def can_subscriber_access_channel(subscriber_id=None, key_code=None, channel_id=None, channel_obj=None):
    """
    Checks whether a subscriber or access key holder is authorized to view this channel.
    Returns bool: True if allowed, False if channel requires a package upgrade.
    """
    is_all, allowed_cats, _ = get_subscriber_allowed_categories(subscriber_id=subscriber_id, key_code=key_code)
    if is_all:
        return True

    if not channel_obj and channel_id:
        channel_obj = get_channel_by_id(channel_id)

    if not channel_obj:
        return False

    cat = (channel_obj.get("category") or "").strip().lower()
    return cat in allowed_cats

def get_categories(allowed_categories=None):
    conn = get_db()
    query = """
        SELECT c.*, COUNT(ch.id) as channel_count
        FROM categories c
        LEFT JOIN channels ch ON ch.category = c.name AND ch.is_active = 1
        WHERE c.is_hidden = 0
    """
    params = []
    cat_set = parse_allowed_categories(allowed_categories)
    if cat_set:
        placeholders = ",".join("?" for _ in cat_set)
        query += f" AND LOWER(c.name) IN ({placeholders})"
        params.extend(list(cat_set))

    query += """
        GROUP BY c.id
        ORDER BY c.sort_order ASC, c.name ASC
    """
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_channels_count(category=None, search=None, active_only=True, health_status=None, allowed_categories=None):
    conn = get_db()
    query = "SELECT COUNT(*) as c FROM channels WHERE 1=1"
    params = []
    
    if active_only:
        query += " AND is_active = 1"
    if category and category.lower() != 'all':
        query += " AND category = ?"
        params.append(category)
    if health_status and health_status.lower() != 'all':
        query += " AND health_status = ?"
        params.append(health_status)
    if search:
        query += " AND (name LIKE ? OR group_title LIKE ?)"
        wild = f"%{search}%"
        params.extend([wild, wild])

    cat_set = parse_allowed_categories(allowed_categories)
    if cat_set:
        placeholders = ",".join("?" for _ in cat_set)
        query += f" AND LOWER(category) IN ({placeholders})"
        params.extend(list(cat_set))

    count = conn.execute(query, params).fetchone()["c"]
    conn.close()
    return count

def get_channels(category=None, search=None, active_only=True, health_status=None, allowed_categories=None, limit=None, offset=0):
    conn = get_db()
    query = "SELECT * FROM channels WHERE 1=1"
    params = []
    
    if active_only:
        query += " AND is_active = 1"
    if category and category.lower() != 'all':
        query += " AND category = ?"
        params.append(category)
    if health_status and health_status.lower() != 'all':
        query += " AND health_status = ?"
        params.append(health_status)
    if search:
        query += " AND (name LIKE ? OR group_title LIKE ?)"
        wild = f"%{search}%"
        params.extend([wild, wild])

    cat_set = parse_allowed_categories(allowed_categories)
    if cat_set:
        placeholders = ",".join("?" for _ in cat_set)
        query += f" AND LOWER(category) IN ({placeholders})"
        params.extend(list(cat_set))

    query += " ORDER BY sort_order ASC, name ASC"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_channel_by_id(channel_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def add_channel(name, stream_url, logo="", category="Entertainment", group_title="", stream_type="hls", sort_order=0):
    conn = get_db()
    now_str = datetime.now().isoformat()
    # Ensure category exists
    conn.execute("INSERT OR IGNORE INTO categories (name, icon) VALUES (?, 'tv')", (category,))
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO channels (name, logo, stream_url, group_title, category, stream_type, sort_order, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, logo, stream_url, group_title or category, category, stream_type, sort_order, now_str))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    notify_vault_write()
    return new_id

def update_channel(channel_id, name, stream_url, logo="", category="Entertainment", group_title="", is_active=1, stream_type="hls"):
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO categories (name, icon) VALUES (?, 'tv')", (category,))
    conn.execute("""
        UPDATE channels
        SET name = ?, stream_url = ?, logo = ?, category = ?, group_title = ?, is_active = ?, stream_type = ?
        WHERE id = ?
    """, (name, stream_url, logo, category, group_title or category, int(is_active), stream_type, channel_id))
    conn.commit()
    conn.close()

def delete_channel(channel_id):
    conn = get_db()
    conn.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
    conn.commit()
    conn.close()

# ----------------------------------------------------
# Favorites
# ----------------------------------------------------
def toggle_favorite(key_code, channel_id):
    conn = get_db()
    fav = conn.execute("SELECT id FROM favorites WHERE key_code = ? AND channel_id = ?", (key_code, channel_id)).fetchone()
    if fav:
        conn.execute("DELETE FROM favorites WHERE id = ?", (fav["id"],))
        is_fav = False
    else:
        conn.execute("INSERT INTO favorites (key_code, channel_id, created_at) VALUES (?, ?, ?)",
                     (key_code, channel_id, datetime.now().isoformat()))
        is_fav = True
    conn.commit()
    conn.close()
    return is_fav

def get_favorites(key_code):
    conn = get_db()
    rows = conn.execute("""
        SELECT ch.* FROM channels ch
        JOIN favorites f ON f.channel_id = ch.id
        WHERE f.key_code = ? AND ch.is_active = 1
        ORDER BY ch.name ASC
    """, (key_code,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------------------------------------------
# Subscriber User Accounts & Key Safety System
# ----------------------------------------------------
def create_subscriber(username, password, phone="", full_name="", key_code="", device_token=None):
    """
    Registers a new subscriber account. Optionally binds and activates their initial access key.
    Returns (success: bool, message: str, subscriber_data: dict)
    """
    clean_user = username.strip().lower()
    if not clean_user or len(clean_user) < 3:
        return False, "Username must be at least 3 characters long.", None
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long.", None

    conn = get_db()
    existing = conn.execute("SELECT id FROM subscribers WHERE LOWER(username) = ?", (clean_user,)).fetchone()
    if existing:
        conn.close()
        return False, "Username is already taken. Please choose another username.", None

    now_str = datetime.now().isoformat()
    pw_hash = generate_password_hash(password)

    # If key_code was provided, validate and activate it
    activated_key = None
    if key_code and key_code.strip():
        clean_key = key_code.strip().upper()
        act_ok, act_msg, key_data = activate_key(clean_key, device_token or "")
        if not act_ok:
            conn.close()
            return False, f"Key Error: {act_msg}", None
        activated_key = key_data["key_code"]

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO subscribers (username, password_hash, phone, full_name, active_key_code, created_at, last_login_at, plain_password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (clean_user, pw_hash, phone.strip(), full_name.strip(), activated_key, now_str, now_str, password))
    conn.commit()
    new_id = cursor.lastrowid
    
    sub_row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (new_id,)).fetchone()
    conn.close()
    notify_vault_write()
    return True, "Account created successfully! Your key is saved safely in your account.", dict(sub_row)

def auto_provision_subscriber_from_key(key_code, device_token=None):
    """
    Automatic Key-to-Account Provisioning System:
    The user enters their access key code:
    1. Validates the key.
    2. If subscriber already exists with this key:
       - Syncs device token to prevent accidental lockout.
       - Returns the existing subscriber, is_new=False, and their plain password.
    3. If subscriber does NOT exist yet:
       - Automatically generates a clean, readable username (e.g. sabro_98ad2b).
       - Automatically generates an easy-to-type, memorable password (e.g. sabro4918).
       - Saves subscriber with plain_password for instant retrieval & display.
       - Activates the key and binds it to the device.
       - Returns (success, message, sub_data, is_new=True, generated_pass, key_data).
    """
    clean_key = key_code.strip().upper()
    conn = get_db()
    key_row = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (clean_key,)).fetchone()
    if not key_row:
        conn.close()
        return False, "Invalid access key. Please check your key code.", None, False, None, None

    key_data = dict(key_row)
    now = datetime.now()

    if key_data["status"] == "revoked":
        conn.close()
        return False, "This access key has been revoked by admin.", None, False, None, key_data

    if key_data["status"] == "expired":
        conn.close()
        return False, "This access key has expired. Please contact Sabro Vision for renewal.", None, False, None, key_data

    # Check if subscriber already exists for this key
    sub_row = conn.execute("SELECT * FROM subscribers WHERE UPPER(active_key_code) = ?", (clean_key,)).fetchone()
    
    if sub_row:
        sub_data = dict(sub_row)
        # Verify expiration if active
        if key_data.get("expires_at"):
            exp_time = datetime.fromisoformat(key_data["expires_at"])
            if now > exp_time:
                conn.execute("UPDATE access_keys SET status = 'expired' WHERE id = ?", (key_data["id"],))
                conn.commit()
                conn.close()
                return False, "This access key has expired.", None, False, None, key_data

        # Sync device token to prevent accidental lockout
        if device_token:
            conn.execute("UPDATE access_keys SET device_token = ? WHERE id = ?", (device_token, key_data["id"]))
            
        now_str = now.isoformat()
        conn.execute("UPDATE subscribers SET last_login_at = ? WHERE id = ?", (now_str, sub_data["id"]))
        conn.commit()
        
        # Reload updated key data
        key_data = dict(conn.execute("SELECT * FROM access_keys WHERE id = ?", (key_data["id"],)).fetchone())
        conn.close()
        return True, f"Welcome back, {sub_data['username']}! Logged in automatically.", sub_data, False, sub_data.get("plain_password"), key_data

    # Key does not have a subscriber yet -> auto-generate username & password
    # Derive clean username from key code
    key_alphanum = "".join(c for c in clean_key if c.isalnum()).lower()
    for pfx in ["sabro", "free", "paid"]:
        if key_alphanum.startswith(pfx):
            key_alphanum = key_alphanum[len(pfx):]
            
    suffix = key_alphanum[:6] if len(key_alphanum) >= 4 else secrets.token_hex(3)
    cand_user = f"sabro_{suffix}"
    
    # Ensure username uniqueness
    existing = conn.execute("SELECT id FROM subscribers WHERE LOWER(username) = ?", (cand_user,)).fetchone()
    if existing:
        cand_user = f"sabro_{suffix}_{secrets.randbelow(900) + 100}"

    # Generate easy-to-type, memorable password (e.g. sabro + 4 digits: sabro7821)
    cand_pass = f"sabro{secrets.randbelow(9000) + 1000}"
    pw_hash = generate_password_hash(cand_pass)

    # Activate key if unused
    days = key_data["duration_days"] or 30
    if key_data["status"] == "unused":
        expires = now + timedelta(days=days)
        conn.execute("""
            UPDATE access_keys
            SET status = 'active',
                activated_at = ?,
                expires_at = ?,
                device_token = ?
            WHERE id = ?
        """, (now.isoformat(), expires.isoformat(), device_token or "", key_data["id"]))
        conn.commit()
    elif key_data["status"] == "active":
        if device_token:
            conn.execute("UPDATE access_keys SET device_token = ? WHERE id = ?", (device_token, key_data["id"]))
            conn.commit()

    now_str = now.isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO subscribers (username, password_hash, phone, full_name, active_key_code, package_id, created_at, last_login_at, plain_password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (cand_user, pw_hash, "", f"Subscriber {suffix.upper()}", clean_key, key_data.get("package_id"), now_str, now_str, cand_pass))
    conn.commit()
    new_sub_id = cursor.lastrowid
    
    # If key has a package assigned, activate subscription
    if key_data.get("package_id"):
        pkg_id = int(key_data["package_id"])
        conn.execute("""
            INSERT INTO subscriptions (subscriber_id, package_id, start_date, expiry_date, status, auto_renew, created_at)
            VALUES (?, ?, ?, ?, 'active', 0, ?)
        """, (new_sub_id, pkg_id, now_str, (now + timedelta(days=days)).isoformat(), now_str))
        conn.commit()

    new_sub_row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (new_sub_id,)).fetchone()
    updated_key_row = conn.execute("SELECT * FROM access_keys WHERE id = ?", (key_data["id"],)).fetchone()
    conn.close()
    notify_vault_write()

    return True, "Account created automatically! Your login credentials are saved safely.", dict(new_sub_row), True, cand_pass, dict(updated_key_row)

def authenticate_subscriber(username, password):
    """
    Authenticates subscriber with username and password.
    Returns (success: bool, message: str, subscriber_data: dict)
    """
    clean_user = username.strip().lower()
    conn = get_db()
    row = conn.execute("SELECT * FROM subscribers WHERE LOWER(username) = ?", (clean_user,)).fetchone()
    if not row:
        conn.close()
        return False, "Invalid username or password.", None

    sub_data = dict(row)
    from werkzeug.security import check_password_hash
    if not check_password_hash(sub_data["password_hash"], password):
        conn.close()
        return False, "Invalid username or password.", None

    now_str = datetime.now().isoformat()
    conn.execute("UPDATE subscribers SET last_login_at = ? WHERE id = ?", (now_str, sub_data["id"]))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True, f"Welcome back, {sub_data['username']}!", sub_data

def get_subscriber_by_id(sub_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (sub_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_subscriber_by_username(username):
    if not username:
        return None
    clean_user = username.strip().lower()
    conn = get_db()
    row = conn.execute("SELECT * FROM subscribers WHERE LOWER(username) = ?", (clean_user,)).fetchone()
    conn.close()
    return dict(row) if row else None

def sync_subscriber_device(key_code, device_token):
    """
    Syncs/updates the active key's device_token for an authenticated subscriber.
    Prevents account lockout when subscriber logs in on a new device or after clearing cache.
    """
    if not key_code or not device_token:
        return
    conn = get_db()
    conn.execute("UPDATE access_keys SET device_token = ? WHERE UPPER(key_code) = ?", (device_token, key_code.strip().upper()))
    conn.commit()
    conn.close()

def link_key_to_subscriber(sub_id, key_code, device_token=None):
    """
    Binds a new or renewed access key to subscriber's account.
    If the key is already active, binds device_token to this subscriber.
    """
    clean_key = key_code.strip().upper()
    conn = get_db()
    row = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (clean_key,)).fetchone()
    if not row:
        conn.close()
        return False, "Invalid access key.", None

    key_data = dict(row)
    now = datetime.now()

    if key_data["status"] == "revoked":
        conn.close()
        return False, "This access key has been revoked by admin.", None

    if key_data["status"] == "expired":
        conn.close()
        return False, "This access key has expired. Please contact Sabro Vision for renewal.", None

    days = key_data["duration_days"] or 30
    if key_data["status"] == "unused":
        expires = now + timedelta(days=days)
        conn.execute("""
            UPDATE access_keys
            SET status = 'active',
                activated_at = ?,
                expires_at = ?,
                device_token = ?
            WHERE id = ?
        """, (now.isoformat(), expires.isoformat(), device_token or "", key_data["id"]))
        conn.commit()
    elif key_data["status"] == "active":
        if key_data.get("expires_at"):
            exp_time = datetime.fromisoformat(key_data["expires_at"])
            if now > exp_time:
                conn.execute("UPDATE access_keys SET status = 'expired' WHERE id = ?", (key_data["id"],))
                conn.commit()
                conn.close()
                return False, "This access key has expired.", None
        if device_token:
            conn.execute("UPDATE access_keys SET device_token = ? WHERE id = ?", (device_token, key_data["id"]))
            conn.commit()

    if key_data.get("package_id"):
        pkg_id = int(key_data["package_id"])
        conn.execute("UPDATE subscribers SET active_key_code = ?, package_id = ? WHERE id = ?", (clean_key, pkg_id, sub_id))
        now_str = now.isoformat()
        conn.execute("""
            INSERT INTO subscriptions (subscriber_id, package_id, start_date, expiry_date, status, auto_renew, created_at)
            VALUES (?, ?, ?, ?, 'active', 0, ?)
        """, (sub_id, pkg_id, now_str, (now + timedelta(days=days)).isoformat(), now_str))
    else:
        conn.execute("UPDATE subscribers SET active_key_code = ? WHERE id = ?", (clean_key, sub_id))
    conn.commit()
    sub_row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (sub_id,)).fetchone()
    conn.close()
    notify_vault_write()
    return True, f"Key {clean_key} safely linked to your account! Subscription active.", dict(sub_row)

# ----------------------------------------------------
# SABRO VISION v1.0 - Audit Logging & Connection Events
# ----------------------------------------------------
def log_audit(admin_user, action, details="", ip_address=""):
    try:
        conn = get_db()
        now_str = datetime.now().isoformat()
        conn.execute("INSERT INTO audit_logs (admin_user, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
                     (admin_user or "System", action, details, ip_address, now_str))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_audit_logs(limit=50):
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def log_connection(username, client_ip="", user_agent="", stream_id=None, action="PLAY"):
    try:
        conn = get_db()
        now_str = datetime.now().isoformat()
        conn.execute("INSERT INTO connection_events (username, client_ip, user_agent, stream_id, action, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (username, client_ip, (user_agent or "")[:250], stream_id, action, now_str))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_connection_events(limit=50):
    conn = get_db()
    rows = conn.execute("SELECT * FROM connection_events ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------------------------------------------
# SABRO VISION v1.0 - Packages & Subscriptions
# ----------------------------------------------------
def get_packages(active_only=True, tenant_id=None):
    conn = get_db()
    clauses = []
    params = []
    if active_only:
        clauses.append("is_active = 1")
    if tenant_id is not None:
        if tenant_id == 1:
            clauses.append("(tenant_id = 1 OR tenant_id IS NULL)")
        else:
            clauses.append("(tenant_id = ? OR tenant_id IS NULL)")
            params.append(tenant_id)
    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"SELECT * FROM packages{where_sql} ORDER BY price_pkr ASC"
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_package_by_id(package_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM packages WHERE id = ?", (package_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_package_by_code(code):
    if not code:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM packages WHERE LOWER(code) = LOWER(?)", (code.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None

def add_package(name, code, duration_days=30, price_pkr=250, max_connections=1, description="", allowed_categories="all", tenant_id=None):
    conn = get_db()
    now_str = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packages (name, code, duration_days, price_pkr, max_connections, is_active, description, allowed_categories, tenant_id, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    """, (name, code.lower().strip(), int(duration_days), int(price_pkr), int(max_connections), description, allowed_categories or "all", tenant_id, now_str))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    notify_vault_write()
    return new_id

def update_package(package_id, name, duration_days, price_pkr, max_connections=1, is_active=1, description="", allowed_categories="all"):
    conn = get_db()
    conn.execute("""
        UPDATE packages
        SET name = ?, duration_days = ?, price_pkr = ?, max_connections = ?, is_active = ?, description = ?, allowed_categories = ?
        WHERE id = ?
    """, (name, int(duration_days), int(price_pkr), int(max_connections), int(is_active), description, allowed_categories or "all", package_id))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def get_subscriber_subscription(subscriber_id):
    conn = get_db()
    row = conn.execute("""
        SELECT s.*, p.name as package_name, p.max_connections, p.duration_days, p.price_pkr
        FROM subscriptions s
        JOIN packages p ON p.id = s.package_id
        WHERE s.subscriber_id = ?
        ORDER BY s.id DESC LIMIT 1
    """, (subscriber_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def activate_subscriber_subscription(subscriber_id, package_id, days=None):
    pkg = get_package_by_id(package_id)
    if not pkg:
        return False, "Package not found"
        
    duration = days if days is not None else pkg["duration_days"]
    now = datetime.now()
    
    curr_sub = get_subscriber_subscription(subscriber_id)
    if curr_sub and curr_sub["status"] == "active":
        curr_exp = datetime.fromisoformat(curr_sub["expiry_date"])
        base_time = max(curr_exp, now)
    else:
        base_time = now

    new_exp = base_time + timedelta(days=duration)
    now_str = now.isoformat()
    exp_str = new_exp.isoformat()

    conn = get_db()
    conn.execute("""
        INSERT INTO subscriptions (subscriber_id, package_id, start_date, expiry_date, status, auto_renew, created_at)
        VALUES (?, ?, ?, ?, 'active', 0, ?)
    """, (subscriber_id, package_id, now_str, exp_str, now_str))
    
    conn.execute("UPDATE subscribers SET status = 'active', package_id = ? WHERE id = ?", (package_id, subscriber_id))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True, f"Subscription activated until {new_exp.strftime('%Y-%m-%d')} (+{duration} days)"

def get_expiration_queue(within_days=7):
    conn = get_db()
    target_date = (datetime.now() + timedelta(days=within_days)).isoformat()
    rows = conn.execute("""
        SELECT sub.*, s.expiry_date, p.name as package_name
        FROM subscribers sub
        LEFT JOIN subscriptions s ON s.subscriber_id = sub.id AND s.status = 'active'
        LEFT JOIN packages p ON p.id = s.package_id
        WHERE s.expiry_date IS NOT NULL AND s.expiry_date <= ? AND s.expiry_date >= ?
        ORDER BY s.expiry_date ASC
    """, (target_date, datetime.now().isoformat())).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------------------------------------------
# SABRO VISION v1.0 - Customer Management & Sector Mapping
# ----------------------------------------------------
def get_subscribers(search=None, status=None, zone=None, limit=None, offset=0, tenant_id=None):
    conn = get_db()
    query = """
        SELECT sub.*, p.name as package_name, s.expiry_date as sub_expiry,
               t.service_name as tenant_service_name, t.code as tenant_code
        FROM subscribers sub
        LEFT JOIN subscriptions s ON s.subscriber_id = sub.id AND s.id = (
            SELECT id FROM subscriptions WHERE subscriber_id = sub.id ORDER BY id DESC LIMIT 1
        )
        LEFT JOIN packages p ON p.id = sub.package_id
        LEFT JOIN tenants t ON t.id = sub.tenant_id
        WHERE 1=1
    """
    params = []
    if tenant_id is not None:
        query += " AND sub.tenant_id = ?"
        params.append(int(tenant_id))
    if status and status != 'all':
        query += " AND sub.status = ?"
        params.append(status)
    if zone and zone != 'all':
        query += " AND sub.zone = ?"
        params.append(zone)
    if search:
        query += " AND (sub.username LIKE ? OR sub.full_name LIKE ? OR sub.phone LIKE ? OR sub.pppoe_username LIKE ? OR sub.fat_id LIKE ?)"
        wild = f"%{search}%"
        params.extend([wild, wild, wild, wild, wild])

    query += " ORDER BY sub.id DESC"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_subscribers_count(search=None, status=None, zone=None, tenant_id=None):
    conn = get_db()
    query = "SELECT COUNT(*) as c FROM subscribers sub WHERE 1=1"
    params = []
    if tenant_id is not None:
        query += " AND sub.tenant_id = ?"
        params.append(int(tenant_id))
    if status and status != 'all':
        query += " AND sub.status = ?"
        params.append(status)
    if zone and zone != 'all':
        query += " AND sub.zone = ?"
        params.append(zone)
    if search:
        query += " AND (sub.username LIKE ? OR sub.full_name LIKE ? OR sub.phone LIKE ? OR sub.pppoe_username LIKE ? OR sub.fat_id LIKE ?)"
        wild = f"%{search}%"
        params.extend([wild, wild, wild, wild, wild])

    c = conn.execute(query, params).fetchone()["c"]
    conn.close()
    return c

def add_subscriber(username, password, full_name="", phone="", pppoe_username="", zone="", fat_id="", email="", package_id=None, notes="", tenant_id=1, is_sabro_isp=0):
    clean_user = username.strip().lower()
    if not clean_user or len(clean_user) < 3:
        return False, "Username must be at least 3 characters", None
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters", None

    conn = get_db()
    existing = conn.execute("SELECT id FROM subscribers WHERE LOWER(username) = ?", (clean_user,)).fetchone()
    if existing:
        conn.close()
        return False, "Username is already taken", None

    now_str = datetime.now().isoformat()
    pw_hash = generate_password_hash(password)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO subscribers (username, password_hash, plain_password, full_name, phone, email, pppoe_username, zone, fat_id, package_id, status, notes, tenant_id, is_sabro_isp, created_at, last_login_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
    """, (clean_user, pw_hash, password, full_name.strip(), phone.strip(), email.strip(), pppoe_username.strip(), zone.strip(), fat_id.strip(), package_id, notes.strip(), int(tenant_id or 1), int(is_sabro_isp or 0), now_str, now_str))
    conn.commit()
    new_id = cursor.lastrowid
    
    if package_id:
        activate_subscriber_subscription(new_id, int(package_id))

    sub_row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (new_id,)).fetchone()
    conn.close()
    notify_vault_write()
    return True, "Subscriber created successfully", dict(sub_row)

def update_subscriber(sub_id, full_name, phone, pppoe_username="", zone="", fat_id="", email="", status="active", notes=""):
    conn = get_db()
    conn.execute("""
        UPDATE subscribers
        SET full_name = ?, phone = ?, pppoe_username = ?, zone = ?, fat_id = ?, email = ?, status = ?, notes = ?
        WHERE id = ?
    """, (full_name.strip(), phone.strip(), pppoe_username.strip(), zone.strip(), fat_id.strip(), email.strip(), status, notes.strip(), sub_id))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def delete_subscriber(sub_id):
    conn = get_db()
    conn.execute("DELETE FROM subscriptions WHERE subscriber_id = ?", (sub_id,))
    conn.execute("DELETE FROM payment_receipts WHERE subscriber_id = ?", (sub_id,))
    conn.execute("DELETE FROM subscribers WHERE id = ?", (sub_id,))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

# ----------------------------------------------------
# SABRO VISION v1.0 - Payment Verification Workflow
# ----------------------------------------------------
def submit_payment_receipt(subscriber_id, package_id, amount_pkr, payment_method, transaction_ref="", sender_number="", proof_image="", notes="", tenant_id=1, invoice_number=None):
    conn = get_db()
    now_str = datetime.now().isoformat()
    if not invoice_number:
        invoice_number = f"SABRO-INV-{datetime.now().strftime('%y%m')}-{secrets.token_hex(2).upper()}"
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO payment_receipts (subscriber_id, package_id, amount_pkr, payment_method, transaction_ref, sender_number, proof_image, status, notes, tenant_id, invoice_number, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
    """, (subscriber_id, package_id, int(amount_pkr), payment_method, transaction_ref.strip(), sender_number.strip(), proof_image, notes.strip(), int(tenant_id or 1), invoice_number, now_str))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    notify_vault_write()
    return new_id

def get_payment_receipts(status=None, limit=50, tenant_id=None):
    conn = get_db()
    query = """
        SELECT r.*, sub.username, sub.full_name, sub.phone as sub_phone, p.name as package_name,
               t.service_name as tenant_service_name
        FROM payment_receipts r
        LEFT JOIN subscribers sub ON sub.id = r.subscriber_id
        LEFT JOIN packages p ON p.id = r.package_id
        LEFT JOIN tenants t ON t.id = r.tenant_id
        WHERE 1=1
    """
    params = []
    if tenant_id is not None:
        query += " AND r.tenant_id = ?"
        params.append(int(tenant_id))
    if status and status != 'all':
        query += " AND r.status = ?"
        params.append(status)
    query += " ORDER BY r.id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def approve_payment_receipt(receipt_id, admin_user, notes="", tenant_id=None):
    conn = get_db()
    query = "SELECT * FROM payment_receipts WHERE id = ?"
    params = [receipt_id]
    if tenant_id is not None:
        query += " AND tenant_id = ?"
        params.append(int(tenant_id))
    receipt = conn.execute(query, params).fetchone()
    if not receipt:
        conn.close()
        return False, "Receipt not found or permission denied"

    r_dict = dict(receipt)
    now_str = datetime.now().isoformat()

    conn.execute("""
        UPDATE payment_receipts
        SET status = 'approved', reviewer_admin = ?, reviewed_at = ?, notes = COALESCE(?, notes)
        WHERE id = ?
    """, (admin_user, now_str, notes if notes else None, receipt_id))
    conn.commit()
    conn.close()

    if r_dict["subscriber_id"] and r_dict["package_id"]:
        activate_subscriber_subscription(r_dict["subscriber_id"], r_dict["package_id"])

    # Create celebration notification for customer
    if r_dict.get("subscriber_id"):
        create_notification(
            r_dict.get("tenant_id", 1),
            r_dict["subscriber_id"],
            "Payment Approved! 🎉",
            f"Your payment of PKR {r_dict['amount_pkr']} ({r_dict['payment_method']}) has been verified. Your subscription is now active!",
            "success"
        )

    log_audit(admin_user, "APPROVE_PAYMENT", f"Approved payment receipt #{receipt_id} for PKR {r_dict['amount_pkr']} ({r_dict['payment_method']})")
    notify_vault_write()
    return True, "Payment approved and subscription automatically activated!"

def reject_payment_receipt(receipt_id, admin_user, notes="", tenant_id=None):
    conn = get_db()
    query = "SELECT * FROM payment_receipts WHERE id = ?"
    params = [receipt_id]
    if tenant_id is not None:
        query += " AND tenant_id = ?"
        params.append(int(tenant_id))
    receipt = conn.execute(query, params).fetchone()
    if not receipt:
        conn.close()
        return False, "Receipt not found or permission denied"

    r_dict = dict(receipt)
    now_str = datetime.now().isoformat()
    conn.execute("""
        UPDATE payment_receipts
        SET status = 'rejected', reviewer_admin = ?, reviewed_at = ?, notes = COALESCE(?, notes)
        WHERE id = ?
    """, (admin_user, now_str, notes if notes else "Rejected by reviewer", receipt_id))
    conn.commit()
    conn.close()

    # Notify customer of rejection reason
    if r_dict.get("subscriber_id"):
        create_notification(
            r_dict.get("tenant_id", 1),
            r_dict["subscriber_id"],
            "Payment Verification Update",
            f"Your payment receipt #{receipt_id} could not be verified. Note: {notes or 'Invalid transaction reference.'}",
            "danger"
        )

    log_audit(admin_user, "REJECT_PAYMENT", f"Rejected payment receipt #{receipt_id}. Reason: {notes}")
    notify_vault_write()
    return True, "Payment receipt marked as rejected"

# ----------------------------------------------------
# SABRO VISION v1.0 - Xtream Codes API v2 Handshake & Helpers
# ----------------------------------------------------
def authenticate_xtream(username, password):
    """
    Xtream Codes API v2 Authentication Engine.
    Used by IPTV Smarters, TiviMate, XCIPTV, OTT Navigator.
    Returns: (is_valid: bool, user_info: dict, error_message: str)
    """
    clean_user = username.strip().lower()
    conn = get_db()
    row = conn.execute("SELECT * FROM subscribers WHERE LOWER(username) = ?", (clean_user,)).fetchone()
    if not row:
        conn.close()
        return False, None, "Invalid username or password"

    sub = dict(row)
    from werkzeug.security import check_password_hash
    pw_matches = check_password_hash(sub["password_hash"], password) or (sub.get("plain_password") and sub["plain_password"] == password)
    if not pw_matches:
        conn.close()
        return False, None, "Invalid username or password"

    if sub.get("status") == "suspended":
        conn.close()
        return False, None, "Account is suspended by administrator"

    now = datetime.now()
    sub_record = conn.execute("""
        SELECT s.*, p.max_connections FROM subscriptions s
        JOIN packages p ON p.id = s.package_id
        WHERE s.subscriber_id = ? AND s.status = 'active'
        ORDER BY s.expiry_date DESC LIMIT 1
    """, (sub["id"],)).fetchone()

    exp_timestamp = None
    max_cons = 1
    if sub_record:
        exp_dt = datetime.fromisoformat(sub_record["expiry_date"])
        if now > exp_dt:
            conn.close()
            return False, None, "Subscription has expired"
        exp_timestamp = int(exp_dt.timestamp())
        max_cons = sub_record["max_connections"] or 1
    elif sub.get("active_key_code"):
        krow = conn.execute("SELECT * FROM access_keys WHERE UPPER(key_code) = ?", (sub["active_key_code"].upper(),)).fetchone()
        if krow:
            kdata = dict(krow)
            if kdata.get("expires_at"):
                exp_dt = datetime.fromisoformat(kdata["expires_at"])
                if now > exp_dt:
                    conn.close()
                    return False, None, "Access key has expired"
                exp_timestamp = int(exp_dt.timestamp())
            max_cons = kdata.get("max_devices", 1)

    if not exp_timestamp:
        exp_timestamp = int((now + timedelta(days=30)).timestamp())

    created_timestamp = int(datetime.fromisoformat(sub["created_at"]).timestamp()) if sub.get("created_at") else int(now.timestamp())
    conn.close()

    user_info = {
        "username": sub["username"],
        "password": sub.get("plain_password") or password,
        "message": "Welcome to SABRO VISION v1.0",
        "auth": 1,
        "status": "Active",
        "exp_date": str(exp_timestamp),
        "is_trial": "0",
        "active_cons": 0,
        "created_at": str(created_timestamp),
        "max_connections": str(max_cons),
        "allowed_output_formats": ["m3u8", "ts"],
        "subscriber_id": sub["id"],
        "package_id": sub.get("package_id")
    }
    return True, user_info, None

def get_xtream_live_categories(allowed_categories=None):
    conn = get_db()
    query = "SELECT id, name FROM categories WHERE is_hidden = 0"
    params = []
    cat_set = parse_allowed_categories(allowed_categories)
    if cat_set:
        placeholders = ",".join("?" for _ in cat_set)
        query += f" AND LOWER(name) IN ({placeholders})"
        params.extend(list(cat_set))
    query += " ORDER BY sort_order ASC, name ASC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [{"category_id": str(r["id"]), "category_name": r["name"], "parent_id": 0} for r in rows]

def get_xtream_live_streams(category_id=None, allowed_categories=None):
    conn = get_db()
    cats = {c["name"]: str(c["id"]) for c in conn.execute("SELECT id, name FROM categories").fetchall()}
    
    query = "SELECT * FROM channels WHERE is_active = 1"
    params = []
    if category_id:
        cat_name = conn.execute("SELECT name FROM categories WHERE id = ?", (category_id,)).fetchone()
        if cat_name:
            query += " AND category = ?"
            params.append(cat_name["name"])

    cat_set = parse_allowed_categories(allowed_categories)
    if cat_set:
        placeholders = ",".join("?" for _ in cat_set)
        query += f" AND LOWER(category) IN ({placeholders})"
        params.extend(list(cat_set))

    query += " ORDER BY sort_order ASC, name ASC"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    output = []
    now_ts = str(int(datetime.now().timestamp()))
    for idx, ch in enumerate(rows):
        cid = cats.get(ch["category"], "1")
        ch_keys = ch.keys()
        epg_val = ch["epg_channel_id"] if "epg_channel_id" in ch_keys and ch["epg_channel_id"] else ch["name"].lower().replace(" ", ".")
        output.append({
            "num": idx + 1,
            "name": ch["name"],
            "stream_type": "live",
            "stream_id": ch["id"],
            "stream_icon": ch["logo"] or "",
            "epg_channel_id": epg_val,
            "added": now_ts,
            "category_id": cid,
            "custom_sid": "",
            "tv_archive": 0,
            "direct_source": ""
        })
    return output

# ----------------------------------------------------
# SABRO VISION v1.0 - Dashboard Analytics
# ----------------------------------------------------
def get_dashboard_analytics():
    conn = get_db()
    total_subs = conn.execute("SELECT COUNT(*) as c FROM subscribers").fetchone()["c"]
    active_subs = conn.execute("SELECT COUNT(*) as c FROM subscribers WHERE status = 'active'").fetchone()["c"]
    total_channels = conn.execute("SELECT COUNT(*) as c FROM channels WHERE is_active = 1").fetchone()["c"]
    
    rev_row = conn.execute("SELECT SUM(amount_pkr) as s FROM payment_receipts WHERE status = 'approved'").fetchone()
    total_revenue_pkr = rev_row["s"] or 0

    outside_rev_row = conn.execute("SELECT SUM(amount_pkr) as s FROM payment_receipts WHERE status = 'approved' AND (tenant_id = 1 OR tenant_id IS NULL)").fetchone()
    outside_revenue_pkr = outside_rev_row["s"] or 0

    reseller_rev_row = conn.execute("SELECT SUM(amount_pkr) as s FROM payment_receipts WHERE status = 'approved' AND tenant_id > 1").fetchone()
    reseller_revenue_pkr = reseller_rev_row["s"] or 0

    pending_payments = conn.execute("SELECT COUNT(*) as c FROM payment_receipts WHERE status = 'pending'").fetchone()["c"]
    pending_resellers = conn.execute("SELECT COUNT(*) as c FROM reseller_inquiries WHERE status = 'pending'").fetchone()["c"]
    total_resellers = conn.execute("SELECT COUNT(*) as c FROM reseller_inquiries").fetchone()["c"]

    # Active Sabro ISP free users vs outside paid customers
    active_sabro_free = conn.execute("SELECT COUNT(*) as c FROM subscribers WHERE is_sabro_isp = 1 AND status = 'active'").fetchone()["c"]
    outside_paid_customers = conn.execute("SELECT COUNT(*) as c FROM subscribers WHERE is_sabro_isp = 0 AND status = 'active'").fetchone()["c"]
    total_active_tenants = conn.execute("SELECT COUNT(*) as c FROM tenants WHERE status = 'active' AND id != 1").fetchone()["c"]
    total_all_tenants = conn.execute("SELECT COUNT(*) as c FROM tenants").fetchone()["c"]
    total_expired = conn.execute("SELECT COUNT(*) as c FROM subscribers WHERE status = 'expired'").fetchone()["c"]
    total_suspended = conn.execute("SELECT COUNT(*) as c FROM subscribers WHERE status = 'suspended'").fetchone()["c"]
    open_tickets = conn.execute("SELECT COUNT(*) as c FROM support_tickets WHERE status IN ('open', 'in_progress')").fetchone()["c"]

    target_7d = (datetime.now() + timedelta(days=7)).isoformat()
    now_iso = datetime.now().isoformat()
    exp_queue_count = conn.execute("""
        SELECT COUNT(*) as c FROM subscriptions
        WHERE status = 'active' AND expiry_date <= ? AND expiry_date >= ?
    """, (target_7d, now_iso)).fetchone()["c"]

    conn.close()

    recent_audits = get_audit_logs(limit=6)
    recent_conns = get_connection_events(limit=8)
    packages = get_packages()

    return {
        "total_subscribers": total_subs,
        "total_registered_users": total_subs,
        "active_subscribers": active_subs,
        "active_sabro_free_users": active_sabro_free,
        "outside_paid_customers": outside_paid_customers,
        "total_channels": total_channels,
        "total_revenue_pkr": total_revenue_pkr,
        "outside_revenue_pkr": outside_revenue_pkr,
        "reseller_revenue_pkr": reseller_revenue_pkr,
        "pending_payments": pending_payments,
        "pending_resellers": pending_resellers,
        "total_resellers": total_resellers,
        "total_active_resellers": total_active_tenants,
        "total_tenants": total_all_tenants,
        "total_expired_subscriptions": total_expired,
        "total_suspended_accounts": total_suspended,
        "open_tickets_count": open_tickets,
        "expiring_soon_count": exp_queue_count,
        "recent_audits": recent_audits,
        "recent_connections": recent_conns,
        "packages": packages
    }

# ----------------------------------------------------
# SABRO VISION v1.0 - Stream Health Diagnostics Engine
# ----------------------------------------------------
def test_single_stream(stream_url, timeout=3.0):
    """
    Performs a lightweight HTTP probe to verify whether an HLS or video stream is online.
    Returns: (is_online, status_code, response_time_ms, reason)
    """
    import requests, time
    t0 = time.time()
    headers = {
        "User-Agent": "VLC/3.0.18 LibVLC/3.0.18",
        "Accept": "*/*",
        "Range": "bytes=0-1024"
    }
    resp = None
    try:
        resp = requests.get(stream_url, headers=headers, timeout=timeout, stream=True, allow_redirects=True)
        ms = int((time.time() - t0) * 1000)
        
        # Valid stream response codes
        if resp.status_code in (200, 206, 301, 302, 307):
            ctype = resp.headers.get("Content-Type", "").lower()
            is_valid = True
            # Reject captive portals returning plain HTML on 200
            if "text/html" in ctype:
                is_valid = False
            return is_valid, resp.status_code, ms, "OK" if is_valid else "Returned HTML instead of stream"
        else:
            return False, resp.status_code, ms, f"HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        ms = int((time.time() - t0) * 1000)
        return False, 0, ms, "Connection timed out"
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return False, 0, ms, str(e)[:60]
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

def update_channel_health(channel_id, status, response_time_ms):
    """Update health status and latency for a single channel."""
    conn = get_db()
    now_str = datetime.now().isoformat()
    conn.execute("""
        UPDATE channels
        SET health_status = ?, response_time_ms = ?, last_checked_at = ?
        WHERE id = ?
    """, (status, response_time_ms, now_str, channel_id))
    conn.commit()
    conn.close()

def get_channel_health_summary():
    """Returns high-level statistics about channel stream health."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM channels").fetchone()["c"]
    online = conn.execute("SELECT COUNT(*) as c FROM channels WHERE health_status = 'online'").fetchone()["c"]
    offline = conn.execute("SELECT COUNT(*) as c FROM channels WHERE health_status = 'offline'").fetchone()["c"]
    slow = conn.execute("SELECT COUNT(*) as c FROM channels WHERE health_status = 'slow'").fetchone()["c"]
    unchecked = conn.execute("SELECT COUNT(*) as c FROM channels WHERE health_status IS NULL OR health_status = 'unknown'").fetchone()["c"]
    active_online = conn.execute("SELECT COUNT(*) as c FROM channels WHERE is_active = 1 AND health_status = 'online'").fetchone()["c"]
    active_total = conn.execute("SELECT COUNT(*) as c FROM channels WHERE is_active = 1").fetchone()["c"]
    
    avg_row = conn.execute("SELECT AVG(response_time_ms) as a FROM channels WHERE health_status = 'online' AND response_time_ms > 0").fetchone()
    avg_latency = int(avg_row["a"]) if avg_row and avg_row["a"] else 0
    conn.close()

    tested = online + offline + slow
    online_pct = round(((online + slow) / tested * 100), 1) if tested > 0 else 0

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "slow": slow,
        "unchecked": unchecked,
        "active_total": active_total,
        "active_online": active_online,
        "avg_latency_ms": avg_latency,
        "online_pct": online_pct,
        "tested": tested
    }

def bulk_toggle_offline_channels(enable=False):
    """Disable (is_active = 0) or Re-enable (is_active = 1) all channels marked as offline."""
    conn = get_db()
    val = 1 if enable else 0
    cursor = conn.cursor()
    cursor.execute("UPDATE channels SET is_active = ? WHERE health_status = 'offline'", (val,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected

def batch_test_channels(category=None, limit=None, max_workers=40, update_db=True):
    """Concurrently tests stream health for channels."""
    from concurrent.futures import ThreadPoolExecutor
    conn = get_db()
    query = "SELECT id, name, stream_url FROM channels WHERE 1=1"
    params = []
    if category and category.lower() != 'all':
        query += " AND category = ?"
        params.append(category)
    if limit:
        query += f" LIMIT {int(limit)}"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    results = []
    def _worker(ch):
        ok, code, ms, reason = test_single_stream(ch["stream_url"])
        status = "online" if ok else "offline"
        if ok and ms > 2500:
            status = "slow"
        return ch["id"], status, ms

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(_worker, rows))

    if update_db and results:
        now_str = datetime.now().isoformat()
        conn = get_db()
        conn.executemany("""
            UPDATE channels
            SET health_status = ?, response_time_ms = ?, last_checked_at = ?
            WHERE id = ?
        """, [(r[1], r[2], now_str, r[0]) for r in results])
        conn.commit()
        conn.close()

    online_cnt = sum(1 for r in results if r[1] in ('online', 'slow'))
    return {
        "tested": len(results),
        "online": online_cnt,
        "offline": len(results) - online_cnt
    }

# ----------------------------------------------------
# ISP Partner, Reseller & White-Label Helpers
# ----------------------------------------------------
def create_reseller_inquiry(company_name, contact_name, phone, email="", city="", subscriber_count="", partner_type="white_label", notes=""):
    conn = get_db()
    cursor = conn.cursor()
    now_str = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO reseller_inquiries 
        (company_name, contact_name, phone, email, city, subscriber_count, partner_type, notes, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
    """, (
        company_name.strip(), 
        contact_name.strip(), 
        phone.strip(), 
        email.strip(), 
        city.strip(), 
        subscriber_count.strip(), 
        partner_type.strip(), 
        notes.strip(), 
        now_str
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    notify_vault_write()
    return new_id

def get_reseller_inquiries(status=None, limit=50):
    conn = get_db()
    query = "SELECT * FROM reseller_inquiries"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_reseller_inquiry_status(inquiry_id, status):
    conn = get_db()
    conn.execute("UPDATE reseller_inquiries SET status = ? WHERE id = ?", (status, int(inquiry_id)))
    conn.commit()
    conn.close()
    notify_vault_write()

# ====================================================
# MULTI-TENANT SAAS & RESELLER HELPERS
# ====================================================

def get_tenants(status=None):
    conn = get_db()
    if status:
        rows = conn.execute("SELECT * FROM tenants WHERE status = ? ORDER BY id ASC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM tenants ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_tenant_by_id(tenant_id):
    if not tenant_id:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM tenants WHERE id = ?", (int(tenant_id),)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_tenant_by_code(code):
    if not code:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM tenants WHERE LOWER(code) = LOWER(?)", (code.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_tenant_by_domain(domain_or_host):
    if not domain_or_host:
        return None
    host = domain_or_host.split(":")[0].strip().lower()
    conn = get_db()
    row = conn.execute("""
        SELECT * FROM tenants 
        WHERE LOWER(custom_domain) = ? OR LOWER(subdomain) = ?
    """, (host, host)).fetchone()
    conn.close()
    return dict(row) if row else None

def create_tenant(data: dict) -> int:
    conn = get_db()
    now_str = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO tenants (
            code, name, company_name, service_name, tagline, custom_domain, subdomain,
            logo_url, brand_color_primary, brand_color_secondary, contact_name,
            email, phone, whatsapp, welcome_message, support_email, support_phone,
            status, max_customers, max_active_subs, max_devices_per_user,
            allowed_features, created_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("code", "").strip().lower(),
        data.get("name", "New ISP Partner"),
        data.get("company_name", ""),
        data.get("service_name", "Vision TV"),
        data.get("tagline", ""),
        data.get("custom_domain") or None,
        data.get("subdomain") or None,
        data.get("logo_url") or "",
        data.get("brand_color_primary", "#00f0ff"),
        data.get("brand_color_secondary", "#6366f1"),
        data.get("contact_name", ""),
        data.get("email", ""),
        data.get("phone", ""),
        data.get("whatsapp", ""),
        data.get("welcome_message", ""),
        data.get("support_email", ""),
        data.get("support_phone", ""),
        data.get("status", "active"),
        int(data.get("max_customers", 500)),
        int(data.get("max_active_subs", 500)),
        int(data.get("max_devices_per_user", 1)),
        data.get("allowed_features", "all"),
        now_str,
        data.get("notes", "")
    ))
    tenant_id = cursor.lastrowid
    conn.commit()
    conn.close()
    notify_vault_write()
    return tenant_id

def update_tenant(tenant_id: int, data: dict) -> bool:
    conn = get_db()
    fields = []
    params = []
    allowed_keys = [
        "name", "company_name", "service_name", "tagline", "custom_domain", "subdomain",
        "logo_url", "brand_color_primary", "brand_color_secondary", "contact_name",
        "email", "phone", "whatsapp", "welcome_message", "support_email", "support_phone",
        "status", "max_customers", "max_active_subs", "max_devices_per_user",
        "allowed_features", "notes"
    ]
    for k in allowed_keys:
        if k in data:
            fields.append(f"{k} = ?")
            params.append(data[k])
    if not fields:
        conn.close()
        return False
    params.append(int(tenant_id))
    conn.execute(f"UPDATE tenants SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def delete_tenant(tenant_id: int, soft_delete=True) -> bool:
    if int(tenant_id) == 1:
        return False  # Cannot delete platform master tenant
    conn = get_db()
    if soft_delete:
        conn.execute("UPDATE tenants SET status = 'suspended' WHERE id = ?", (int(tenant_id),))
    else:
        conn.execute("DELETE FROM tenants WHERE id = ?", (int(tenant_id),))
    conn.commit()
    conn.close()
    notify_vault_write()
    return True

def get_tenant_metrics(tenant_id: int) -> dict:
    conn = get_db()
    tid = int(tenant_id)
    cust_count = conn.execute("SELECT COUNT(*) FROM subscribers WHERE tenant_id = ?", (tid,)).fetchone()[0]
    active_subs = conn.execute("SELECT COUNT(*) FROM subscribers WHERE tenant_id = ? AND status = 'active'", (tid,)).fetchone()[0]
    keys_count = conn.execute("SELECT COUNT(*) FROM access_keys WHERE tenant_id = ?", (tid,)).fetchone()[0]
    rev_row = conn.execute("SELECT COALESCE(SUM(amount_pkr), 0) FROM payment_receipts WHERE tenant_id = ? AND status = 'approved'", (tid,)).fetchone()
    total_rev = rev_row[0] if rev_row else 0
    open_tickets = conn.execute("SELECT COUNT(*) FROM support_tickets WHERE tenant_id = ? AND status IN ('open', 'in_progress')", (tid,)).fetchone()[0]
    tenant_row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tid,)).fetchone()
    conn.close()
    return {
        "tenant": dict(tenant_row) if tenant_row else None,
        "total_customers": cust_count,
        "active_subscribers": active_subs,
        "total_keys": keys_count,
        "total_revenue_pkr": total_rev,
        "open_tickets": open_tickets
    }

# ----------------------------------------------------
# Reseller Authentication & User Helpers
# ----------------------------------------------------
def authenticate_reseller(username, password):
    if not username or not password:
        return None
    conn = get_db()
    row = conn.execute("""
        SELECT ru.*, t.code as tenant_code, t.name as tenant_name, t.service_name,
               t.status as tenant_status, t.brand_color_primary, t.brand_color_secondary,
               t.logo_url, t.company_name
        FROM reseller_users ru
        JOIN tenants t ON ru.tenant_id = t.id
        WHERE LOWER(ru.username) = LOWER(?) AND ru.status = 'active'
    """, (username.strip(),)).fetchone()
    if not row:
        conn.close()
        return None
    from werkzeug.security import check_password_hash
    if check_password_hash(row["password_hash"], password):
        now_str = datetime.now().isoformat()
        conn.execute("UPDATE reseller_users SET last_login_at = ? WHERE id = ?", (now_str, row["id"]))
        conn.commit()
        res = dict(row)
        conn.close()
        return res
    conn.close()
    return None

def create_reseller_user(tenant_id, username, password, full_name='', email='', phone='', role='owner'):
    conn = get_db()
    now_str = datetime.now().isoformat()
    pwd_hash = generate_password_hash(password)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reseller_users (tenant_id, username, password_hash, full_name, email, phone, role, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
    """, (int(tenant_id), username.strip(), pwd_hash, full_name, email, phone, role, now_str))
    uid = cursor.lastrowid
    conn.commit()
    conn.close()
    notify_vault_write()
    return uid

def get_reseller_users(tenant_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, tenant_id, username, full_name, email, phone, role, status, created_at, last_login_at
        FROM reseller_users WHERE tenant_id = ? ORDER BY id ASC
    """, (int(tenant_id),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------------------------------------------
# Multi-Tenant Support Tickets Helpers
# ----------------------------------------------------
def create_support_ticket(tenant_id, subscriber_id, subject, category, priority, initial_message, sender_name):
    conn = get_db()
    now_str = datetime.now().isoformat()
    ticket_num = f"TCK-{datetime.now().strftime('%y%m')}-{secrets.token_hex(2).upper()}"
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO support_tickets (ticket_number, tenant_id, subscriber_id, subject, category, priority, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
    """, (ticket_num, int(tenant_id) if tenant_id else 1, int(subscriber_id) if subscriber_id else None, subject.strip(), category, priority, now_str, now_str))
    t_id = cursor.lastrowid

    if initial_message:
        cursor.execute("""
            INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message, created_at)
            VALUES (?, 'customer', ?, ?, ?)
        """, (t_id, sender_name or "Subscriber", initial_message.strip(), now_str))

    conn.commit()
    conn.close()
    notify_vault_write()
    return t_id, ticket_num

def get_support_tickets(tenant_id=None, subscriber_id=None, status=None):
    conn = get_db()
    query = """
        SELECT st.*, s.username as subscriber_username, t.service_name as tenant_service_name,
               (SELECT COUNT(*) FROM ticket_messages WHERE ticket_id = st.id) as message_count
        FROM support_tickets st
        LEFT JOIN subscribers s ON st.subscriber_id = s.id
        LEFT JOIN tenants t ON st.tenant_id = t.id
        WHERE 1=1
    """
    params = []
    if tenant_id is not None:
        query += " AND st.tenant_id = ?"
        params.append(int(tenant_id))
    if subscriber_id is not None:
        query += " AND st.subscriber_id = ?"
        params.append(int(subscriber_id))
    if status and status != 'all':
        query += " AND st.status = ?"
        params.append(status)
    query += " ORDER BY st.updated_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_support_ticket(ticket_id, tenant_id=None, subscriber_id=None):
    conn = get_db()
    query = """
        SELECT st.*, s.username as subscriber_username, s.phone as subscriber_phone, t.service_name as tenant_service_name
        FROM support_tickets st
        LEFT JOIN subscribers s ON st.subscriber_id = s.id
        LEFT JOIN tenants t ON st.tenant_id = t.id
        WHERE st.id = ?
    """
    params = [int(ticket_id)]
    if tenant_id is not None:
        query += " AND st.tenant_id = ?"
        params.append(int(tenant_id))
    if subscriber_id is not None:
        query += " AND st.subscriber_id = ?"
        params.append(int(subscriber_id))
    row = conn.execute(query, params).fetchone()
    if not row:
        conn.close()
        return None
    t = dict(row)
    msg_rows = conn.execute("""
        SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY id ASC
    """, (int(ticket_id),)).fetchall()
    t["messages"] = [dict(m) for m in msg_rows]
    conn.close()
    return t

def add_ticket_message(ticket_id, sender_type, sender_name, message):
    conn = get_db()
    now_str = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (int(ticket_id), sender_type, sender_name, message.strip(), now_str))
    cursor.execute("UPDATE support_tickets SET updated_at = ? WHERE id = ?", (now_str, int(ticket_id)))
    conn.commit()
    mid = cursor.lastrowid
    conn.close()
    notify_vault_write()
    return mid

def update_ticket_status(ticket_id, status):
    conn = get_db()
    now_str = datetime.now().isoformat()
    conn.execute("UPDATE support_tickets SET status = ?, updated_at = ? WHERE id = ?", (status, now_str, int(ticket_id)))
    conn.commit()
    conn.close()
    notify_vault_write()

# ----------------------------------------------------
# Notification Helpers
# ----------------------------------------------------
def create_notification(tenant_id, subscriber_id, title, message, notif_type='info'):
    conn = get_db()
    now_str = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (tenant_id, subscriber_id, title, message, type, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
    """, (int(tenant_id) if tenant_id else 1, int(subscriber_id) if subscriber_id else None, title.strip(), message.strip(), notif_type, now_str))
    nid = cursor.lastrowid
    conn.commit()
    conn.close()
    notify_vault_write()
    return nid

def get_notifications(tenant_id=None, subscriber_id=None, limit=20):
    conn = get_db()
    query = "SELECT * FROM notifications WHERE 1=1"
    params = []
    if subscriber_id:
        query += " AND (subscriber_id = ? OR subscriber_id IS NULL)"
        params.append(int(subscriber_id))
    if tenant_id:
        query += " AND (tenant_id = ? OR tenant_id IS NULL)"
        params.append(int(tenant_id))
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_notification_read(notif_id, subscriber_id=None):
    conn = get_db()
    if subscriber_id:
        conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND subscriber_id = ?", (int(notif_id), int(subscriber_id)))
    else:
        conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (int(notif_id),))
    conn.commit()
    conn.close()

# ----------------------------------------------------
# Sabro Networks ISP Integration Helpers
# ----------------------------------------------------
def link_subscriber_to_isp(subscriber_id, pppoe_username, is_sabro_isp=1, isp_status='verified_active'):
    conn = get_db()
    now_str = datetime.now().isoformat()
    conn.execute("""
        UPDATE subscribers 
        SET pppoe_username = ?, is_sabro_isp = ?, isp_status = ?, isp_verified_at = ?
        WHERE id = ?
    """, (pppoe_username.strip(), int(is_sabro_isp), isp_status, now_str, int(subscriber_id)))
    conn.commit()
    conn.close()
    notify_vault_write()

def unlink_subscriber_from_isp(subscriber_id):
    conn = get_db()
    conn.execute("""
        UPDATE subscribers 
        SET is_sabro_isp = 0, isp_status = 'unlinked'
        WHERE id = ?
    """, (int(subscriber_id),))
    conn.commit()
    conn.close()
    notify_vault_write()


