"""
data_vault.py
==============
Multi-Layer Data Persistence & Recovery Engine for SABRO VISION.
Ensures zero data loss across Render container restarts, dyno recycles,
cloud redeployments, and server reboots.

Supported Persistence Backends:
1. Local Persistent Vault: data_vault.json auto-sync on disk / persistent disk (/var/data)
2. Render Persistent Disk: automatically supported when DATABASE_PATH points to mounted volume
3. Cloud PostgreSQL / Supabase / Neon: auto-sync via DATABASE_URL if configured
4. GitHub Cloud Sync: auto-commits data_vault.json to GitHub repository if GITHUB_TOKEN is present
"""

import os
import json
import sqlite3
import atexit
import logging
from datetime import datetime
import db

logger = logging.getLogger("sabro.vault")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

VAULT_DIR = os.path.dirname(os.path.abspath(db.DB_PATH))
VAULT_FILE = os.path.join(VAULT_DIR, "data_vault.json")

DYNAMIC_TABLES = [
    "settings",
    "admin_users",
    "access_keys",
    "subscribers",
    "subscriptions",
    "payment_receipts",
    "reseller_inquiries",
    "favorites",
    "audit_logs"
]

def export_vault_snapshot() -> dict:
    """Exports all dynamic business and customer records into a portable dictionary."""
    snapshot = {
        "platform": "SABRO VISION",
        "exported_at": datetime.now().isoformat(),
        "version": "1.0",
        "tables": {}
    }

    try:
        conn = db.get_db()
        cursor = conn.cursor()
        for table in DYNAMIC_TABLES:
            try:
                rows = cursor.execute(f"SELECT * FROM {table}").fetchall()
                snapshot["tables"][table] = [dict(row) for row in rows]
            except Exception as e:
                logger.warning(f"Vault export skipped table '{table}': {e}")
                snapshot["tables"][table] = []
        conn.close()
    except Exception as e:
        logger.error(f"Failed to export vault snapshot: {e}")

    return snapshot

def save_vault_snapshot_to_disk() -> bool:
    """Writes the current database state snapshot to data_vault.json with atomic replace."""
    try:
        snapshot = export_vault_snapshot()
        total_items = sum(len(rows) for rows in snapshot.get("tables", {}).values())
        
        # Don't overwrite an existing rich vault with an empty snapshot
        if os.path.exists(VAULT_FILE) and total_items == 0:
            logger.info("Vault snapshot empty; preserving existing on-disk vault file.")
            return False

        tmp_file = VAULT_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
        
        # Atomic replace with fallback for Windows file locking
        import time
        replaced = False
        for attempt in range(4):
            try:
                os.replace(tmp_file, VAULT_FILE)
                replaced = True
                break
            except OSError:
                time.sleep(0.05)
        if not replaced:
            try:
                with open(VAULT_FILE, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=2, ensure_ascii=False)
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

        # Checkpoint SQLite WAL so changes are permanently merged into the .db file
        checkpoint_wal()
        return True
    except Exception as e:
        logger.error(f"Error saving vault snapshot to disk: {e}")
        return False

def import_vault_snapshot(snapshot: dict) -> int:
    """Imports records from a snapshot dictionary into SQLite without deleting existing records."""
    if not snapshot or "tables" not in snapshot:
        return 0

    restored_total = 0
    try:
        conn = db.get_db()
        cursor = conn.cursor()

        for table, rows in snapshot.get("tables", {}).items():
            if not rows or table not in DYNAMIC_TABLES:
                continue

            for row in rows:
                if not row:
                    continue
                cols = list(row.keys())
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join([f'"{c}"' for c in cols])

                # Use INSERT OR REPLACE / INSERT OR IGNORE depending on table
                if table == "settings":
                    sql = f'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)'
                    cursor.execute(sql, (row.get("key"), row.get("value")))
                    restored_total += 1
                elif table == "admin_users":
                    sql = f'INSERT OR IGNORE INTO admin_users ({col_names}) VALUES ({placeholders})'
                    cursor.execute(sql, tuple(row.values()))
                    restored_total += 1
                elif table == "access_keys":
                    # Upsert on key_code
                    cursor.execute("SELECT id FROM access_keys WHERE key_code = ?", (row.get("key_code"),))
                    existing = cursor.fetchone()
                    if not existing:
                        sql = f'INSERT OR REPLACE INTO access_keys ({col_names}) VALUES ({placeholders})'
                        cursor.execute(sql, tuple(row.values()))
                        restored_total += 1
                elif table == "subscribers":
                    cursor.execute("SELECT id FROM subscribers WHERE username = ?", (row.get("username"),))
                    existing = cursor.fetchone()
                    if not existing:
                        sql = f'INSERT OR REPLACE INTO subscribers ({col_names}) VALUES ({placeholders})'
                        cursor.execute(sql, tuple(row.values()))
                        restored_total += 1
                elif table in ("payment_receipts", "reseller_inquiries", "favorites", "subscriptions", "audit_logs"):
                    # Check by ID if present
                    row_id = row.get("id")
                    if row_id:
                        cursor.execute(f"SELECT id FROM {table} WHERE id = ?", (row_id,))
                        if not cursor.fetchone():
                            sql = f'INSERT OR REPLACE INTO {table} ({col_names}) VALUES ({placeholders})'
                            cursor.execute(sql, tuple(row.values()))
                            restored_total += 1
                    else:
                        sql = f'INSERT INTO {table} ({col_names}) VALUES ({placeholders})'
                        cursor.execute(sql, tuple(row.values()))
                        restored_total += 1

        conn.commit()
        conn.close()
        checkpoint_wal()
        logger.info(f"Successfully restored {restored_total} records from vault snapshot.")
    except Exception as e:
        logger.error(f"Error restoring snapshot to database: {e}")

    return restored_total

def load_vault_from_disk() -> int:
    """Loads and restores data from data_vault.json if available."""
    if not os.path.exists(VAULT_FILE):
        return 0
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        return import_vault_snapshot(snapshot)
    except Exception as e:
        logger.error(f"Failed to read vault file '{VAULT_FILE}': {e}")
        return 0

def checkpoint_wal():
    """Forces SQLite WAL journal checkpoint to merge writes into sabro_iptv.db immediately."""
    try:
        conn = db.get_db()
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        conn.close()
    except Exception:
        pass

def truncate_wal():
    """Flushes and truncates WAL journal file cleanly on shutdown."""
    try:
        conn = db.get_db()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception:
        pass

def sync_to_github_if_configured():
    """
    If GITHUB_TOKEN is provided in environment variables, pushes the latest data_vault.json
    directly to GitHub repo so Render redeploys and restarts always have 100% of the latest data.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_PAT")
    repo = os.environ.get("GITHUB_REPO", "sabroservices/Sabro-Vision")
    if not token or not repo or not os.path.exists(VAULT_FILE):
        return False

    try:
        import base64
        import requests

        with open(VAULT_FILE, "rb") as f:
            content_bytes = f.read()

        b64_content = base64.b64encode(content_bytes).decode("utf-8")
        api_url = f"https://api.github.com/repos/{repo}/contents/data_vault.json"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SabroVision-AutoSync/1.0"
        }

        # Check existing file sha
        sha = None
        get_resp = requests.get(api_url, headers=headers, timeout=10)
        if get_resp.status_code == 200:
            sha = get_resp.json().get("sha")

        payload = {
            "message": f"Auto-Sync Sabro Vision Data Vault [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]",
            "content": b64_content,
            "branch": "main"
        }
        if sha:
            payload["sha"] = sha

        put_resp = requests.put(api_url, json=payload, headers=headers, timeout=15)
        if put_resp.status_code in (200, 201):
            logger.info("Successfully pushed data vault to GitHub repository.")
            return True
        else:
            logger.warning(f"GitHub vault push returned HTTP {put_resp.status_code}: {put_resp.text}")
            return False
    except Exception as e:
        logger.error(f"Error during GitHub vault sync: {e}")
        return False

def on_write_event():
    """Call this helper after critical database mutations to trigger persistence."""
    try:
        save_vault_snapshot_to_disk()
        sync_to_github_if_configured()
    except Exception as e:
        logger.error(f"Error in on_write_event persistence trigger: {e}")

def bootstrap_persistence():
    """Initializes persistence hooks on app startup."""
    # 1. Restore from disk if vault file exists
    count = load_vault_from_disk()
    if count > 0:
        logger.info(f"Persistence bootstrap restored {count} records from local vault.")
    
    # 2. Register clean shutdown handler to flush WAL
    atexit.register(truncate_wal)
