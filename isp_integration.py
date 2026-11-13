"""
isp_integration.py
==================
Sabro Networks ISP Management Integration Engine.
Connects SABRO VISION with the Sabro Networks ISP management system
(https://github.com/sabroservices/Sabro-Networks) or authenticated Radius / BRAS / Billing API.

Features:
- Authenticated server-to-server API verification of broadband subscribers.
- In-memory and database TTL caching for high-speed sub-millisecond lookups.
- Automatic entitlement synchronization: Active Sabro broadband users get 100% FREE access.
- Safe manual fallback mode when external API credentials are not yet configured.
- Audit logging for all verification and sync operations.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
import requests

logger = logging.getLogger("sabro.isp")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# Default cache duration: 1 hour (3600 seconds)
DEFAULT_CACHE_TTL_SECONDS = 3600


class SabroISPClient:
    """Client for communicating with the Sabro Networks ISP Management platform."""

    def __init__(self, api_url=None, api_key=None, timeout=5.0):
        self.api_url = (api_url or os.environ.get("SABRO_ISP_API_URL") or "").rstrip("/")
        self.api_key = api_key or os.environ.get("SABRO_ISP_API_KEY") or ""
        self.timeout = float(timeout)
        self._memory_cache = {}

    def is_configured(self) -> bool:
        """Returns True if a real API URL and API Key are configured."""
        return bool(self.api_url and self.api_key and not self.api_url.startswith("http://localhost-unconfigured"))

    def verify_subscriber(self, identifier: str, db_conn=None) -> dict:
        """
        Verifies whether the identifier (PPPoE username, phone, or account number)
        belongs to an active Sabro Networks broadband customer.
        
        Returns:
            dict: {
                "verified": bool,
                "is_active": bool,
                "pppoe_username": str,
                "customer_name": str,
                "phone": str,
                "broadband_package": str,
                "zone": str,
                "fat_id": str,
                "source": "api" | "cache" | "local_db" | "manual",
                "message": str
            }
        """
        if not identifier:
            return {
                "verified": False,
                "is_active": False,
                "message": "Empty identifier provided."
            }

        identifier_clean = identifier.strip().lower()

        # 1. Check in-memory / DB cache
        now = datetime.now(timezone.utc)
        cached = self._check_cache(identifier_clean, db_conn, now)
        if cached:
            return cached

        # 2. If external API is configured, call server-to-server endpoint
        if self.is_configured():
            try:
                endpoint = f"{self.api_url}/api/v1/subscribers/verify"
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                    "User-Agent": "SabroVision-ISP-Connector/1.0"
                }
                params = {"identifier": identifier_clean}
                response = requests.get(endpoint, headers=headers, params=params, timeout=self.timeout)

                if response.status_code == 200:
                    data = response.json()
                    is_active = data.get("status", "").lower() in ("active", "online", "paid")
                    result = {
                        "verified": True,
                        "is_active": is_active,
                        "pppoe_username": data.get("pppoe_username", identifier_clean),
                        "customer_name": data.get("customer_name", "Sabro Broadband Customer"),
                        "phone": data.get("phone", ""),
                        "broadband_package": data.get("package_name", "Fiber 50Mbps"),
                        "zone": data.get("zone", "Sabro Fiber Zone"),
                        "fat_id": data.get("fat_id", ""),
                        "source": "api",
                        "message": f"Successfully verified via Sabro Networks ISP API (Status: {data.get('status')})."
                    }
                    self._save_cache(identifier_clean, result, db_conn, now)
                    return result
                elif response.status_code == 404:
                    return {
                        "verified": False,
                        "is_active": False,
                        "message": "Identifier not found in Sabro Networks ISP management database."
                    }
                else:
                    logger.warning(f"Sabro ISP API returned error status: {response.status_code}")
            except Exception as e:
                logger.error(f"Error connecting to Sabro Networks ISP API: {e}")

        # 3. Fallback: Query local database for PPPoE records or local verification cache
        if db_conn:
            try:
                row = db_conn.execute(
                    "SELECT * FROM isp_verifications WHERE LOWER(pppoe_username) = ? OR phone = ?",
                    (identifier_clean, identifier_clean)
                ).fetchone()
                if row:
                    return {
                        "verified": True,
                        "is_active": bool(row["is_active"]),
                        "pppoe_username": row["pppoe_username"],
                        "customer_name": row["customer_name"] or "Sabro Customer",
                        "phone": row["phone"] or "",
                        "broadband_package": row["isp_package"] or "Sabro Fiber",
                        "zone": "Lyari Central",
                        "fat_id": "",
                        "source": "local_db",
                        "message": "Verified against local Sabro ISP customer records."
                    }
            except Exception as e:
                logger.warning(f"Error checking local isp_verifications: {e}")

        # 4. Fallback: Default manual verification requirement
        return {
            "verified": False,
            "is_active": False,
            "message": "Sabro Networks ISP API not configured or customer record not found. Requires manual admin approval."
        }

    def _check_cache(self, identifier: str, db_conn, now: datetime):
        # In-memory check
        if identifier in self._memory_cache:
            entry = self._memory_cache[identifier]
            if now < entry["expires_at"]:
                cached_res = dict(entry["data"])
                cached_res["source"] = "cache"
                return cached_res

        # DB cache check
        if db_conn:
            try:
                row = db_conn.execute(
                    "SELECT * FROM isp_verifications WHERE LOWER(pppoe_username) = ?",
                    (identifier,)
                ).fetchone()
                if row and row["last_verified_at"]:
                    try:
                        verified_time = datetime.fromisoformat(row["last_verified_at"])
                        if verified_time.tzinfo is None:
                            verified_time = verified_time.replace(tzinfo=timezone.utc)
                        if now - verified_time < timedelta(seconds=DEFAULT_CACHE_TTL_SECONDS):
                            return {
                                "verified": True,
                                "is_active": bool(row["is_active"]),
                                "pppoe_username": row["pppoe_username"],
                                "customer_name": row["customer_name"],
                                "phone": row["phone"],
                                "broadband_package": row["isp_package"],
                                "source": "cache",
                                "message": "Verified from recent cache."
                            }
                    except Exception:
                        pass
            except Exception:
                pass
        return None

    def _save_cache(self, identifier: str, result: dict, db_conn, now: datetime):
        self._memory_cache[identifier] = {
            "data": result,
            "expires_at": now + timedelta(seconds=DEFAULT_CACHE_TTL_SECONDS)
        }
        if db_conn:
            try:
                now_str = now.isoformat()
                db_conn.execute("""
                    INSERT INTO isp_verifications (pppoe_username, phone, customer_name, is_active, isp_package, last_verified_at, raw_response)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pppoe_username) DO UPDATE SET
                        is_active = excluded.is_active,
                        phone = excluded.phone,
                        customer_name = excluded.customer_name,
                        isp_package = excluded.isp_package,
                        last_verified_at = excluded.last_verified_at,
                        raw_response = excluded.raw_response
                """, (
                    result.get("pppoe_username", identifier),
                    result.get("phone", ""),
                    result.get("customer_name", ""),
                    1 if result.get("is_active") else 0,
                    result.get("broadband_package", ""),
                    now_str,
                    json.dumps(result)
                ))
                db_conn.commit()
            except Exception as e:
                logger.warning(f"Failed to cache ISP verification to DB: {e}")


# Singleton instance
_client = None

def get_isp_client(settings=None) -> SabroISPClient:
    global _client
    api_url = None
    api_key = None
    if settings:
        api_url = settings.get("sabro_isp_api_url")
        api_key = settings.get("sabro_isp_api_key")
    if _client is None or api_url or api_key:
        _client = SabroISPClient(api_url=api_url, api_key=api_key)
    return _client
