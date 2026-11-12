#!/usr/bin/env python3
"""
SABRO VISION - High-Speed Stream Health Diagnostic & Testing Engine
Tests HLS / M3U8 video streams ingested from GitHub and updates database status.
"""

import os
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import db

def test_stream_worker(channel):
    """Probes a single channel stream URL."""
    cid = channel["id"]
    name = channel["name"]
    url = channel["stream_url"]
    cat = channel["category"]
    
    is_online, status_code, latency_ms, reason = db.test_single_stream(url, timeout=3.5)
    
    if is_online:
        health = "slow" if latency_ms > 2500 else "online"
    else:
        health = "offline"
        
    return {
        "id": cid,
        "name": name,
        "category": cat,
        "url": url,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "health": health,
        "reason": reason
    }

def run_diagnostics(limit=None, category=None, workers=50, disable_offline=False, batch_size=200):
    print("======================================================================")
    print("        SABRO VISION v1.0 - STREAM HEALTH TESTING ENGINE              ")
    print("======================================================================")
    
    conn = db.get_db()
    query = "SELECT id, name, stream_url, category FROM channels WHERE 1=1"
    params = []
    if category and category.lower() != "all":
        query += " AND category = ?"
        params.append(category)
    if limit:
        query += f" LIMIT {int(limit)}"
    
    channels = conn.execute(query, params).fetchall()
    total_count = conn.execute("SELECT COUNT(*) as c FROM channels").fetchone()["c"]
    conn.close()

    total_to_test = len(channels)
    print(f"[*] Ingested Channels in Database: {total_count:,}")
    print(f"[*] Target Scope: {total_to_test:,} channels" + (f" (Category: {category})" if category else " (Global Catalog)"))
    print(f"[*] Concurrent Workers: {workers} threads")
    print(f"[*] Probe Timeout: 3.5s per stream\n")

    if total_to_test == 0:
        print("[!] No channels matched the specified criteria.")
        return

    results = []
    online_count = 0
    slow_count = 0
    offline_count = 0
    t_start = time.time()
    
    print(f"{'#':<6} | {'STATUS':<9} | {'LATENCY':<8} | {'CATEGORY':<14} | {'CHANNEL NAME'}")
    print("-" * 75)

    # Process in batches to write updates progressively to SQLite
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ch = {executor.submit(test_stream_worker, ch): ch for ch in channels}
        
        idx = 0
        batch_to_save = []
        now_str = datetime.now().isoformat()
        
        for future in as_completed(future_to_ch):
            idx += 1
            res = future.result()
            results.append(res)
            batch_to_save.append(res)
            
            if res["health"] == "online":
                online_count += 1
                status_str = "\033[92mONLINE\033[0m" if sys.stdout.isatty() else "[ONLINE]"
            elif res["health"] == "slow":
                slow_count += 1
                status_str = "\033[93mSLOW\033[0m" if sys.stdout.isatty() else "[SLOW]"
            else:
                offline_count += 1
                status_str = "\033[91mOFFLINE\033[0m" if sys.stdout.isatty() else "[OFFLINE]"

            # Print first 25 or online hits or every 50th progress
            if idx <= 25 or res["health"] in ("online", "slow") or idx % 50 == 0:
                print(f"{idx:<6} | {res['health'].upper():<9} | {res['latency_ms']:>4}ms   | {res['category'][:14]:<14} | {res['name'][:30]}")

            # Progressive batch commit to SQLite
            if len(batch_to_save) >= batch_size:
                c = db.get_db()
                c.executemany("""
                    UPDATE channels
                    SET health_status = ?, response_time_ms = ?, last_checked_at = ?
                    WHERE id = ?
                """, [(r["health"], r["latency_ms"], now_str, r["id"]) for r in batch_to_save])
                c.commit()
                c.close()
                batch_to_save.clear()

        # Commit any remaining items
        if batch_to_save:
            c = db.get_db()
            c.executemany("""
                UPDATE channels
                SET health_status = ?, response_time_ms = ?, last_checked_at = ?
                WHERE id = ?
            """, [(r["health"], r["latency_ms"], now_str, r["id"]) for r in batch_to_save])
            c.commit()
            c.close()
            batch_to_save.clear()

    total_time = time.time() - t_start
    total_online = online_count + slow_count
    online_pct = (total_online / total_to_test * 100) if total_to_test > 0 else 0

    print("\n" + "=" * 70)
    print("                     DIAGNOSTIC TEST SUMMARY                          ")
    print("=" * 70)
    print(f"  Channels Tested:       {total_to_test:,}")
    print(f"  Verified Online:       {online_count:,} ({online_count / total_to_test * 100:.1f}%)")
    print(f"  Slow Latency (>2.5s):  {slow_count:,}")
    print(f"  Offline / Inactive:    {offline_count:,} ({offline_count / total_to_test * 100:.1f}%)")
    print(f"  Total Active Streams:  {total_online:,} ({online_pct:.1f}% health)")
    print(f"  Elapsed Time:          {total_time:.1f} seconds ({total_to_test / total_time:.1f} streams/sec)")
    print("=" * 70)

    if disable_offline:
        disabled = db.bulk_toggle_offline_channels(enable=False)
        print(f"\n[+] Successfully deactivated {disabled:,} offline channels from public list.")
        print("    Subscribers will now only see 100% verified working streams!")

    return results

def main():
    parser = argparse.ArgumentParser(description="Sabro Vision Stream Tester")
    parser.add_argument("--all", action="store_true", help="Test all channels in catalog")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of channels to test (default: all)")
    parser.add_argument("--category", type=str, default=None, help="Filter by specific category (e.g. Sports, News)")
    parser.add_argument("--workers", type=int, default=50, help="Concurrent worker threads (default: 50)")
    parser.add_argument("--disable-offline", action="store_true", help="Automatically set is_active=0 for offline feeds")
    args = parser.parse_args()

    run_diagnostics(
        limit=args.limit,
        category=args.category,
        workers=args.workers,
        disable_offline=args.disable_offline
    )

if __name__ == "__main__":
    main()
