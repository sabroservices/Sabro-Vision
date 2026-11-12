import re
import requests
import db

def parse_m3u_content(content):
    """
    Parses M3U/M3U8 string content and extracts channel items:
    [{'name': str, 'stream_url': str, 'logo': str, 'group_title': str, 'category': str}]
    """
    channels = []
    lines = content.splitlines()
    
    current_meta = None
    
    # Regex patterns for EXTINF attributes
    tvg_name_re = re.compile(r'tvg-name=["\'](.*?)["\']', re.IGNORECASE)
    tvg_logo_re = re.compile(r'tvg-logo=["\'](.*?)["\']', re.IGNORECASE)
    group_title_re = re.compile(r'group-title=["\'](.*?)["\']', re.IGNORECASE)

    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if line.startswith("#EXTINF:"):
            # Parse EXTINF
            logo_match = tvg_logo_re.search(line)
            group_match = group_title_re.search(line)
            name_match = tvg_name_re.search(line)
            
            # Extract channel display name (after last comma)
            comma_idx = line.rfind(",")
            if comma_idx != -1:
                display_name = line[comma_idx + 1:].strip()
            else:
                display_name = name_match.group(1) if name_match else "Unknown Channel"

            logo = logo_match.group(1).strip() if logo_match else ""
            group = group_match.group(1).strip() if group_match else "General"
            
            # Standardize group into category
            category = categorize_group(group, display_name)

            current_meta = {
                "name": display_name,
                "logo": logo,
                "group_title": group,
                "category": category
            }
        elif not line.startswith("#") and current_meta:
            # Stream URL
            stream_url = line
            stream_type = "hls" if (".m3u8" in stream_url or "m3u8" in stream_url.lower()) else "ts"
            
            channels.append({
                "name": current_meta["name"],
                "logo": current_meta["logo"],
                "stream_url": stream_url,
                "group_title": current_meta["group_title"],
                "category": current_meta["category"],
                "stream_type": stream_type
            })
            current_meta = None
            
    return channels

def categorize_group(group_title, name=""):
    """Maps arbitrary group-title or name to standard Sabro Vision categories."""
    group_clean = group_title.split(";")[0].strip() if group_title else ""
    if group_clean.lower() in ["undefined", "general", "other", ""]:
        group_clean = "Entertainment"

    combined = f"{group_clean} {name}".lower()
    
    if any(k in combined for k in ["sport", "cricket", "football", "fifa", "ten sports", "ptv sport", "ipl", "psl", "espn", "wwe", "racing", "golf"]):
        return "Sports"
    if any(k in combined for k in ["news", "khabar", "samachar", "geo news", "ary news", "dawn", "dunya", "bol", "cnn", "bbc", "weather"]):
        return "News"
    if any(k in combined for k in ["movie", "cinema", "film", "action", "hbo", "star movies", "box office"]):
        return "Movies"
    if any(k in combined for k in ["islam", "quran", "makkah", "madinah", "sunnah", "deen", "peace tv", "hidayat", "religious"]):
        return "Islamic"
    if any(k in combined for k in ["kid", "cartoon", "disney", "nick", "pogo", "anim", "junior", "family"]):
        return "Kids"
    if any(k in combined for k in ["music", "song", "gaana", "mtv", "jalwa", "sound"]):
        return "Music"
    if any(k in combined for k in ["documentary", "nat geo", "discovery", "history", "wild", "animal", "science", "travel"]):
        return "Documentary"
    if any(k in combined for k in ["pakistan", "urdu", "drama", "hum tv", "geo tv", "ary digital", "express", "series", "entertainment"]):
        return "Entertainment"
        
    return group_clean.capitalize() if len(group_clean) < 25 else "Entertainment"

def import_m3u_url(url, playlist_name="M3U Playlist"):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    
    channels = parse_m3u_content(resp.text)
    return save_imported_channels(channels, playlist_name, source_url=url)

def import_xtream_codes(server_url, username, password):
    """
    Connects to Xtream Codes API (player_api.php) and imports live streams.
    """
    base_url = server_url.rstrip("/")
    api_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_live_streams"
    
    headers = {"User-Agent": "IPTVSmarters/2.2.1.2"}
    resp = requests.get(api_url, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    
    if not isinstance(data, list):
        raise ValueError("Invalid Xtream Codes credentials or server response")
        
    channels = []
    for item in data:
        stream_id = item.get("stream_id")
        name = item.get("name", "Unknown Channel")
        logo = item.get("stream_icon", "")
        category_name = item.get("category_name", "Live TV")
        
        # Xtream codes standard HLS or TS stream URL
        stream_url = f"{base_url}/live/{username}/{password}/{stream_id}.m3u8"
        
        channels.append({
            "name": name,
            "logo": logo,
            "stream_url": stream_url,
            "group_title": category_name,
            "category": categorize_group(category_name, name),
            "stream_type": "hls"
        })
        
    return save_imported_channels(channels, playlist_name=f"Xtream: {username}", source_url=server_url)

def save_imported_channels(channels, playlist_name, source_url=""):
    conn = db.get_db()
    cursor = conn.cursor()
    
    now_str = db.datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO playlists (name, type, source_url, channel_count, last_synced_at, created_at)
        VALUES (?, 'm3u', ?, ?, ?, ?)
    """, (playlist_name, source_url, len(channels), now_str, now_str))
    playlist_id = cursor.lastrowid

    # 1. Bulk insert unique categories
    unique_cats = {ch["category"] for ch in channels if ch.get("category")}
    cursor.executemany(
        "INSERT OR IGNORE INTO categories (name, icon) VALUES (?, 'tv')",
        [(cat,) for cat in unique_cats]
    )

    # 2. Bulk insert all channels with executemany
    rows = [
        (
            ch["name"],
            ch.get("logo", ""),
            ch["stream_url"],
            ch.get("group_title", ""),
            ch.get("category", "Entertainment"),
            ch.get("stream_type", "hls"),
            playlist_id,
            now_str
        )
        for ch in channels
    ]
    cursor.executemany("""
        INSERT INTO channels (name, logo, stream_url, group_title, category, stream_type, playlist_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
        
    conn.commit()
    conn.close()
    return len(channels)
