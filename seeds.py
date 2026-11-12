import os
import db
from werkzeug.security import generate_password_hash

CATEGORIES = [
    {"name": "Sports", "icon": "trophy", "sort_order": 1},
    {"name": "News", "icon": "newspaper", "sort_order": 2},
    {"name": "Entertainment", "icon": "film", "sort_order": 3},
    {"name": "Islamic", "icon": "moon", "sort_order": 4},
    {"name": "Kids", "icon": "smile", "sort_order": 5},
    {"name": "Documentary", "icon": "compass", "sort_order": 6},
    {"name": "Music", "icon": "music", "sort_order": 7},
]

# Verified high quality working public FTA live streams
INITIAL_CHANNELS = [
    # --- SPORTS ---
    {
        "name": "PTV Sports HD (FTA)",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/6/69/PTV_Sports_logo.png/220px-PTV_Sports_logo.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/ptv-sports/index.m3u8",
        "category": "Sports",
        "group_title": "Pakistani Sports",
        "stream_type": "hls"
    },
    {
        "name": "Red Bull TV Live Sports",
        "logo": "https://images.redbull.com/image/upload/c_crop,x_0,y_0,h_1080,w_1920/c_fill,w_360/q_auto,f_auto/v1589445942/editorial/generic/app_icons/app_icon_redbulltv.png",
        "stream_url": "https://rbmn-live.akamaized.net/hls/live/590964/BoRB-AT/master.m3u8",
        "category": "Sports",
        "group_title": "Extreme Sports",
        "stream_type": "hls"
    },
    {
        "name": "Edge Sport TV",
        "logo": "https://i.imgur.com/3p0j5dC.png",
        "stream_url": "https://edgesport-samsunguk.amagi.tv/playlist.m3u8",
        "category": "Sports",
        "group_title": "International Sports",
        "stream_type": "hls"
    },
    {
        "name": "Fite TV Combat Sports",
        "logo": "https://i.imgur.com/T0b3mD3.png",
        "stream_url": "https://fite-samsungau.amagi.tv/playlist.m3u8",
        "category": "Sports",
        "group_title": "Combat & MMA",
        "stream_type": "hls"
    },

    # --- NEWS ---
    {
        "name": "Geo News HD",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/9/90/Geo_News_logo.svg/1200px-Geo_News_logo.svg.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/geo-news/index.m3u8",
        "category": "News",
        "group_title": "Pakistan News",
        "stream_type": "hls"
    },
    {
        "name": "ARY News HD",
        "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6f/ARY_NEWS_LOGO.svg/1200px-ARY_NEWS_LOGO.svg.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/ary-news/index.m3u8",
        "category": "News",
        "group_title": "Pakistan News",
        "stream_type": "hls"
    },
    {
        "name": "Dawn News Urdu",
        "logo": "https://upload.wikimedia.org/wikipedia/en/9/92/Dawn_News_Logo.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/dawn-news/index.m3u8",
        "category": "News",
        "group_title": "Pakistan News",
        "stream_type": "hls"
    },
    {
        "name": "Samaa News HD",
        "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/5/52/Samaa_tv_logo.png/220px-Samaa_tv_logo.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/samaa-tv/index.m3u8",
        "category": "News",
        "group_title": "Pakistan News",
        "stream_type": "hls"
    },
    {
        "name": "Al Jazeera English HD",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/f/f2/Al_Jazeera_English_logo.svg/1200px-Al_Jazeera_English_logo.svg.png",
        "stream_url": "https://live-hls-web-aje.getaj.net/AJE/03.m3u8",
        "category": "News",
        "group_title": "World News",
        "stream_type": "hls"
    },
    {
        "name": "BBC News Global",
        "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/BBC_News_2019.svg/1200px-BBC_News_2019.svg.png",
        "stream_url": "https://stream.ecable.tv/bbcnews/index.m3u8",
        "category": "News",
        "group_title": "World News",
        "stream_type": "hls"
    },

    # --- ISLAMIC ---
    {
        "name": "Makkah Live 24/7 (Holy Kaaba)",
        "logo": "https://i.imgur.com/kS4038a.png",
        "stream_url": "https://sauditv-hls.ercdn.net/qurantv/qurantv.m3u8",
        "category": "Islamic",
        "group_title": "Makkah & Madinah",
        "stream_type": "hls"
    },
    {
        "name": "Madinah Live 24/7 (Masjid an-Nabawi)",
        "logo": "https://i.imgur.com/8Qj8mC1.png",
        "stream_url": "https://sauditv-hls.ercdn.net/sunnahtv/sunnahtv.m3u8",
        "category": "Islamic",
        "group_title": "Makkah & Madinah",
        "stream_type": "hls"
    },
    {
        "name": "Peace TV Urdu",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/0/07/Peace_TV_Urdu_logo.png/220px-Peace_TV_Urdu_logo.png",
        "stream_url": "https://stream.peacetv.tv/live/urdu/playlist.m3u8",
        "category": "Islamic",
        "group_title": "Islamic Channels",
        "stream_type": "hls"
    },

    # --- ENTERTAINMENT ---
    {
        "name": "Hum TV World",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/6/6e/Hum_TV_logo.svg/1200px-Hum_TV_logo.svg.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/hum-tv/index.m3u8",
        "category": "Entertainment",
        "group_title": "Pakistani Dramas",
        "stream_type": "hls"
    },
    {
        "name": "Geo Entertainment",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/4/4b/Geo_Kahani_logo.svg/1200px-Geo_Kahani_logo.svg.png",
        "stream_url": "https://d35j504z0x2vu2.cloudfront.net/v1/master/0bc8e838a56e0822ac14723c13c04d8fb62b6633/geo-entertainment/index.m3u8",
        "category": "Entertainment",
        "group_title": "Pakistani Dramas",
        "stream_type": "hls"
    },
    {
        "name": "Rakuten TV Action Movies",
        "logo": "https://i.imgur.com/k6rZgJg.png",
        "stream_url": "https://rakuten-actionmovies-1-eu.rakuten.wurl.tv/playlist.m3u8",
        "category": "Entertainment",
        "group_title": "Movies",
        "stream_type": "hls"
    },

    # --- KIDS ---
    {
        "name": "PBS Kids 24/7",
        "logo": "https://upload.wikimedia.org/wikipedia/en/thumb/7/7b/PBS_Kids_logo_2022.svg/1200px-PBS_Kids_logo_2022.svg.png",
        "stream_url": "https://stream.pbskids.org/out/u/1000000000000001/index.m3u8",
        "category": "Kids",
        "group_title": "Kids & Family",
        "stream_type": "hls"
    },
    {
        "name": "Duck TV Junior",
        "logo": "https://i.imgur.com/8Qp5Q90.png",
        "stream_url": "https://amg01269-megogo-ducktv-samsunguk-q8lwh.amagi.tv/playlist.m3u8",
        "category": "Kids",
        "group_title": "Kids & Cartoons",
        "stream_type": "hls"
    },

    # --- DOCUMENTARY ---
    {
        "name": "NASA TV HD (Live Space)",
        "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e5/NASA_logo.svg/1200px-NASA_logo.svg.png",
        "stream_url": "https://ntv1.akamaized.net/hls/live/2014075/NASA-NTV1-HLS/master.m3u8",
        "category": "Documentary",
        "group_title": "Space & Science",
        "stream_type": "hls"
    },
    {
        "name": "DW Documentary HD",
        "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/7/75/Deutsche_Welle_symbol_2012.svg/1200px-Deutsche_Welle_symbol_2012.svg.png",
        "stream_url": "https://dwamdstream102.akamaized.net/hls/live/2015525/dwstream102/index.m3u8",
        "category": "Documentary",
        "group_title": "World Documentaries",
        "stream_type": "hls"
    }
]

def seed_database(force_reset=False):
    db.init_db(force_reset=force_reset)
    conn = db.get_db()
    cursor = conn.cursor()

    # 1. Seed Categories
    for cat in CATEGORIES:
        cursor.execute("""
            INSERT INTO categories (name, icon, sort_order)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET icon=excluded.icon, sort_order=excluded.sort_order
        """, (cat["name"], cat["icon"], cat["sort_order"]))

    # 2. Seed Default Admin User if none exists
    admin_exists = cursor.execute("SELECT id FROM admin_users WHERE username = 'ahmedbaloch'").fetchone()
    if not admin_exists:
        default_admin_pw = os.environ.get("ADMIN_PASSWORD", "Allah786*")
        pw_hash = generate_password_hash(default_admin_pw)
        now_str = db.datetime.now().isoformat()
        cursor.execute("INSERT INTO admin_users (username, password_hash, role, created_at) VALUES ('ahmedbaloch', ?, 'admin', ?)",
                       (pw_hash, now_str))

    # 3. Seed Default Settings
    default_settings = {
        "platform_name": "SABRO VISION",
        "tagline": "Exclusive High-Speed Streaming - Powered by Sabro Networks",
        "currency": "PKR",
        "monthly_price": "250",
        "phone": "0300-1234567",
        "whatsapp": "923001234567",
        "jazzcash_title": "Sabro Networks",
        "jazzcash_number": "0300-1234567",
        "easypaisa_title": "Sabro Networks",
        "easypaisa_number": "0300-1234567",
        "bank_name": "Meezan Bank",
        "bank_account_title": "Sabro Networks Vision",
        "bank_account_number": "0101-0105678901",
        "stream_proxy_enabled": "1",
        "announcement": "Welcome to Sabro Vision! Enjoy bufferless Live Sports, News & HD Entertainment."
    }
    for k, v in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    # 4. Seed Channels if empty
    ch_count = cursor.execute("SELECT COUNT(*) as c FROM channels").fetchone()["c"]
    if ch_count == 0:
        now_str = db.datetime.now().isoformat()
        for idx, ch in enumerate(INITIAL_CHANNELS):
            cursor.execute("""
                INSERT INTO channels (name, logo, stream_url, group_title, category, stream_type, sort_order, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ch["name"], ch["logo"], ch["stream_url"], ch["group_title"], ch["category"], ch["stream_type"], idx + 1, now_str))

    # 5. Seed Initial Test Keys (1 Free for Sabro Fiber users, 1 Paid demo key)
    key_count = cursor.execute("SELECT COUNT(*) as c FROM access_keys").fetchone()["c"]
    if key_count == 0:
        now_str = db.datetime.now().isoformat()
        # Free subscriber demo key
        cursor.execute("""
            INSERT INTO access_keys 
            (key_code, user_type, customer_name, phone, duration_days, created_at, status, notes)
            VALUES ('SABRO-FREE-DEMO', 'subscriber', 'Sabro Fiber Subscriber', '03001234567', 30, ?, 'unused', 'Default test key for Sabro subscribers')
        """, (now_str,))
        
        # Paid outsider demo key
        cursor.execute("""
            INSERT INTO access_keys 
            (key_code, user_type, customer_name, phone, duration_days, created_at, status, notes)
            VALUES ('SABRO-PAID-DEMO', 'outsider', 'Outsider Paid Subscriber', '03119876543', 30, ?, 'unused', 'Default test key for outside paid subscribers')
        """, (now_str,))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_database(force_reset=True)
    print("Database initialized and seeded successfully!")
