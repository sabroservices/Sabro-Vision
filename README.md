# SABRO VISION — IPTV & Subscriber Streaming Platform

**Powered by Sabro Networks** | Engineered by **Vshatkay Solutions**

Ultra HD **Obsidian Glass** streaming platform engineered for ISP fiber subscribers (100% Free) and outside subscribers (Flat 250 PKR / 1 Screen), supporting **Web TV**, **Smart TV 10-Foot Leanback (`/tv`)**, **Mobile PWA**, **Xtream Codes API v2**, and **B2B ISP White-Label Partnerships (`/partner`)**.

---

## Quick Local Run (Windows / Linux / macOS)

```bash
pip install -r requirements.txt
python run.py --port 8080
```

- **Direct Sign-In**: `http://127.0.0.1:8080/login` (or `/gatekeeper`)
- **Web Player**: `http://127.0.0.1:8080/`
- **Smart TV Mode**: `http://127.0.0.1:8080/tv`
- **Admin Control Panel**: `http://127.0.0.1:8080/admin/login` *(Default: `ahmedbaloch` / `adminadmin1` — change password immediately after first login under Admin -> Settings)*

---

## 1. Upload to GitHub

From this project folder, run:

```bash
git init
git add .
git commit -m "Initial commit: Sabro Vision IPTV Platform"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

---

## 2. Deploy to Render

### Option A: Blueprint (Recommended — 1 Click via `render.yaml`)
1. Log in to [Render](https://dashboard.render.com/).
2. Click **New +** -> **Blueprint**.
3. Connect your GitHub repository containing **SABRO VISION**.
4. Render automatically detects `render.yaml` (`gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 8 --timeout 120`, `/api/health` probe, and auto-generated `SECRET_KEY`).
5. Click **Apply** and wait ~2 minutes for the live HTTPS URL!

### Option B: Manual Web Service Setup
- **Runtime**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 8 --timeout 120`
- **Health Check Path**: `/api/health`
- **Environment Variables**:
  - `SECRET_KEY`: *(any random 64-char hex string)*
  - `FLASK_DEBUG`: `0`
  - *(Optional Persistent Storage on Paid Plan)*: Mount a Render Disk at `/var/data` and set `DATABASE_PATH=/var/data/sabro_iptv.db`. On first boot, the pre-seeded database (with 11,459+ channels) is automatically copied to `/var/data/sabro_iptv.db`.
