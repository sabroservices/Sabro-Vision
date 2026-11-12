# Sabro Vision - 100% Zero-Cost 24/7 Deployment & Operation Guide

This guide explains how to host and run **Sabro Vision** 24 hours a day, 7 days a week, **without spending a single rupee**, while maintaining full control over monthly subscriber access keys and outsider monetization.

---

## Deployment Option 1: On Your Local Sabro Networks Server / Windows PC (0 PKR)

Running on your existing ISP network machine (the same network as your MikroTik or Fiber OLT) provides the **fastest streaming speeds** with **zero latency**, because traffic stays inside your local optical fiber network!

### Step 1: Run Sabro Vision on Startup (Auto-Run 24/7)
To ensure the server starts automatically when the Windows computer powers on:
1. Press `Win + R`, type `shell:startup`, and press Enter.
2. Right-click inside the startup folder -> **New** -> **Shortcut**.
3. Browse and select `start_sabro_iptv.bat` in this folder.
4. Now, if the computer reboots after power loss, Sabro Vision starts automatically!

### Step 2: Make It Accessible to All Fiber Users (MikroTik DNS)
If you run Sabro Networks on MikroTik, you can give your subscribers a clean, professional address (e.g., `http://tv.sabronetworks.com` or `http://iptv.local`):
1. In Winbox, go to **IP** -> **DNS** -> **Static**.
2. Click **+ Add**:
   - **Name:** `tv.sabronetworks.com` (or `iptv.local`)
   - **Address:** Your local server IP (e.g. `192.168.10.5` or your local gateway IP)
3. In **IP** -> **Firewall** -> **NAT**, ensure port `8080` or `80` redirects to the IPTV server machine.
4. Now, any customer on your fiber network can simply open `http://tv.sabronetworks.com:8080` on their phone, laptop, or Android TV!

---

## Deployment Option 2: Oracle Cloud Always-Free Tier (0 PKR Forever)

Oracle Cloud provides **Always-Free compute instances** with **zero credit card charges forever**:
- 4 ARM OCPUs & 24 GB RAM (or 2 x86 AMD VMs)
- 200 GB NVMe Storage
- 10 TB/Month Free Egress Bandwidth
- Free Static Public IPv4 Address

### Step 1: Create Free Oracle VM
1. Go to `https://www.oracle.com/cloud/free/` and sign up for an Always Free account.
2. In the Oracle Cloud Console, navigate to **Compute** -> **Instances** -> **Create Instance**.
3. Select **Ubuntu 22.04 Minimal** or **Ubuntu 24.04**.
4. Choose **Ampere (ARM)** with 2 to 4 OCPUs and 12-24 GB RAM (Always Free Eligible).
5. Download your SSH private key and click **Create**.

### Step 2: Open Ingress Ports in Oracle Cloud
In the Oracle Cloud Console:
1. Go to **Networking** -> **Virtual Cloud Networks** -> your VCN -> **Security Lists** -> **Default Security List**.
2. Click **Add Ingress Rules**:
   - **Source CIDR:** `0.0.0.0/0`
   - **IP Protocol:** TCP
   - **Destination Port Range:** `80, 443, 8080`
3. Click **Add Ingress Rules**.

### Step 3: Deploy Sabro Vision on the Ubuntu Server
Connect via SSH and run:
```bash
# 1. Update system & install Python
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# 2. Upload or clone SABRO VISION folder to /var/www/sabro_vision
sudo mkdir -p /var/www/sabro_vision
sudo chown -R $USER:$USER /var/www/sabro_vision

# Copy files or use scp/sftp to transfer the SABRO VISION files
cd /var/www/sabro_vision

# 3. Create virtual environment & install requirements
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Initialize database
python3 seeds.py
```

### Step 4: Configure systemd (Auto-Restart 24/7)
Create an automatic system service so Sabro Vision keeps running forever and restarts on system reboot:
```bash
sudo nano /etc/systemd/system/sabro_vision.service
```
Paste this configuration:
```ini
[Unit]
Description=Sabro Vision 24/7 Production Server
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/var/www/sabro_iptv
ExecStart=/var/www/sabro_iptv/venv/bin/python /var/www/sabro_iptv/run.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sabro_iptv
sudo systemctl start sabro_iptv
sudo systemctl status sabro_iptv
```

---

## Monthly Access Key Business Workflow

### 1. For Sabro Networks Fiber Subscribers (FREE)
- Every month when generating internet bills, your billing team generates a monthly key (or bulk generates 100 keys in the Admin Panel under **Access Keys** -> **Bulk Generate**).
- Share the key with the customer via WhatsApp using the built-in 1-click WhatsApp share button.
- The key is valid for 30 days. When their internet package renews, give them the next month's key.

### 2. For Outside Users (PAID)
- Outsiders open your IPTV address and see the **Direct Sign-In** screen (with expandable Pricing & Payment info).
- They see your **JazzCash**, **EasyPaisa**, or **Meezan Bank** account details and transfer **PKR 250** (flat rate for 1 Screen).
- They click the **"Buy Monthly Pass via WhatsApp"** button, which sends you proof of payment.
- In your Admin Panel (`/admin/keys`), click **Generate Key**:
  - Select: **Paid Outsider**
  - Enter customer name & phone number.
  - Click **Generate Key** -> click the green **WhatsApp** icon next to the key to instantly deliver it to the customer!
