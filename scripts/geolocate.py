"""
IoT Honeypot - IP Geolocation & Attack Map Generator
Enriches attacker IPs with country/city/ISP info and builds a world map
Project 2: Healthcare - IoT Deception Honeypot Network
Infotact Technical Internship Program
"""

import json
import os
import time
import requests


def geolocate_ip(ip):
    """
    Geolocate a single IP address using ip-api.com (free, no key needed).
    Returns dict with country, city, ISP, lat, lon.
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon,org"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0)
            }
    except Exception as e:
        print(f"[WARN] Could not geolocate {ip}: {e}")

    return {
        "ip": ip,
        "country": "Unknown",
        "country_code": "??",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "lat": 0,
        "lon": 0
    }


def geolocate_all(iocs_file="reports/iocs_extracted.json"):
    """Load IoCs and geolocate all attacker IPs."""
    if not os.path.exists(iocs_file):
        print(f"[ERROR] IoCs file not found: {iocs_file}")
        print("Run parse_logs.py first:  python3 scripts/parse_logs.py")
        return []

    with open(iocs_file) as f:
        iocs = json.load(f)

    attacker_ips = iocs.get("attacker_ips", [])

    if not attacker_ips:
        # Use demo IPs for testing when no real attackers yet
        print("[INFO] No attacker IPs found. Using demo IPs for testing.")
        attacker_ips = [
            "185.220.101.45",   # Tor exit node (Russia)
            "45.33.32.156",     # Known scanner (USA)
            "103.21.244.0",     # Asia Pacific
            "194.165.16.29",    # Netherlands
            "89.248.167.131",   # Netherlands
            "198.199.10.234",   # USA
        ]

    geo_results = []
    print(f"[*] Geolocating {len(attacker_ips)} attacker IP(s)...")
    print("-" * 50)

    for ip in attacker_ips:
        geo = geolocate_ip(ip)
        geo_results.append(geo)
        print(f"  {ip} -> {geo['city']}, {geo['country']} ({geo['isp']})")
        time.sleep(0.5)  # Be polite to the free API

    return geo_results


def build_attack_map(geo_results, output="reports/attack_map.html"):
    """Build an interactive world map showing attack origins using Folium."""
    try:
        import folium
        from collections import Counter
    except ImportError:
        print("[ERROR] Folium not installed. Run:  pip3 install folium")
        return

    os.makedirs("reports", exist_ok=True)

    # Count attacks per country for summary
    countries = Counter([g["country"] for g in geo_results if g["country"] != "Unknown"])

    # Create the map centered on the world
    m = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="CartoDB dark_matter"
    )

    # Add a marker for each attacker IP
    for geo in geo_results:
        if geo["lat"] == 0 and geo["lon"] == 0:
            continue

        popup_text = f"""
        <b>Attacker IP:</b> {geo['ip']}<br>
        <b>Country:</b> {geo['country']}<br>
        <b>City:</b> {geo['city']}<br>
        <b>ISP:</b> {geo['isp']}<br>
        <b>Org:</b> {geo['org']}
        """

        folium.CircleMarker(
            location=[geo["lat"], geo["lon"]],
            radius=8,
            color="#E24B4A",
            fill=True,
            fill_color="#E24B4A",
            fill_opacity=0.8,
            popup=folium.Popup(popup_text, max_width=250),
            tooltip=f"{geo['ip']} - {geo['country']}"
        ).add_to(m)

    # Add a title to the map
    title_html = """
    <div style="position: fixed; top: 10px; left: 50%; transform: translateX(-50%);
                z-index: 1000; background: rgba(0,0,0,0.8); color: white;
                padding: 10px 20px; border-radius: 8px; font-family: monospace;">
        <b>IoT Honeypot - Attack Origin Map</b><br>
        <small>VitalsMonitor-RPi4 | Healthcare Deception Network</small>
    </div>
    """
    m.get_root().html.add_child(folium.Element(title_html))

    m.save(output)
    print(f"\n[*] Attack map saved to: {output}")
    print(f"[*] Open it in your browser to see the world map!")

    # Print country summary
    print(f"\n  Top Attacking Countries:")
    for country, count in countries.most_common(10):
        print(f"    {count}x  {country}")


def save_geo_data(geo_results, output="reports/geo_enriched.json"):
    """Save geolocated data to JSON."""
    os.makedirs("reports", exist_ok=True)
    with open(output, "w") as f:
        json.dump(geo_results, f, indent=2)
    print(f"[*] Geo data saved to: {output}")


if __name__ == "__main__":
    geo_results = geolocate_all()
    if geo_results:
        save_geo_data(geo_results)
        build_attack_map(geo_results)
        print("\n[*] Done! Open reports/attack_map.html in your browser.")
