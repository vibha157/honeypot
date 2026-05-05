"""
IoT Honeypot - Log Parser
Parses Cowrie JSON logs and extracts all attacker Indicators of Compromise (IoCs)
Project 2: Healthcare - IoT Deception Honeypot Network
Infotact Technical Internship Program
"""

import json
import os
from datetime import datetime
from collections import Counter


LOG_FILE = "cowrie-logs/cowrie.json"


def parse_cowrie_logs(log_file=LOG_FILE):
    """
    Parse Cowrie JSON log file and extract all IoCs.
    Returns dict with attacker IPs, credentials tried, commands run, file downloads.
    """
    if not os.path.exists(log_file):
        print(f"[ERROR] Log file not found: {log_file}")
        print("Make sure Cowrie is running and attackers have connected.")
        print("For testing, run:  python3 scripts/simulate_attack.py")
        return None

    iocs = {
        "attacker_ips": set(),
        "credentials_tried": [],
        "commands_run": [],
        "files_downloaded": [],
        "session_ids": set(),
        "total_events": 0
    }

    print(f"[*] Parsing log file: {log_file}")
    print("-" * 50)

    with open(log_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                iocs["total_events"] += 1
                event_type = event.get("eventid", "")
                src_ip = event.get("src_ip", "unknown")
                session = event.get("session", "")

                if src_ip != "unknown":
                    iocs["attacker_ips"].add(src_ip)
                if session:
                    iocs["session_ids"].add(session)

                # Login attempts (both success and fail)
                if event_type in ("cowrie.login.success", "cowrie.login.failed"):
                    username = event.get("username", "")
                    password = event.get("password", "")
                    success = event_type == "cowrie.login.success"
                    iocs["credentials_tried"].append({
                        "ip": src_ip,
                        "username": username,
                        "password": password,
                        "success": success,
                        "timestamp": event.get("timestamp", "")
                    })
                    status = "SUCCESS" if success else "FAILED"
                    print(f"[LOGIN {status}] {src_ip} tried {username}:{password}")

                # Commands typed by attacker
                elif event_type == "cowrie.command.input":
                    cmd = event.get("input", "")
                    iocs["commands_run"].append({
                        "ip": src_ip,
                        "command": cmd,
                        "session": session,
                        "timestamp": event.get("timestamp", "")
                    })
                    print(f"[COMMAND] {src_ip} ran: {cmd}")

                # Files downloaded/uploaded by attacker (malware)
                elif event_type in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                    file_info = {
                        "ip": src_ip,
                        "url": event.get("url", ""),
                        "filename": event.get("filename", ""),
                        "sha256": event.get("shasum", ""),
                        "size": event.get("size", 0),
                        "timestamp": event.get("timestamp", "")
                    }
                    iocs["files_downloaded"].append(file_info)
                    print(f"[FILE DROP] {src_ip} dropped file SHA256: {file_info['sha256']}")

            except json.JSONDecodeError:
                continue

    # Convert sets to lists for JSON serialization
    iocs["attacker_ips"] = list(iocs["attacker_ips"])
    iocs["session_ids"] = list(iocs["session_ids"])

    return iocs


def print_summary(iocs):
    """Print a clean summary of all extracted IoCs."""
    print("\n" + "=" * 60)
    print("  HONEYPOT THREAT INTELLIGENCE SUMMARY")
    print("=" * 60)

    print(f"\n  Total Events Logged  : {iocs['total_events']}")
    print(f"  Unique Attacker IPs  : {len(iocs['attacker_ips'])}")
    print(f"  Login Attempts       : {len(iocs['credentials_tried'])}")
    print(f"  Commands Executed    : {len(iocs['commands_run'])}")
    print(f"  Files Dropped        : {len(iocs['files_downloaded'])}")
    print(f"  Unique Sessions      : {len(iocs['session_ids'])}")

    if iocs["attacker_ips"]:
        print(f"\n  Attacker IPs:")
        for ip in iocs["attacker_ips"]:
            print(f"    - {ip}")

    if iocs["credentials_tried"]:
        print(f"\n  Top 5 Passwords Tried:")
        passwords = [c["password"] for c in iocs["credentials_tried"]]
        for pwd, count in Counter(passwords).most_common(5):
            print(f"    {count}x  {pwd}")

    if iocs["commands_run"]:
        print(f"\n  Commands Run by Attackers:")
        for cmd_info in iocs["commands_run"][:10]:
            print(f"    [{cmd_info['ip']}] {cmd_info['command']}")

    if iocs["files_downloaded"]:
        print(f"\n  Malware Files Dropped:")
        for f in iocs["files_downloaded"]:
            print(f"    SHA256: {f['sha256']}")
            print(f"    URL   : {f['url']}")

    print("\n" + "=" * 60)


def save_iocs_to_file(iocs, output="reports/iocs_extracted.json"):
    """Save extracted IoCs to a JSON file for further analysis."""
    os.makedirs("reports", exist_ok=True)
    with open(output, "w") as f:
        json.dump(iocs, f, indent=2, default=str)
    print(f"\n[*] IoCs saved to: {output}")


if __name__ == "__main__":
    iocs = parse_cowrie_logs()
    if iocs:
        print_summary(iocs)
        save_iocs_to_file(iocs)
        print("\n[*] Next step: Run   python3 scripts/geolocate.py   to map attack origins")
