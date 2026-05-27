# simulate_attack.py — Manual Control Demo Mode (FIXED)

import random
import time
import os
import csv
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────
BASE_DIR  = r"D:\Cyber_Project"
ALERT_LOG = os.path.join(BASE_DIR, "results", "ids_alerts.csv")

from config import TARGET_IP  # ✅ TARGET SYSTEM
TARGET_PORT = None             # None = use attack-specific ports

os.makedirs(os.path.join(BASE_DIR, "results"), exist_ok=True)

# ── Initialize CSV file ───────────────────────────────────────
if not os.path.exists(ALERT_LOG) or os.path.getsize(ALERT_LOG) == 0:
    with open(ALERT_LOG, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp","src_ip","dst_ip",
            "src_port","dst_port","proto",
            "pred_label","confidence"
        ])

# ── Generate realistic local IP (same subnet) ─────────────────
def random_ip():
    while True:
        ip = f"192.168.29.{random.randint(2, 254)}"
        if ip != TARGET_IP:
            return ip

# ── Write alert to CSV ────────────────────────────────────────
def write_alert(src_ip, dst_ip, src_port, dst_port,
                attack_type, confidence, proto="TCP"):
    with open(ALERT_LOG, "a", newline="") as f:
        csv.writer(f).writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, dst_ip, src_port, dst_port,
            proto, attack_type, confidence
        ])

# ── Attack definitions ────────────────────────────────────────
ATTACKS = {
    "1": {"name":"DDoS SYN Flood","type":"DDoS","count":15,"conf":(0.88,0.99),"proto":"TCP","ports":[80,443,1883,22],"icon":"🔴"},
    "2": {"name":"DDoS UDP Flood","type":"DDoS","count":12,"conf":(0.85,0.98),"proto":"UDP","ports":[80,443,53],"icon":"🔴"},
    "3": {"name":"Recon Port Scan","type":"Recon","count":8,"conf":(0.78,0.93),"proto":"TCP","ports":list(range(20,1025,50)),"icon":"🟡"},
    "4": {"name":"Recon OS Fingerprint","type":"Recon","count":5,"conf":(0.75,0.90),"proto":"TCP","ports":[80,443,22,21],"icon":"🟡"},
    "5": {"name":"ARP Spoofing","type":"Spoofing","count":6,"conf":(0.82,0.96),"proto":"TCP","ports":[80,443,53],"icon":"🟣"},
    "6": {"name":"DNS Spoofing","type":"Spoofing","count":4,"conf":(0.80,0.93),"proto":"UDP","ports":[53],"icon":"🟣"},
    "7": {"name":"SSH Brute Force","type":"BruteForce","count":10,"conf":(0.85,0.97),"proto":"TCP","ports":[22],"icon":"🟠"},
    "8": {"name":"Web Login Brute Force","type":"BruteForce","count":8,"conf":(0.88,0.99),"proto":"TCP","ports":[80,443,8080],"icon":"🟠"},
    "9": {"name":"Normal ESP32 Traffic","type":"BENIGN","count":10,"conf":(0.88,0.99),"proto":"TCP","ports":[1883],"icon":"🟢"},
    "10":{"name":"Mixed Normal Traffic","type":"BENIGN","count":8,"conf":(0.85,0.99),"proto":"TCP","ports":[80,443,53,1883],"icon":"🟢"},
    "11":{"name":"Full Attack Scenario","type":"MIXED","count":30,"conf":(0.80,0.99),"proto":"MIXED","ports":[],"icon":"⚡"},
}

# ── Run one attack ────────────────────────────────────────────
def run_attack(key, delay=0.5):
    attack = ATTACKS[key]

    if attack["type"] == "MIXED":
        run_mixed_scenario(attack["count"], delay)
        return

    print(f"\n  {attack['icon']} Running: {attack['name']}")
    print(f"  Sending {attack['count']} events...\n")

    for i in range(attack["count"]):
        conf     = round(random.uniform(*attack["conf"]), 2)
        src_ip   = random_ip()
        src_port = random.randint(1024, 65535)

        # Choose port
        dst_port = TARGET_PORT if TARGET_PORT else random.choice(attack["ports"])

        write_alert(src_ip, TARGET_IP, src_port,
                    dst_port, attack["type"], conf, attack["proto"])

        print(f"    {attack['icon']} [{i+1:02}/{attack['count']}] "
              f"{attack['type']:<12} | "
              f"{src_ip}:{src_port} → {TARGET_IP}:{dst_port} | "
              f"conf:{conf:.2f}")

        time.sleep(delay)

    print(f"\n  ✔ Done — {attack['count']} events written")

# ── Mixed attack scenario ─────────────────────────────────────
def run_mixed_scenario(total, delay):
    print(f"\n  ⚡ Running Full Attack Scenario ({total} events)\n")

    attack_keys = ["1","3","5","7","9"]

    for i in range(total):
        key    = random.choice(attack_keys)
        attack = ATTACKS[key]

        conf   = round(random.uniform(*attack["conf"]), 2)
        src_ip = random_ip()
        sport  = random.randint(1024, 65535)
        dport  = TARGET_PORT if TARGET_PORT else random.choice(attack["ports"])

        write_alert(src_ip, TARGET_IP, sport,
                    dport, attack["type"], conf, attack["proto"])

        print(f"    {attack['icon']} [{i+1:02}/{total}] "
              f"{attack['type']:<12} | "
              f"{src_ip}:{sport} → {TARGET_IP}:{dport} | "
              f"conf:{conf:.2f}")

        time.sleep(delay)

    print(f"\n  ✔ Mixed scenario completed")

# ── Show stats ────────────────────────────────────────────────
def show_counts():
    if not os.path.exists(ALERT_LOG):
        print("No alerts yet.")
        return

    counts = {}
    total  = 0

    with open(ALERT_LOG, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = row.get("pred_label", "UNKNOWN")
            counts[t] = counts.get(t, 0) + 1
            total += 1

    print(f"\n📊 Total alerts: {total}")
    for t, c in counts.items():
        print(f"  {t:<12} : {c}")

# ── Clear logs ────────────────────────────────────────────────
def clear_alerts():
    with open(ALERT_LOG, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp","src_ip","dst_ip",
            "src_port","dst_port","proto",
            "pred_label","confidence"
        ])
    print("✔ Alerts cleared")

# ── Menu ──────────────────────────────────────────────────────
def print_menu():
    print("\n" + "="*50)
    print(" IoT IDS DEMO SIMULATOR ")
    print("="*50)

    for key, attack in ATTACKS.items():
        print(f"[{key}] {attack['icon']} {attack['name']} ({attack['count']})")

    print("[c] Clear logs")
    print("[s] Show stats")
    print("[q] Quit")

# ── Main loop ─────────────────────────────────────────────────
print("\nStarting IoT IDS Simulator...")
print(f"Target: {TARGET_IP}")
print(f"Dashboard: http://127.0.0.1:5000")

while True:
    print_menu()
    choice = input("\nEnter choice: ").strip().lower()

    if choice == "q":
        break
    elif choice == "c":
        clear_alerts()
    elif choice == "s":
        show_counts()
    elif choice in ATTACKS:
        try:
            delay = float(input("Delay (default 0.5): ") or 0.5)
        except:
            delay = 0.5
        run_attack(choice, delay)
    else:
        print("Invalid choice")