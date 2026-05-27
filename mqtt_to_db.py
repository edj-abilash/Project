import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

import paho.mqtt.client as mqtt
import sqlite3
import json
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────
BROKER_IP = " 172.20.10.2"    # your PC IP
TOPIC     = "Message"
DB_PATH   = r"D:\Cyber_Project\database\ids.db"

# ── Write to dashboard database ───────────────────────────────
def write_to_db(src_ip, dst_ip, src_port,
                dst_port, protocol,
                attack_type, confidence):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO alerts
            (timestamp, src_ip, dst_ip,
             src_port, dst_port, protocol,
             attack_type, confidence, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            str(src_ip),
            str(dst_ip),
            int(src_port),
            int(dst_port),
            str(protocol),
            str(attack_type),
            float(confidence),
            "Arduino_MQTT"
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Error: {e}")
        return False

# ── When MQTT message arrives ─────────────────────────────────
def on_message(client, userdata, msg):
    try:
        raw = msg.payload.decode("utf-8").strip()

        # Skip retained ONLINE message
        if raw == "ONLINE" or raw == "":
            return

        print(f"\nReceived: {raw}")

        # Parse JSON from Arduino
        data = json.loads(raw)

        # Extract fields from Arduino payload
        # handles both old format and new format
        src_ip      = data.get("src_ip",
                      data.get("node", "ESP32"))
        dst_ip      = data.get("dst_ip",      BROKER_IP)
        src_port    = data.get("src_port",    1883)
        dst_port    = data.get("dst_port",    1883)
        protocol    = data.get("protocol",    "MQTT")
        attack_type = data.get("attack_type", "BENIGN")
        confidence  = data.get("confidence",  0.92)

        # Also show sensor data if present
        temp = data.get("temp", "?")
        hum  = data.get("hum",  "?")
        node = data.get("node", "ESP32")
        count= data.get("count", 0)

        # Write to database → appears on dashboard
        ok = write_to_db(
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            protocol    = protocol,
            attack_type = attack_type,
            confidence  = confidence
        )

        # Print status
        status = "SAVED" if ok else "FAILED"
        print(f"[{status}] {datetime.now().strftime('%H:%M:%S')} "
              f"| Node: {node} #{count} "
              f"| {src_ip} -> {dst_ip}:{dst_port} "
              f"| {protocol} | {attack_type} "
              f"| conf={confidence} "
              f"| temp={temp} hum={hum}")

    except json.JSONDecodeError:
        print(f"Non-JSON received: {msg.payload}")
    except Exception as e:
        print(f"Error: {e}")

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to broker {BROKER_IP}:1883")
        client.subscribe(TOPIC)
        print(f"Subscribed to: {TOPIC}")
        print(f"Waiting for Arduino messages...")
        print(f"Dashboard: http://localhost:5000")
        print("-" * 50)
    else:
        print(f"Connection failed. Code: {rc}")

def on_disconnect(client, userdata, rc):
    print(f"Disconnected. Reconnecting...")

# ── Start bridge ──────────────────────────────────────────────
print("=" * 50)
print("  MQTT TO DASHBOARD BRIDGE")
print("=" * 50)
print(f"  Broker  : {BROKER_IP}:1883")
print(f"  Topic   : {TOPIC}")
print(f"  DB      : {DB_PATH}")
print("=" * 50)

bridge = mqtt.Client(client_id="mqtt-dashboard-bridge")
bridge.on_connect    = on_connect
bridge.on_message    = on_message
bridge.on_disconnect = on_disconnect

try:
    bridge.connect(BROKER_IP, 1883, 60)
    bridge.loop_forever()
except KeyboardInterrupt:
    print("\nStopped by user")
except Exception as e:
    print(f"Error: {e}")
    print("Make sure mosquitto is running: mosquitto -v")