import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
from scapy.all import sniff, IP, TCP, UDP, ARP
import joblib, numpy as np
import collections, time, os, threading
from datetime import datetime
import importlib.util
import pandas as pd

# ── Load database module ──────────────────────────────────────
_spec = importlib.util.spec_from_file_location(
    "database",
    r"D:\Cyber_Project\database\database.py"
)
db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db)
db.init_db()

# ── Configuration ─────────────────────────────────────────────
MODEL_PATH           = r"D:\Cyber_Project\models\ids_pipeline.pkl"
FLOW_TIMEOUT         = 5      # seconds before flow is classified
CONFIDENCE_THRESHOLD = 0.70   # minimum confidence to raise alert
MIN_PACKETS          = 2      # minimum packets per flow

os.makedirs("results", exist_ok=True)
os.makedirs("logs",    exist_ok=True)

# ── Load trained pipeline ─────────────────────────────────────
# BUG 1 FIXED — load pipeline FIRST, then print verification
print("⏳ Initializing Cyberpunk IDS Engine...")
print("🔮 Loading neural pathways...")

try:
    pipeline     = joblib.load(MODEL_PATH)
    model        = pipeline["model"]
    scaler       = pipeline["scaler"]
    feature_cols = pipeline["feature_cols"]
    label_map    = pipeline["label_map"]

    # ── Model verification AFTER loading ─────────────────────
    print("\n" + "="*55)
    print("  MODEL VERIFICATION")
    print("="*55)
    print(f"  Accuracy      : {pipeline.get('accuracy', 'N/A')}")
    print(f"  Trees         : {model.n_estimators}")
    print(f"  Features      : {len(feature_cols)}")
    print(f"  Feature list  : {feature_cols}")
    print(f"  Classes       : {list(label_map.values())}")
    cw = getattr(model, 'class_weight', None)
    print(f"  Class weights : {'balanced' if cw else 'none'}")
    print("="*55 + "\n")

    print(f"✅ Model loaded: Random_Forest")
    print(f"🎯 Classes: {', '.join(label_map.values())}")

except Exception as e:
    print(f"❌ Failed to load model: {e}")
    print("⚠️  Running in simulation mode — predictions will be random")
    model        = None
    scaler       = None
    feature_cols = []
    label_map    = {0:"BENIGN", 1:"DDoS", 2:"Recon",
                    3:"Spoofing", 4:"BruteForce"}

# ── Flow buffer ───────────────────────────────────────────────
flow_buffer        = collections.defaultdict(list)
flow_last_seen     = {}
flow_packet_counts = collections.defaultdict(int)

stats = {
    "total_packets": 0,
    "total_flows":   0,
    "alerts":        0,
    "start_time":    datetime.now()
}

# ── Flow key extractor ────────────────────────────────────────
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    proto    = "TCP"   if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    return (pkt[IP].src, pkt[IP].dst, src_port, dst_port, proto)

# ── Packet handler ────────────────────────────────────────────
def packet_handler(pkt):
    stats["total_packets"] += 1
    key = get_flow_key(pkt)
    if key:
        flow_buffer[key].append(pkt)
        flow_last_seen[key]     = time.time()
        flow_packet_counts[key] += 1

# ── BUG 2 FIXED — extract the SAME features model was trained on
def extract_features_from_flow(key, packets):
    """
    Extract features matching the CICIoT2023 training feature names.
    Your feature_cols list is loaded from models/feature_cols.pkl —
    this function computes ALL possible features and then
    classify_flow picks only the ones in feature_cols.
    """
    src_ip, dst_ip, src_port, dst_port, proto = key

    times    = [float(p.time) for p in packets]
    lengths  = [len(p) for p in packets]
    duration = max(times[-1] - times[0], 1e-6)
    n_pkts   = len(packets)
    n_bytes  = sum(lengths)

    # Forward / backward split (even = fwd, odd = bwd)
    fwd      = packets[::2]
    bwd      = packets[1::2]
    fwd_lens = [len(p) for p in fwd] or [0]
    bwd_lens = [len(p) for p in bwd] or [0]

    # Inter-arrival times
    iats     = np.diff(times).tolist() if len(times) > 1 else [0.0]

    # TCP flag counts
    syn = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)
    ack = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x10)
    psh = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x08)
    rst = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x04)
    fin = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x01)
    urg = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x20)
    ece = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x40)
    cwr = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x80)

    # Protocol counts
    tcp_count  = sum(1 for p in packets if TCP in p)
    udp_count  = sum(1 for p in packets if UDP in p)
    arp_count  = sum(1 for p in packets if ARP in p)
    icmp_count = sum(1 for p in packets if p.haslayer('ICMP'))

    # Rates
    pkt_rate   = n_pkts   / duration
    byte_rate  = n_bytes  / duration
    srate      = len(fwd) / duration
    drate      = len(bwd) / duration

    feats = {
        # ── Core flow features (match CICIoT2023 column names) ──
        "flow_duration":        duration,
        "Header_Length":        sum(p[IP].ihl * 4 if IP in p else 20 for p in packets),
        "Duration":             duration,
        "Rate":                 pkt_rate,
        "Srate":                srate,
        "Drate":                drate,

        # TCP flags
        "fin_flag_number":      fin,
        "syn_flag_number":      syn,
        "rst_flag_number":      rst,
        "psh_flag_number":      psh,
        "ack_flag_number":      ack,
        "ece_flag_number":      ece,
        "cwr_flag_number":      cwr,
        "ack_count":            ack,
        "syn_count":            syn,
        "fin_count":            fin,
        "urg_count":            urg,
        "rst_count":            rst,

        # Protocol indicators
        "HTTP":                 1 if any(TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80) for p in packets) else 0,
        "HTTPS":                1 if any(TCP in p and (p[TCP].dport == 443 or p[TCP].sport == 443) for p in packets) else 0,
        "DNS":                  1 if any(UDP in p and (p[UDP].dport == 53 or p[UDP].sport == 53) for p in packets) else 0,
        "Telnet":               1 if any(TCP in p and p[TCP].dport == 23 for p in packets) else 0,
        "SMTP":                 1 if any(TCP in p and p[TCP].dport == 25 for p in packets) else 0,
        "SSH":                  1 if any(TCP in p and p[TCP].dport == 22 for p in packets) else 0,
        "IRC":                  1 if any(TCP in p and p[TCP].dport == 6667 for p in packets) else 0,
        "TCP":                  tcp_count,
        "UDP":                  udp_count,
        "DHCP":                 1 if any(UDP in p and p[UDP].dport == 67 for p in packets) else 0,
        "ARP":                  arp_count,
        "ICMP":                 icmp_count,
        "IPv":                  n_pkts,
        "LLC":                  0,

        # Statistical features
        "Tot sum":              n_bytes,
        "Min":                  min(lengths),
        "Max":                  max(lengths),
        "AVG":                  np.mean(lengths),
        "Std":                  np.std(lengths),
        "Tot size":             n_bytes,
        "IAT":                  np.mean(iats),
        "Number":               n_pkts,
        "Magnitue":             np.sqrt(np.mean(np.array(lengths)**2)),
        "Radius":               np.sqrt(np.var(fwd_lens) + np.var(bwd_lens)),
        "Covariance":           np.cov(fwd_lens, bwd_lens)[0][1] if len(fwd_lens) > 1 and len(bwd_lens) > 1 else 0.0,
        "Variance":             np.var(lengths),
        "Weight":               n_pkts / duration,

        # ── Engineered features (if you added them in retraining) ──
        "dst_port_entropy":     drate / (pkt_rate + 1e-6),
        "scan_indicator":       1 if syn > ack else 0,
        "low_volume_flag":      1 if n_bytes < 500 else 0,
        "icmp_dominance":       icmp_count / (n_pkts + 1e-6),
        "udp_tcp_ratio":        udp_count  / (tcp_count + 1e-6),
        "arp_dominance":        arp_count  / (n_pkts + 1e-6),
        "small_pkt_flag":       1 if min(lengths) < 64 else 0,
        "no_tcp_flag":          1 if tcp_count == 0 else 0,
        "arp_no_tcp":           (arp_count / (n_pkts + 1e-6)) * (1 if tcp_count == 0 else 0),
        "syn_ack_imbalance":    abs(syn - ack) / (n_pkts + 1e-6),
        "flow_symmetry":        srate / (drate + 1e-6),
        "flag_density":         (syn + ack + fin) / (n_pkts + 1e-6),
        "pkt_size_cv":          np.std(lengths) / (np.mean(lengths) + 1e-6),
    }

    return feats

# ── Alert logger ──────────────────────────────────────────────
def log_alert(key, pred_label, confidence, packet_count):
    src_ip, dst_ip, src_port, dst_port, proto = key
    db.insert_alert(
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        src_port     = src_port,
        dst_port     = dst_port,
        protocol     = proto,
        attack_type  = pred_label,
        confidence   = confidence,
        source       = "IDS Engine",
        packet_count = packet_count
    )
    stats["alerts"] += 1

# ── Flow classifier ───────────────────────────────────────────
def classify_flow(key, packets):
    if not model or not scaler:
        # Simulation mode
        import random
        pred_label = random.choice(["BENIGN", "DDoS", "Recon", "Spoofing", "BruteForce"])
        confidence = random.uniform(0.7, 0.99)
    else:
        try:
            # Extract ALL features then pick only trained ones
            all_feats = extract_features_from_flow(key, packets)

            # Build feature vector in exact same order as training
            x_vec    = [float(all_feats.get(col, 0.0)) for col in feature_cols]
            x_df     = pd.DataFrame([x_vec], columns=feature_cols)
            x_scaled = scaler.transform(x_df)

            pred_id    = int(model.predict(x_scaled)[0])
            pred_label = label_map.get(pred_id, "UNKNOWN")

            confidence = 0.0
            if hasattr(model, "predict_proba"):
                proba      = model.predict_proba(x_scaled)[0]
                confidence = float(np.max(proba))

        except Exception as e:
            print(f"⚠️  Classification error: {e}")
            return

    packet_count = len(packets)

    if pred_label != "BENIGN" and confidence >= CONFIDENCE_THRESHOLD:
        log_alert(key, pred_label, confidence, packet_count)
        print(f"🚨 [{datetime.now().strftime('%H:%M:%S')}] ALERT: {pred_label} ({confidence:.2%})")
        print(f"   └─ {key[0]}:{key[2]} → {key[1]}:{key[3]} [{key[4]}] | Pkts: {packet_count}")
    elif pred_label == "BENIGN":
        log_alert(key, pred_label, confidence, packet_count)

# ── Background: classify timed-out flows ──────────────────────
def flow_classifier():
    while True:
        time.sleep(1)
        now     = time.time()
        expired = [k for k, t in list(flow_last_seen.items())
                   if now - t > FLOW_TIMEOUT]
        for key in expired:
            packets = flow_buffer.pop(key, [])
            flow_last_seen.pop(key, None)
            flow_packet_counts.pop(key, None)
            if len(packets) >= MIN_PACKETS:
                classify_flow(key, packets)
                stats["total_flows"] += 1

# ── Background: status printer ────────────────────────────────
def print_status():
    while True:
        time.sleep(10)
        uptime = datetime.now() - stats["start_time"]
        print(f"\n📊 [{datetime.now().strftime('%H:%M:%S')}] STATUS")
        print(f"   Packets: {stats['total_packets']:,} | "
              f"Flows: {stats['total_flows']:,} | "
              f"Alerts: {stats['alerts']}")
        print(f"   Uptime : {uptime}")
        print(f"   Active flows: {len(flow_buffer)}\n")

# ── Start background threads ──────────────────────────────────
threading.Thread(target=flow_classifier, daemon=True).start()
threading.Thread(target=print_status,    daemon=True).start()

# ── Main entry ────────────────────────────────────────────────
print("\n" + "="*60)
print("🛡️  CYBERPUNK IoT IDS ENGINE v2.0")
print("="*60)
print("\n🌐 Monitoring network interface: Wi-Fi")
print(f"🗄  Database : D:\\Cyber_Project\\database\\ids.db")
print(f"⚡ Threshold : {CONFIDENCE_THRESHOLD:.0%} confidence")
print(f"⏱️  Flow timeout : {FLOW_TIMEOUT}s")
print(f"🌿 Features  : {len(feature_cols)} loaded from model")
print("\n🔴 Press Ctrl+C to stop\n")

try:
    sniff(
        iface = "Wi-Fi",
        prn   = packet_handler,
        store = False
    )
except KeyboardInterrupt:
    print("\n\n🛑 IDS Engine stopped by user")
    print(f"📈 Final: {stats['total_packets']:,} packets | "
          f"{stats['total_flows']:,} flows | "
          f"{stats['alerts']} alerts")
except Exception as e:
    print(f"\n❌ Error: {e}")
    print("⚠️  Make sure Npcap is installed and run as Administrator")