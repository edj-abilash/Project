# ============================================================
# FILE LOCATION: D:\Cyber_Project\database\database.py
# PURPOSE      : Central SQLite database for IoT IDS Project
# TABLES       : users, alerts, system_log
# USED BY      : app.py, ids_engine.py, simulate_attack.py
# ============================================================
import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
import sqlite3
import os
import sys
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# ══════════════════════════════════════════════════════════════
#  DATABASE LOCATION
# ══════════════════════════════════════════════════════════════
BASE_DIR = r"D:\Cyber_Project"
DB_DIR   = os.path.join(BASE_DIR, "database")
DB_PATH  = os.path.join(DB_DIR,   "ids.db")

os.makedirs(DB_DIR, exist_ok=True)

print(f"[DB] Location : {DB_PATH}")

# ══════════════════════════════════════════════════════════════
#  CONNECTION
# ══════════════════════════════════════════════════════════════
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

# ══════════════════════════════════════════════════════════════
#  CREATE TABLES
# ══════════════════════════════════════════════════════════════
def init_db():
    conn = get_conn()
    c    = conn.cursor()

    # ── Table 1: users ────────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            email         TEXT    UNIQUE NOT NULL DEFAULT '',
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT "user",
            created_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT
        )
    ''')

    # Add email column to existing databases that don't have it
    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
        conn.commit()
        print("[DB] Email column added to users table")
    except Exception:
        pass  # Column already exists — ignore

    # ── Table 2: alerts ───────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT    NOT NULL,
            src_ip       TEXT,
            dst_ip       TEXT,
            src_port     INTEGER DEFAULT 0,
            dst_port     INTEGER DEFAULT 0,
            protocol     TEXT    DEFAULT "TCP",
            attack_type  TEXT    DEFAULT "UNKNOWN",
            confidence   REAL    DEFAULT 0.0,
            source       TEXT    DEFAULT "IDS Engine",
            packet_count INTEGER DEFAULT 0
        )
    ''')

    # ── Table 3: system_log ───────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    DEFAULT CURRENT_TIMESTAMP,
            level     TEXT    DEFAULT "INFO",
            message   TEXT
        )
    ''')

    # ── Indexes ───────────────────────────────────────────────
    c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts(src_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_confidence  ON alerts(confidence DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_syslog_timestamp   ON system_log(timestamp DESC)')

    # ── Default admin user ────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', (
            'admin',
            'admin@iotids.local',
            generate_password_hash('admin123'),
            'admin'
        ))
        print("[DB] ✅ Default admin created → admin / admin123")

    conn.commit()
    conn.close()
    print(f"[DB] All tables ready -> {DB_PATH}")

# ══════════════════════════════════════════════════════════════
#  USER METHODS
# ══════════════════════════════════════════════════════════════

def get_user(username):
    """Returns user dict by username or None if not found."""
    conn = get_conn()
    row  = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email):
    """Returns user dict by email or None if not found."""
    conn = get_conn()
    row  = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email.strip().lower(),)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_password(username, password):
    """Returns True if username exists and password matches."""
    user = get_user(username)
    if not user:
        return False
    return check_password_hash(user['password_hash'], password)


def verify_by_email_or_username(identifier, password):
    """
    Login with either username OR email — one field handles both.
    Returns the username string if valid, None if not.
    """
    try:
        conn = get_conn()
        c    = conn.cursor()
        row  = c.execute('''
            SELECT * FROM users
            WHERE username = ? OR email = ?
        ''', (
            identifier.strip(),
            identifier.strip().lower()
        )).fetchone()
        conn.close()
        if row and check_password_hash(
                row['password_hash'], password):
            return row['username']
        return None
    except Exception as e:
        print(f"[DB] verify_by_email_or_username error: {e}")
        return None


def user_exists(username):
    """Returns True if username already exists."""
    return get_user(username) is not None


def email_exists(email):
    """Returns True if email already registered."""
    try:
        conn = get_conn()
        row  = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email.strip().lower(),)
        ).fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        print(f"[DB] email_exists error: {e}")
        return False


def create_user(username, password, email='', role='user'):
    """
    Creates a new user with hashed password and email.
    Returns True on success, False on failure.
    """
    if user_exists(username):
        return False
    try:
        conn = get_conn()
        conn.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', (
            username,
            email.strip().lower(),
            generate_password_hash(password),
            role
        ))
        conn.commit()
        conn.close()
        print(f"[DB] ✅ User created: {username} ({email}) [{role}]")
        return True
    except Exception as e:
        print(f"[DB] ❌ Error creating user: {e}")
        return False


def update_last_login(username):
    """Updates last_login timestamp after successful login."""
    conn = get_conn()
    conn.execute('''
        UPDATE users SET last_login = ? WHERE username = ?
    ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
    conn.commit()
    conn.close()


def get_all_users():
    """Returns list of all users excluding password_hash."""
    conn = get_conn()
    rows = conn.execute('''
        SELECT id, username, email, role, created_at, last_login
        FROM users
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_user(username):
    """Deletes a user by username."""
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"[DB] 🗑 User deleted: {username}")


def change_password(username, new_password):
    """Updates password hash for a user."""
    conn = get_conn()
    conn.execute('''
        UPDATE users SET password_hash = ? WHERE username = ?
    ''', (generate_password_hash(new_password), username))
    conn.commit()
    conn.close()
    return True

# ══════════════════════════════════════════════════════════════
#  ALERT METHODS
# ══════════════════════════════════════════════════════════════

def insert_alert(src_ip, dst_ip, src_port, dst_port,
                 protocol, attack_type, confidence,
                 source="IDS Engine", packet_count=0):
    try:
        conn = get_conn()
        conn.execute('''
            INSERT INTO alerts
                (timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, attack_type, confidence,
                 source, packet_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            str(src_ip), str(dst_ip),
            int(src_port), int(dst_port),
            str(protocol), str(attack_type),
            float(confidence), str(source), int(packet_count)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] ❌ Error inserting alert: {e}")


def get_alerts(limit=100, attack_type=None, src_ip=None):
    conn  = get_conn()
    query = "SELECT * FROM alerts"
    args  = []
    filters = []
    if attack_type:
        filters.append("attack_type = ?")
        args.append(attack_type)
    if src_ip:
        filters.append("src_ip = ?")
        args.append(src_ip)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    rows = conn.execute(query, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_conn()
    c    = conn.cursor()

    total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    type_counts = {}
    rows = c.execute('''
        SELECT attack_type, COUNT(*) as cnt
        FROM alerts GROUP BY attack_type ORDER BY cnt DESC
    ''').fetchall()
    for row in rows:
        type_counts[row['attack_type']] = row['cnt']

    unique_sources = c.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM alerts"
    ).fetchone()[0]
    unique_targets = c.execute(
        "SELECT COUNT(DISTINCT dst_ip) FROM alerts"
    ).fetchone()[0]

    recent_rows = c.execute('''
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 15
    ''').fetchall()
    recent = [dict(r) for r in recent_rows]

    conn.close()
    benign = type_counts.get('BENIGN', 0)

    return {
        'total':          total,
        'attack_counts':  type_counts,
        'ddos':           type_counts.get('DDoS',       0),
        'portscan':       type_counts.get('Recon',      0),
        'arpspoof':       type_counts.get('Spoofing',   0),
        'bruteforce':     type_counts.get('BruteForce', 0),
        'benign':         benign,
        'threats':        total - benign,
        'unique_sources': unique_sources,
        'unique_targets': unique_targets,
        'recent':         recent
    }


def clear_alerts():
    conn = get_conn()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    print("[DB] 🗑 All alerts cleared")


def get_alert_by_id(alert_id):
    conn = get_conn()
    row  = conn.execute(
        "SELECT * FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_top_attackers(limit=10):
    conn = get_conn()
    rows = conn.execute('''
        SELECT src_ip, COUNT(*) as count FROM alerts
        WHERE attack_type != "BENIGN"
        GROUP BY src_ip ORDER BY count DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_by_hour():
    conn = get_conn()
    rows = conn.execute('''
        SELECT strftime("%H:00", timestamp) as hour,
               COUNT(*) as count
        FROM alerts GROUP BY hour ORDER BY hour
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════
#  SYSTEM LOG METHODS
# ══════════════════════════════════════════════════════════════

def log_system(level, message):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO system_log (level, message) VALUES (?, ?)",
            (level.upper(), message)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] ❌ Error writing system log: {e}")


def get_system_logs(limit=50):
    conn = get_conn()
    rows = conn.execute('''
        SELECT * FROM system_log
        ORDER BY timestamp DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_system_logs():
    conn = get_conn()
    conn.execute("DELETE FROM system_log")
    conn.commit()
    conn.close()

# ══════════════════════════════════════════════════════════════
#  DATABASE INFO
# ══════════════════════════════════════════════════════════════

def db_info():
    if not os.path.exists(DB_PATH):
        print(f"[DB] ❌ Database not found at {DB_PATH}")
        return
    conn   = get_conn()
    c      = conn.cursor()
    tables = c.execute('''
        SELECT name FROM sqlite_master
        WHERE type = "table" ORDER BY name
    ''').fetchall()
    size = os.path.getsize(DB_PATH)
    print(f"\n{'═'*50}")
    print(f"  📁 FILE    : {DB_PATH}")
    print(f"  💾 SIZE    : {size:,} bytes ({size/1024:.1f} KB)")
    print(f"{'═'*50}")
    print(f"  {'TABLE':<24} {'ROWS':>8}")
    print(f"  {'─'*32}")
    for t in tables:
        name  = t['name']
        count = c.execute(
            f"SELECT COUNT(*) FROM {name}"
        ).fetchone()[0]
        print(f"  {name:<24} {count:>8,}")
    print(f"{'═'*50}\n")
    conn.close()


def run_query(sql, args=()):
    conn = get_conn()
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════
#  RUN DIRECTLY TO TEST
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "═"*50)
    print("  IoT IDS — Database Initialization")
    print("═"*50)
    init_db()
    db_info()
    print("  Testing alert insert...")
    insert_alert(
        src_ip="192.168.1.99", dst_ip="192.168.29.7",
        src_port=54321, dst_port=80, protocol="TCP",
        attack_type="DDoS", confidence=0.97,
        source="Test", packet_count=10
    )
    print("  ✅ Test alert inserted")
    db_info()
    stats = get_stats()
    print(f"  Stats: {stats['total']} total | "
          f"{stats['threats']} threats | "
          f"{stats['benign']} benign")
    print("\n  ✅ Database test complete\n")