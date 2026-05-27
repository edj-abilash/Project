from flask import (Flask, render_template, jsonify,
                   request, redirect, url_for, flash, send_file)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user, UserMixin)
from functools import wraps
from datetime import datetime
import os, json, time, sys, subprocess, atexit
import importlib.util

# ── Global Config ─────────────────────────────
from config import TARGET_IP
# Base directory 
BASE_DIR = r"D:\Cyber_Project"

# Load database module
_spec = importlib.util.spec_from_file_location(
    "database",
    os.path.join(BASE_DIR, "database", "database.py")
)
db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db)

# ── Initialize database ───────────────────────────────────────
db.init_db()

# ── Flask app ─────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder = os.path.join(BASE_DIR, "templates"),
    static_folder   = os.path.join(BASE_DIR, "static")
)
app.config['SECRET_KEY'] = 'cyberpunk-ids-secret-key-2024'

# ── Flask-Login ───────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view             = 'login'
login_manager.login_message          = '⚠️ Access denied. Please authenticate.'
login_manager.login_message_category = 'warning'

# ── User class ────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, username, role='user'):
        self.id       = username
        self.username = username
        self.role     = role

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    u = db.get_user(user_id)
    if u:
        return User(u['username'], u['role'])
    return None

# ── Admin decorator ───────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            flash('⛔ Admin privileges required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════
#  BACKGROUND SERVICES
# ══════════════════════════════════════════════════════════════
_subprocesses = []

def start_background_services():
    python   = sys.executable
    services = [
        {
            "name":   "IDS Engine",
            "script": os.path.join(BASE_DIR, "ids_engine.py"),
            "log":    os.path.join(BASE_DIR, "logs", "ids_engine.log")
        }
    ]
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    for svc in services:
        if not os.path.exists(svc["script"]):
            print(f"⚠️  Skipping {svc['name']} — not found: {svc['script']}")
            continue
        try:
            log_file = open(svc["log"], "a")
            flags    = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            proc     = subprocess.Popen(
                [python, svc["script"]],
                stdout=log_file, stderr=log_file,
                cwd=BASE_DIR, creationflags=flags
            )
            _subprocesses.append((proc, svc["name"], log_file))
            print(f"✅ Started : {svc['name']} (PID: {proc.pid})")
            print(f"   Log     : {svc['log']}")
        except Exception as e:
            print(f"❌ Failed to start {svc['name']}: {e}")

def stop_background_services():
    print("\n🛑 Stopping background services...")
    for proc, name, log_file in _subprocesses:
        try:
            proc.terminate()
            proc.wait(timeout=5)
            log_file.close()
            print(f"   ✅ Stopped: {name}")
        except Exception as e:
            print(f"   ⚠️  Could not stop {name}: {e}")
            try:
                proc.kill()
            except:
                pass

def check_service_status():
    status = {}
    for proc, name, _ in _subprocesses:
        status[name] = "running" if proc.poll() is None else "stopped"
    return status

atexit.register(stop_background_services)

# ══════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════════════════════════
@app.errorhandler(500)
def err500(e):
    return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.errorhandler(404)
def err404(e):
    return jsonify({'error': 'Not found'}), 404

# ══════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return redirect(url_for('dashboard')
                    if current_user.is_authenticated
                    else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Single field — accepts username OR email
        identifier = request.form.get('identifier', '').strip()
        password   = request.form.get('password', '')

        if not identifier or not password:
            flash('⚠️ Enter your username or email and password', 'warning')
            return render_template('login.html')

        username = db.verify_by_email_or_username(identifier, password)
        if username:
            u = db.get_user(username)
            db.update_last_login(username)
            db.log_system('INFO', f'User logged in: {username}')
            login_user(User(u['username'], u['role']), remember=True)
            flash(f'🔓 Welcome back, {username}!', 'success')
            return redirect(request.args.get('next') or url_for('dashboard'))

        flash('❌ Invalid username/email or password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email',    '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            flash('⚠️ Please fill in all fields', 'warning')
            return render_template('register.html')
        if len(username) < 3:
            flash('⚠️ Username must be at least 3 characters', 'warning')
            return render_template('register.html')
        if len(username) > 20:
            flash('⚠️ Username must be 20 characters or less', 'warning')
            return render_template('register.html')
        if '@' not in email or '.' not in email:
            flash('⚠️ Enter a valid email address', 'warning')
            return render_template('register.html')
        if len(password) < 6:
            flash('⚠️ Password must be at least 6 characters', 'warning')
            return render_template('register.html')
        if password != confirm:
            flash('⚠️ Passwords do not match', 'warning')
            return render_template('register.html')
        if db.user_exists(username):
            flash('⚠️ Username already taken', 'warning')
            return render_template('register.html')
        if db.email_exists(email):
            flash('⚠️ Email already registered', 'warning')
            return render_template('register.html')

        if db.create_user(username, password, email=email):
            db.log_system('INFO', f'New user registered: {username} ({email})')
            flash('✅ Account created! Please login.', 'success')
            return redirect(url_for('login'))

        flash('❌ Failed to create account. Please try again.', 'danger')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    db.log_system('INFO', f'User logged out: {current_user.username}')
    logout_user()
    flash('👋 Logged out successfully', 'info')
    return redirect(url_for('login'))

# ══════════════════════════════════════════════════════════════
#  MAIN PAGES
# ══════════════════════════════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        stats = db.get_stats()
        return render_template('dashboard.html',
                               user           = current_user,
                               total          = stats['total'],
                               threats        = stats['threats'],
                               ddos           = stats['ddos'],
                               portscan       = stats['portscan'],
                               arpspoof       = stats['arpspoof'],
                               bruteforce     = stats['bruteforce'],
                               benign         = stats['benign'],
                               unique_sources = stats['unique_sources'],
                               unique_targets = stats['unique_targets'],
                               attack_counts  = stats['attack_counts'],
                               recent         = stats['recent'])
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return render_template('dashboard.html',
                               user=current_user,
                               total=0, threats=0, ddos=0,
                               portscan=0, arpspoof=0,
                               bruteforce=0, benign=0,
                               unique_sources=0, unique_targets=0,
                               attack_counts={}, recent=[])


@app.route('/alerts')
@login_required
def alerts_page():
    try:
        alerts = db.get_alerts(limit=500)
        return render_template('alerts.html',
                               alerts=alerts, user=current_user)
    except Exception as e:
        flash(f'Error loading alerts: {str(e)}', 'danger')
        return render_template('alerts.html',
                               alerts=[], user=current_user)


@app.route('/admin')
@admin_required
def admin_panel():
    try:
        return render_template('admin.html',
                               users = db.get_all_users(),
                               stats = db.get_stats(),
                               logs  = db.get_system_logs(20),
                               user  = current_user)
    except Exception as e:
        flash(f'Error loading admin panel: {str(e)}', 'danger')
        return render_template('admin.html',
                               users=[], stats={},
                               logs=[], user=current_user)


@app.route('/admin/delete_user/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    if username in ('admin', current_user.username):
        flash('⛔ Cannot delete this account', 'danger')
        return redirect(url_for('admin_panel'))
    db.delete_user(username)
    db.log_system('WARN', f'User deleted: {username}')
    flash(f'🗑️ User {username} deleted', 'success')
    return redirect(url_for('admin_panel'))

# ══════════════════════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════════════════════
@app.route('/api/latest')
@login_required
def api_latest():
    try:
        stats = db.get_stats()
        return jsonify({
            'success':        True,
            'total':          stats['total'],
            'threats':        stats['threats'],
            'ddos':           stats['ddos'],
            'portscan':       stats['portscan'],
            'arpspoof':       stats['arpspoof'],
            'bruteforce':     stats['bruteforce'],
            'benign':         stats['benign'],
            'unique_sources': stats['unique_sources'],
            'unique_targets': stats['unique_targets'],
            'attack_counts':  stats['attack_counts'],
            'recent':         stats['recent'][:10],
            'timestamp':      datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False, 'error': str(e),
            'total': 0, 'threats': 0, 'ddos': 0,
            'portscan': 0, 'arpspoof': 0, 'bruteforce': 0,
            'benign': 0, 'unique_sources': 0, 'unique_targets': 0,
            'attack_counts': {}, 'recent': []
        }), 500


@app.route('/system_status')
@login_required
def system_status():
    try:
        svc_status  = check_service_status()
        ids_running = svc_status.get('IDS Engine') == 'running'
        if not ids_running:
            recent = db.get_alerts(limit=1)
            if recent:
                try:
                    last_ts = datetime.strptime(
                        recent[0]['timestamp'], '%Y-%m-%d %H:%M:%S')
                    ids_running = (datetime.now() - last_ts).seconds < 30
                except:
                    pass
        return jsonify({
            'success':       True,
            'ids_engine':    'running' if ids_running else 'standby',
            'web_interface': 'active',
            'services':      svc_status,
            'timestamp':     datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({
            'success': False, 'error': str(e),
            'ids_engine': 'unknown', 'web_interface': 'active'
        }), 500


@app.route('/api/health')
def health_check():
    return jsonify({
        'status':    'healthy',
        'database':  db.DB_PATH,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/db_info')
@login_required
def api_db_info():
    try:
        conn   = db.get_conn()
        c      = conn.cursor()
        tables = c.execute(
            'SELECT name FROM sqlite_master WHERE type="table"'
        ).fetchall()
        info = {}
        for t in tables:
            name       = t['name']
            count      = c.execute(
                f"SELECT COUNT(*) FROM {name}"
            ).fetchone()[0]
            info[name] = count
        conn.close()
        return jsonify({
            'success': True,
            'db_path': db.DB_PATH,
            'db_size': os.path.getsize(db.DB_PATH),
            'tables':  info
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Simulator API ─────────────────────────────────────────────
@app.route('/api/sim/write', methods=['POST'])
@login_required
def sim_write():
    try:
        data = request.get_json()
        db.insert_alert(
            src_ip      = data.get('src_ip',     '192.168.1.1'),
            dst_ip      = data.get('dst_ip',     '10.0.0.1'),
            src_port    = data.get('src_port',   12345),
            dst_port    = data.get('dst_port',   80),
            protocol    = data.get('proto',      'TCP'),
            attack_type = data.get('pred_label', 'UNKNOWN'),
            confidence  = data.get('confidence', 0.9),
            source      = 'Simulator'
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sim/clear', methods=['POST'])
@login_required
def sim_clear():
    try:
        db.clear_alerts()
        db.log_system('INFO', 'Alerts cleared by simulator')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Export route ──────────────────────────────────────────────
@app.route('/api/export')
@login_required
def export_report():
    try:
        import importlib.util as ilu
        spec = ilu.spec_from_file_location(
            "export_report",
            os.path.join(BASE_DIR, "export_report.py")
        )
        exp = ilu.module_from_spec(spec)
        spec.loader.exec_module(exp)

        filepath = exp.generate_report(
            exported_by=current_user.username
        )
        filename = os.path.basename(filepath)
        db.log_system('INFO',
            f'Report exported by {current_user.username}: {filename}')

        return send_file(
            filepath,
            as_attachment = True,
            download_name = filename,
            mimetype      = ('application/vnd.openxmlformats-'
                             'officedocument.spreadsheetml.sheet')
        )
    except Exception as e:
        db.log_system('ERROR', f'Export failed: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  🛡  Cyberpunk IoT IDS System")
    print("="*55)
    print(f"  🗄  Database : {db.DB_PATH}")
    print(f"  🔗 URL       : http://localhost:5000")
    print(f"  👤 Login     : admin / admin123")
    print("="*55)

    print("\n🚀 Starting background services...")
    start_background_services()

    print("\n🌐 Starting web dashboard...")
    print("🔴 Press Ctrl+C to stop everything\n")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)