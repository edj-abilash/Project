import importlib.util

spec = importlib.util.spec_from_file_location(
    'database',
    r'D:\Cyber_Project\database\database.py'
)
db = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db)

print("\n=== DATABASE INFO ===")
db.db_info()

print("=== ALL USERS ===")
users = db.get_all_users()
if not users:
    print("  No users found")
else:
    for u in users:
        print("  ID        :", u.get('id'))
        print("  Username  :", u.get('username'))
        print("  Role      :", u.get('role'))
        print("  Created   :", u.get('created_at'))
        print("  Last Login:", u.get('last_login'))
        print("  -----------")

print("\n=== ALL ALERTS ===")
alerts = db.get_alerts(limit=5)
if not alerts:
    print("  No alerts yet")
else:
    for a in alerts:
        print("  ID         :", a.get('id'))
        print("  Timestamp  :", a.get('timestamp'))
        print("  Attack Type:", a.get('attack_type'))
        print("  Source IP  :", a.get('src_ip'))
        print("  Confidence :", a.get('confidence'))
        print("  -----------")

print("\n=== STATS ===")
stats = db.get_stats()
print("  Total alerts :", stats.get('total'))
print("  Threats      :", stats.get('threats'))
print("  Benign       :", stats.get('benign'))
print("  Attack counts:", stats.get('attack_counts'))
