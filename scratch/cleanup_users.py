import sys
import os
sys.path.insert(0, os.path.abspath("."))

from backend.database import SessionLocal
from backend.models import User

db = SessionLocal()

# We keep 'admin' and real manually registered accounts: 'dave', 'gch', 'alemu_abebe'
keep_usernames = ['admin', 'dave', 'gch', 'alemu_abebe']

users = db.query(User).all()
deleted_count = 0
kept_count = 0

for u in users:
    if u.username in keep_usernames or not (u.username.startswith('test_') or u.username.startswith('google_user_test')):
        kept_count += 1
        print(f"[KEEP] ID #{u.id}: username='{u.username}', email='{u.email}', role='{u.role}'")
    else:
        print(f"[DELETE] ID #{u.id}: username='{u.username}', email='{u.email}'")
        db.delete(u)
        deleted_count += 1

db.commit()
print(f"\n[+] Cleanup Finished! Kept {kept_count} real users, deleted {deleted_count} dummy/test accounts.")
db.close()
