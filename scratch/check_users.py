import sys
import os
sys.path.insert(0, os.path.abspath("."))

from backend.database import SessionLocal
from backend.models import User

db = SessionLocal()
users = db.query(User).all()
print("CURRENT USERS IN DATABASE:")
for u in users:
    print(f"ID #{u.id}: username='{u.username}', email='{u.email}', role='{u.role}', verified={u.is_email_verified}, provider='{u.auth_provider}'")
db.close()
