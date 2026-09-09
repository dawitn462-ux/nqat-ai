import sqlite3

conn = sqlite3.connect('nkat_dev.db')
c = conn.cursor()

tables = ['findings', 'subdomains', 'remediations', 'feedback_labels', 'audit_logs', 'scans']
for t in tables:
    try:
        c.execute(f"DELETE FROM {t}")
        c.execute(f"DELETE FROM sqlite_sequence WHERE name='{t}'")
    except Exception as e:
        print(f"Error on table {t}: {e}")

conn.commit()
print("Reset completed successfully.")
print("SQLite Sequence table:")
for row in c.execute("SELECT * FROM sqlite_sequence").fetchall():
    print(row)

print("Target domains table:")
for row in c.execute("SELECT id, domain, owner, status FROM domain_targets").fetchall():
    print(row)

conn.close()
