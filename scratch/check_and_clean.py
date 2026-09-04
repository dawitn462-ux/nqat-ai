import sqlite3
import os

db_path = "nkat_dev.db"

print("--- NKAT AI PLATFORM DIAGNOSTICS & CLEANUP ---")

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check scan table columns
    cursor.execute("PRAGMA table_info(scans)")
    cols = [r[1] for r in cursor.fetchall()]
    print(f"[+] Scan table columns: {cols}")

    target_col = "target" if "target" in cols else "target_url"
    
    # 1. Check all scan statuses
    cursor.execute("SELECT status, COUNT(*) FROM scans GROUP BY status")
    statuses = cursor.fetchall()
    print("\n[+] Scan Status Breakdown:")
    for st, cnt in statuses:
        print(f"    - {st}: {cnt}")
        
    # 2. Find any stuck scans
    cursor.execute(f"SELECT id, {target_col}, status, created_at FROM scans WHERE status IN ('IN_PROGRESS', 'RUNNING', 'PENDING', 'STARTING')")
    stuck_scans = cursor.fetchall()
    
    if stuck_scans:
        print(f"\n[!] Found {len(stuck_scans)} stuck scan(s):")
        for scan in stuck_scans:
            print(f"    - Scan #{scan[0]} | Target: {scan[1]} | Status: {scan[2]} | Created: {scan[3]}")
            
        # Update stuck scans to FAILED
        cursor.execute("UPDATE scans SET status = 'FAILED' WHERE status IN ('IN_PROGRESS', 'RUNNING', 'PENDING', 'STARTING')")
        conn.commit()
        print(f"\n[+] SUCCESS: Cleaned up {len(stuck_scans)} stuck scan(s) -> updated status to 'FAILED'.")
    else:
        print("\n[+] Zero stuck scan records in database.")
        
    conn.close()
else:
    print(f"[!] Database file '{db_path}' not found.")

print("\n[+] Cleanup complete!")
