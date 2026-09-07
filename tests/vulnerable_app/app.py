"""
Isolated Deliberately Vulnerable Test Application — Target for NKAT AI Remediation Verification
-----------------------------------------------------------------------------------------------
Contains intentional SQL Injection vulnerability on /api/v1/user endpoint for end-to-end SAST/DAST rescan testing.
"""

import sqlite3
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_app.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT);")
    cursor.execute("DELETE FROM users;")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'SUPERADMIN');")
    cursor.execute("INSERT INTO users (username, role) VALUES ('alice', 'USER');")
    conn.commit()
    conn.close()


def get_user_from_db(username: str):
    """
    Query handler — Target for automated patch generation.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string interpolation vulnerable to SQL Injection
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows


class VulnerableAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/v1/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "app": "Isolated Vulnerable Test App"}')
            return

        if parsed.path == "/api/v1/user":
            params = parse_qs(parsed.query)
            username = params.get("username", [""])[0]

            try:
                import importlib
                import tests.vulnerable_app.app as app_mod
                importlib.reload(app_mod)
                rows = app_mod.get_user_from_db(username)
                
                # If SQL injection payload like "' OR '1'='1" matched all rows (>1 user), flag detection
                if len(rows) > 1 and ("'" in username or "OR" in username.upper()):
                    body = f'{{"status": "vulnerable", "users_count": {len(rows)}, "evidence": "SQL Injection successful: bypass authentication"}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                    return

                if rows:
                    user_data = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(str(user_data).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "User not found"}')
            except sqlite3.OperationalError as exc:
                # SQL syntax error indicator for SQLi
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(f'{{"error": "Database error", "details": "{exc}"}}'.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress stdout noise during tests


def run_server(port: int = 8888):
    init_db()
    server = HTTPServer(("127.0.0.1", port), VulnerableAppHandler)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
