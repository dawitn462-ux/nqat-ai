"""
Isolated Interactive Vulnerable Security Lab Application — Target for NKAT AI Security Platform
------------------------------------------------------------------------------------------------
Provides a real web target with an interactive UI dashboard and live vulnerable endpoints:
- SQL Injection (/api/v1/user?username=)
- Reflected XSS (/search?q=)
- Exposed Credentials (/.env)
- Exposed Git Repository (/.git/config)
- Exposed Database Backup (/backup.zip, /database.sql)
- Exposed API Documentation (/swagger-ui, /api-docs)
- Exposed Metrics (/metrics)
- Server Banner Leak (Server, X-Powered-By)
"""

import sqlite3
import os
import sys
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_app.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT);")
    cursor.execute("DELETE FROM users;")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'SUPERADMIN');")
    cursor.execute("INSERT INTO users (username, role) VALUES ('alice', 'USER');")
    cursor.execute("INSERT INTO users (username, role) VALUES ('bob', 'ANALYST');")
    conn.commit()
    conn.close()


def get_user_from_db(username: str):
    """
    Query handler — Target for automated patch generation.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string interpolation vulnerable to SQL Injection
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows


LAB_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NKAT Security Testing Lab Target App</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #090d16;
            --card-bg: rgba(18, 26, 44, 0.75);
            --card-border: rgba(0, 240, 255, 0.2);
            --primary-cyan: #00f0ff;
            --primary-purple: #7928ca;
            --primary-pink: #ff0080;
            --text-main: #f0f4fc;
            --text-muted: #8b9bb4;
            --danger-red: #ff3366;
            --warning-orange: #ff9900;
            --success-green: #00ff88;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(121, 40, 202, 0.15) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(0, 240, 255, 0.15) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--card-border);
            margin-bottom: 2rem;
        }

        .logo-group {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-badge {
            background: linear-gradient(135deg, var(--primary-cyan), var(--primary-purple));
            color: #000;
            font-weight: 800;
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            font-size: 0.9rem;
            letter-spacing: 1px;
        }

        h1 {
            font-size: 1.6rem;
            font-weight: 700;
            background: linear-gradient(90deg, #ffffff, var(--primary-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-pill {
            background: rgba(255, 51, 102, 0.15);
            border: 1px solid rgba(255, 51, 102, 0.4);
            color: var(--danger-red);
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .status-pill::before {
            content: '';
            width: 8px;
            height: 8px;
            background-color: var(--danger-red);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--danger-red);
        }

        .hero-banner {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.8rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.37);
        }

        .hero-banner h2 {
            font-size: 1.25rem;
            color: var(--primary-cyan);
            margin-bottom: 0.5rem;
        }

        .hero-banner p {
            color: var(--text-muted);
            line-height: 1.6;
            font-size: 0.95rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            padding: 1.5rem;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .card:hover {
            border-color: var(--primary-cyan);
            transform: translateY(-2px);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .tag {
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
        }

        .tag-sqli { background: rgba(255, 51, 102, 0.2); color: var(--danger-red); border: 1px solid rgba(255, 51, 102, 0.4); }
        .tag-xss { background: rgba(255, 153, 0, 0.2); color: var(--warning-orange); border: 1px solid rgba(255, 153, 0, 0.4); }
        .tag-info { background: rgba(0, 240, 255, 0.2); color: var(--primary-cyan); border: 1px solid rgba(0, 240, 255, 0.4); }

        .input-group {
            margin-bottom: 1rem;
        }

        label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.4rem;
        }

        input[type="text"] {
            width: 100%;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #fff;
            padding: 0.7rem 1rem;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s ease;
        }

        input[type="text"]:focus {
            border-color: var(--primary-cyan);
        }

        .btn-group {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }

        .btn-payload {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            padding: 0.35rem 0.7rem;
            border-radius: 6px;
            font-family: 'Fira Code', monospace;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-payload:hover {
            background: rgba(0, 240, 255, 0.15);
            color: var(--primary-cyan);
            border-color: var(--primary-cyan);
        }

        .btn-submit {
            width: 100%;
            background: linear-gradient(135deg, var(--primary-cyan), #0099ff);
            color: #000;
            font-weight: 700;
            padding: 0.75rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: opacity 0.2s ease;
        }

        .btn-submit:hover {
            opacity: 0.9;
        }

        .output-box {
            background: #04060a;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.8rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.82rem;
            color: #a0aec0;
            max-height: 180px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .link-list {
            list-style: none;
        }

        .link-list li {
            margin-bottom: 0.6rem;
        }

        .link-list a {
            color: var(--primary-cyan);
            text-decoration: none;
            font-family: 'Fira Code', monospace;
            font-size: 0.88rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0.8rem;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 6px;
            transition: background 0.2s ease;
        }

        .link-list a:hover {
            background: rgba(0, 240, 255, 0.1);
        }

        footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--card-border);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-group">
                <span class="logo-badge">LAB TARGET</span>
                <h1>NKAT Vulnerable Security Lab Application</h1>
            </div>
            <div class="status-pill">
                TARGET ACTIVE (Port 8888)
            </div>
        </header>

        <div class="hero-banner">
            <h2>🎯 Isolated Target Application for NKAT AI Security Audit</h2>
            <p>This web application contains deliberate security vulnerabilities (SQL Injection, Reflected XSS, Exposed Environment Credentials, Git Config Leakage, Backup File Disclosure, Server Version Banner Leaks, and Missing Security Headers) designed to be scanned, correlated, and remediated by the NKAT AI Security Platform.</p>
        </div>

        <div class="grid">
            <!-- SQL Injection Sandbox -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">💉 SQL Injection Sandbox</div>
                    <span class="tag tag-sqli">CWE-89</span>
                </div>
                <div class="input-group">
                    <label>Target Endpoint: GET /api/v1/user?username=</label>
                    <input type="text" id="sqli-input" value="' OR '1'='1">
                </div>
                <div class="btn-group">
                    <button class="btn-payload" onclick="setSqli(\"' OR '1'='1\")">' OR '1'='1</button>
                    <button class="btn-payload" onclick="setSqli(\"admin'--\")">admin'--</button>
                    <button class="btn-payload" onclick="setSqli(\"1' UNION SELECT 1,'hacked','admin'--\")">UNION SELECT</button>
                </div>
                <button class="btn-submit" onclick="testSqli()">Send SQLi Request</button>
                <div style="margin-top: 1rem;">
                    <label>HTTP Response Data:</label>
                    <div class="output-box" id="sqli-output">Click Send SQLi Request to test payload...</div>
                </div>
            </div>

            <!-- Reflected XSS Sandbox -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🧪 Reflected XSS Sandbox</div>
                    <span class="tag tag-xss">CWE-79</span>
                </div>
                <div class="input-group">
                    <label>Target Endpoint: GET /search?q=</label>
                    <input type="text" id="xss-input" value="<script>alert('NKAT_AI_XSS')</script>">
                </div>
                <div class="btn-group">
                    <button class="btn-payload" onclick="setXss(\"<script>alert('XSS')</script>\")">&lt;script&gt;</button>
                    <button class="btn-payload" onclick="setXss(\"<img src=x onerror=alert(1)>\")">&lt;img onerror&gt;</button>
                </div>
                <button class="btn-submit" onclick="testXss()">Send XSS Request</button>
                <div style="margin-top: 1rem;">
                    <label>Raw HTML Reflection Output:</label>
                    <div class="output-box" id="xss-output">Click Send XSS Request to test payload...</div>
                </div>
            </div>

            <!-- Exposed Secrets & Backups -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📁 Exposed Sensitive Files</div>
                    <span class="tag tag-info">CWE-200 / CWE-538</span>
                </div>
                <ul class="link-list">
                    <li><a href="/.env" target="_blank"><span>/.env Credentials File</span> <span style="font-size:0.75rem; color:var(--danger-red)">HIGH RISK</span></a></li>
                    <li><a href="/.git/config" target="_blank"><span>/.git/config Repository</span> <span style="font-size:0.75rem; color:var(--warning-orange)">MEDIUM RISK</span></a></li>
                    <li><a href="/backup.zip" target="_blank"><span>/backup.zip Archive</span> <span style="font-size:0.75rem; color:var(--warning-orange)">MEDIUM RISK</span></a></li>
                    <li><a href="/database.sql" target="_blank"><span>/database.sql Dump</span> <span style="font-size:0.75rem; color:var(--danger-red)">HIGH RISK</span></a></li>
                </ul>
            </div>

            <!-- API Docs & Metrics -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📑 Information Disclosure</div>
                    <span class="tag tag-info">CWE-200</span>
                </div>
                <ul class="link-list">
                    <li><a href="/swagger-ui" target="_blank"><span>/swagger-ui API Console</span> <span>SWAGGER</span></a></li>
                    <li><a href="/api-docs" target="_blank"><span>/api-docs OpenAPI Specs</span> <span>JSON</span></a></li>
                    <li><a href="/metrics" target="_blank"><span>/metrics Prometheus Stats</span> <span>TEXT</span></a></li>
                </ul>
                <div style="margin-top: 1rem; font-size:0.82rem; color:var(--text-muted);">
                    Server Header Leaks: <code style="color:var(--primary-cyan)">Server: NKAT-Vulnerable-Lab/1.0.0</code> & <code style="color:var(--primary-cyan)">X-Powered-By: Express/4.18.2</code>
                </div>
            </div>
        </div>

        <footer>
            NKAT AI Security Platform Target Application — Authorized Local Scope (127.0.0.1:8888)
        </footer>
    </div>

    <script>
        function setSqli(val) {
            document.getElementById('sqli-input').value = val;
        }
        function setXss(val) {
            document.getElementById('xss-input').value = val;
        }

        async function testSqli() {
            const val = document.getElementById('sqli-input').value;
            const out = document.getElementById('sqli-output');
            out.innerText = "Sending request to GET /api/v1/user?username=" + encodeURIComponent(val) + "...";
            try {
                const res = await fetch('/api/v1/user?username=' + encodeURIComponent(val));
                const text = await res.text();
                out.innerText = `[HTTP Status ${res.status}]\n` + text;
            } catch (err) {
                out.innerText = "Error: " + err;
            }
        }

        async function testXss() {
            const val = document.getElementById('xss-input').value;
            const out = document.getElementById('xss-output');
            out.innerText = "Sending request to GET /search?q=" + encodeURIComponent(val) + "...";
            try {
                const res = await fetch('/search?q=' + encodeURIComponent(val));
                const text = await res.text();
                out.innerText = `[HTTP Status ${res.status}]\n` + text;
            } catch (err) {
                out.innerText = "Error: " + err;
            }
        }
    </script>
</body>
</html>
"""


class VulnerableAppHandler(BaseHTTPRequestHandler):
    def send_banner_headers(self):
        # Intentional server banner & power header leak for DAST scanner detection
        self.send_header("Server", "NKAT-Vulnerable-Lab/1.0.0")
        self.send_header("X-Powered-By", "Express/4.18.2")

    def do_GET(self):
        parsed = urlparse(self.path)

        # 1. Main Interactive Target UI Dashboard
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_banner_headers()
            self.end_headers()
            self.wfile.write(LAB_HTML_PAGE.encode("utf-8"))
            return

        # 2. Health Endpoint
        if parsed.path == "/api/v1/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_banner_headers()
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "app": "NKAT Vulnerable Security Lab App"}')
            return

        # 3. SQL Injection Endpoint (/api/v1/user?username=)
        if parsed.path == "/api/v1/user":
            params = parse_qs(parsed.query)
            username = params.get("username", [""])[0]

            try:
                rows = get_user_from_db(username)

                # If SQL injection payload returned multiple rows (>1 user), flag detection
                if len(rows) > 1 and ("'" in username or "OR" in username.upper() or "UNION" in username.upper()):
                    body = f'{{"status": "vulnerable", "users_count": {len(rows)}, "evidence": "SQL Injection successful: bypass authentication", "data": {json.dumps(rows)}}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_banner_headers()
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                    return

                if rows:
                    user_data = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_banner_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps(user_data).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.send_banner_headers()
                    self.end_headers()
                    self.wfile.write(b'{"error": "User not found"}')
            except sqlite3.OperationalError as exc:
                # SQL syntax error indicator for SQLi scanner
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_banner_headers()
                self.end_headers()
                self.wfile.write(f'{{"error": "Database SQL error", "details": "{exc}"}}'.encode("utf-8"))
            return

        # 4. Reflected XSS Endpoint (/search?q=)
        if parsed.path in ("/search", "/rest/products/search"):
            params = parse_qs(parsed.query)
            query = params.get("q", [""])[0] or params.get("query", [""])[0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_banner_headers()
            self.end_headers()
            # Vulnerable reflected output without HTML entity encoding
            body = f"<html><body><h1>Search Results for: {query}</h1><p>Zero items found.</p></body></html>"
            self.wfile.write(body.encode("utf-8"))
            return

        # 5. Exposed Environment File (/.env)
        if parsed.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_banner_headers()
            self.end_headers()
            env_content = (
                "ENVIRONMENT=production\n"
                "DATABASE_URL=sqlite:///./vulnerable_app.db\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "JWT_SECRET=super_secret_jwt_signing_key_2026\n"
                "ADMIN_PASSWORD=AdminP@ssw0rd2026!\n"
            )
            self.wfile.write(env_content.encode("utf-8"))
            return

        # 6. Exposed Git Config (/.git/config)
        if parsed.path == "/.git/config":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_banner_headers()
            self.end_headers()
            git_config = (
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n"
                "[remote \"origin\"]\n\turl = https://github.com/nkat-ai/vulnerable-app.git\n"
            )
            self.wfile.write(git_config.encode("utf-8"))
            return

        # 7. Exposed Backup Archive (/backup.zip, /database.sql)
        if parsed.path in ("/backup.zip", "/database.sql", "/dump.sql"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_banner_headers()
            self.end_headers()
            self.wfile.write(b"NKAT_EXPOSED_BACKUP_DUMP_HEADER_DATA_2026")
            return

        # 8. Information Disclosure (/swagger-ui, /api-docs, /metrics)
        if parsed.path in ("/swagger-ui", "/api-docs"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_banner_headers()
            self.end_headers()
            self.wfile.write(b'{"swagger": "2.0", "info": {"title": "NKAT Vulnerable API", "version": "1.0.0"}}')
            return

        # 9. Domain Ownership Verification File Endpoint (/.well-known/nkat-verification.txt)
        if parsed.path in ("/.well-known/nkat-verification.txt", "/nkat-verify.txt"):
            token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nkat-verification.txt")
            if os.path.exists(token_file):
                with open(token_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
            else:
                content = "nkat-verify-demo-token-127001-8888"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_banner_headers()
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        self.send_response(404)
        self.send_banner_headers()
        self.end_headers()
        self.wfile.write(b'{"error": "Endpoint not found"}')

    def log_message(self, format, *args):
        pass  # Suppress stdout logging in test runs


def run_server(port: int = 8888):
    init_db()
    server = HTTPServer(("127.0.0.1", port), VulnerableAppHandler)
    server.serve_forever()


if __name__ == "__main__":
    print("[*] Starting NKAT Vulnerable Security Lab App on http://127.0.0.1:8888 ...")
    run_server(8888)
