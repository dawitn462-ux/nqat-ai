"""
Remediation Advisor Service — NKAT AI Fix-Recommendation Engine & Human Guide Generator
----------------------------------------------------------------------------------------
Generates actionable remediation recommendations, code/config snippets, and full multi-server
remediation guides (Nginx, Apache, Express/Node) covering:
1. Plain language meaning
2. Security risk assessment
3. Exact fix steps per server engine (Nginx, Apache, Express/Node)
4. Verification steps
5. Rollback instructions
"""

import re
from typing import Dict, Any, Optional


def generate_recommendation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps a finding dictionary to a specific, actionable remediation recommendation
    and a comprehensive step-by-step human guide.
    """
    if not isinstance(finding, dict):
        finding = {}

    finding_id = finding.get("id") or finding.get("finding_id")
    check_name = str(finding.get("check_name") or finding.get("title") or "").strip()
    evidence = str(finding.get("evidence") or "")
    metadata = finding.get("metadata") or finding.get("template_info") or {}

    from backend.services.reference_mapper import map_finding_to_references

    target_url = str(finding.get("target_url") or finding.get("endpoint") or finding.get("target") or "http://target-host").rstrip("/")

    check_name_lower = check_name.lower()

    # 1. Missing Security Headers
    if "missing security header" in check_name_lower or "security header" in check_name_lower or ("header" in check_name_lower and "missing" in check_name_lower):
        rec_data = _recommend_security_header(finding_id, check_name, target_url)

    # 2. Exposed Git Repository / Version Control
    elif "exposed git" in check_name_lower or ".git" in check_name_lower or "exposed version control" in check_name_lower or "git repository" in check_name_lower:
        rec_data = _recommend_exposed_git(finding_id, check_name, target_url)

    # Backup / Archive File Exposure
    elif "backup" in check_name_lower or ".bak" in check_name_lower or ".zip" in check_name_lower or ".tar" in check_name_lower or ".swp" in check_name_lower or "~" in check_name_lower:
        rec_data = _recommend_backup(finding_id, check_name, target_url)

    # Sensitive Environment & Credential Files
    elif ".env" in check_name_lower or "sensitive" in check_name_lower or "secret" in check_name_lower or "config" in check_name_lower or "credential" in check_name_lower:
        rec_data = _recommend_sensitive_file(finding_id, check_name, target_url)

    # Directory Listing / Information Leak
    elif "directory listing" in check_name_lower or "index of" in check_name_lower or "info leak" in check_name_lower or "information disclosure" in check_name_lower:
        rec_data = _recommend_directory_listing(finding_id, check_name, target_url)

    # 3. SQL Injection
    elif "sql injection" in check_name_lower or "sqli" in check_name_lower:
        rec_data = _recommend_sql_injection(finding_id, check_name)

    # 4. Nuclei / CVE-based Findings
    elif "cve-" in check_name_lower or "cve" in check_name_lower or finding.get("type") == "nuclei" or "nuclei" in check_name_lower:
        rec_data = _recommend_cve_nuclei(finding_id, check_name, evidence, metadata)

    # Specific common web vulnerabilities
    elif "xss" in check_name_lower or "cross-site script" in check_name_lower:
        rec_data = _recommend_xss(finding_id, check_name)

    # Exposed API Docs / Swagger UI
    elif "swagger" in check_name_lower or "api documentation" in check_name_lower or "openapi" in check_name_lower:
        rec_data = _recommend_swagger(finding_id, check_name)

    # Exposed FTP Directory
    elif "ftp" in check_name_lower:
        rec_data = _recommend_ftp(finding_id, check_name)

    # Exposed Metrics / Monitoring Endpoints
    elif "metrics" in check_name_lower or "prometheus" in check_name_lower:
        rec_data = _recommend_metrics(finding_id, check_name, target_url)

    # Outdated Software & Tech Fingerprints
    elif "outdated" in check_name_lower or "fingerprint" in check_name_lower or "software" in check_name_lower:
        rec_data = _recommend_outdated(finding_id, check_name, target_url)

    # 5. Unrecognized finding types (Fallback - Never blank)
    else:
        rec_data = _recommend_fallback(finding_id, check_name)

    # Enrich with real NIST, OWASP, and CWE reference data
    refs = map_finding_to_references(finding)
    rec_data["owasp_category"] = refs.get("owasp_category")
    rec_data["cwe_id"] = refs.get("cwe_id")
    rec_data["cwe_info"] = refs.get("cwe_info")
    rec_data["nvd_cve_details"] = refs.get("nvd_cve_details")

    if "full_fix_guide" in rec_data and isinstance(rec_data["full_fix_guide"], dict):
        rec_data["full_fix_guide"]["owasp_category"] = refs.get("owasp_category")
        rec_data["full_fix_guide"]["cwe_id"] = refs.get("cwe_id")
        rec_data["full_fix_guide"]["owasp_details"] = refs.get("owasp_details")
        rec_data["full_fix_guide"]["cwe_info"] = refs.get("cwe_info")
        rec_data["full_fix_guide"]["nvd_cve_details"] = refs.get("nvd_cve_details")
        rec_data["full_fix_guide"]["authoritative_citation"] = refs.get("authoritative_citation")

        # Format a human-readable remediation_guide string from full_fix_guide
        g = rec_data["full_fix_guide"]
        fix_steps_dict = g.get("fix_steps", {})
        steps_str = ""
        if isinstance(fix_steps_dict, dict):
            if "express_node" in fix_steps_dict:
                steps_str += f"### Node.js / Express Fix:\n{fix_steps_dict['express_node']}\n\n"
            if "nginx" in fix_steps_dict:
                steps_str += f"### Nginx Web Server Fix:\n{fix_steps_dict['nginx']}\n\n"
            if "apache" in fix_steps_dict:
                steps_str += f"### Apache Web Server Fix:\n{fix_steps_dict['apache']}\n\n"
        elif isinstance(fix_steps_dict, str):
            steps_str = f"### Step-by-Step Fix:\n{fix_steps_dict}\n\n"

        rec_data["remediation_guide"] = (
            f"### Finding Analysis: {check_name}\n"
            f"{g.get('plain_language_meaning', '')}\n\n"
            f"**Security Risk:** {g.get('why_it_is_risky', '')}\n\n"
            f"{steps_str}"
            f"### Verification Steps:\n{g.get('verification_steps', '')}\n\n"
            f"### ↩ Rollback Instructions:\n{g.get('rollback_note', '')}"
        )

    return rec_data


def _recommend_security_header(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    check_lower = check_name.lower()

    if "content-security-policy" in check_lower or "csp" in check_lower:
        title = "Add Content-Security-Policy (CSP) Header"
        rec = "Add the Content-Security-Policy HTTP header to restrict approved sources of content and mitigate XSS and data injection attacks."
        snippet = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';\" always;"
        header_name = "Content-Security-Policy"
        header_val = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    elif "x-frame-options" in check_lower:
        title = "Add X-Frame-Options Header"
        rec = "Set the X-Frame-Options header to DENY or SAMEORIGIN to prevent framing and Clickjacking attacks."
        snippet = "add_header X-Frame-Options \"SAMEORIGIN\" always;"
        header_name = "X-Frame-Options"
        header_val = "SAMEORIGIN"
    elif "x-content-type-options" in check_lower:
        title = "Add X-Content-Type-Options Header"
        rec = "Set the X-Content-Type-Options header to 'nosniff' to prevent MIME-type sniffing."
        snippet = "add_header X-Content-Type-Options \"nosniff\" always;"
        header_name = "X-Content-Type-Options"
        header_val = "nosniff"
    elif "strict-transport-security" in check_lower or "hsts" in check_lower:
        title = "Add Strict-Transport-Security (HSTS) Header"
        rec = "Enforce HTTPS by sending the Strict-Transport-Security header with a long max-age and includeSubDomains directive."
        snippet = "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        header_name = "Strict-Transport-Security"
        header_val = "max-age=31536000; includeSubDomains"
    elif "referrer-policy" in check_lower:
        title = "Add Referrer-Policy Header"
        rec = "Set Referrer-Policy header to control how much referrer information is included with requests."
        snippet = "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
        header_name = "Referrer-Policy"
        header_val = "strict-origin-when-cross-origin"
    elif "permissions-policy" in check_lower:
        title = "Add Permissions-Policy Header"
        rec = "Set Permissions-Policy header to restrict browser API features (camera, microphone, geolocation)."
        snippet = "add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;"
        header_name = "Permissions-Policy"
        header_val = "geolocation=(), camera=(), microphone=()"
    else:
        header_name = check_name.split(":")[-1].strip() if ":" in check_name else check_name
        title = f"Add Security Header: {header_name}"
        rec = f"Configure server responses to include the '{header_name}' security header with a recommended secure value."
        snippet = f"add_header {header_name} \"<recommended_secure_value>\" always;"
        header_val = "<recommended_secure_value>"

    guide = {
        "plain_language_meaning": f"The web application response is missing the '{header_name}' HTTP security header, which instructs modern browsers on security policy enforcement.",
        "why_it_is_risky": f"Without '{header_name}', web browsers run under permissive legacy mode, leaving users vulnerable to script injection, Clickjacking framing, or protocol downgrade attacks.",
        "fix_steps": {
            "nginx": f"Open `/etc/nginx/sites-available/default` (or website config) and add inside `server {{ ... }}` or `location / {{ ... }}` block:\n  add_header {header_name} \"{header_val}\" always;\nThen test and reload Nginx:\n  sudo nginx -t && sudo systemctl reload nginx",
            "apache": f"Enable headers module (`sudo a2enmod headers`). Add to `.htaccess` or virtual host configuration:\n  Header always set {header_name} \"{header_val}\"\nThen reload Apache:\n  sudo systemctl reload apache2",
            "express_node": f"Install Helmet security middleware (`npm install helmet`). In your Node/Express `server.js`:\n  const helmet = require('helmet');\n  app.use(helmet()); // Automatically sets modern security headers"
        },
        "verification_steps": f"Run terminal command: `curl -I {target_url}` and verify `{header_name}: {header_val}` appears in response headers.",
        "rollback_note": f"To undo: remove or comment out the added `add_header` directive from server config and reload server service."
    }

    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "HEADER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_exposed_git(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Block Public Access to .git Directory"
    rec = "Remove or restrict public web server access to the '.git/' version control directory to prevent source code exposure."
    snippet = (
        "# Nginx Configuration Rule:\n"
        "location ~ /\\.git {\n"
        "    deny all;\n"
        "    return 404;\n"
        "}\n\n"
        "# Apache .htaccess Rule:\n"
        "RedirectMatch 404 /\\.git"
    )
    guide = {
        "plain_language_meaning": "The `.git/` directory of your source control repository is publicly accessible via the web server.",
        "why_it_is_risky": "Attacker tools can download your entire `.git` tree, reconstruct your application source code, and steal API keys, database credentials, or secret tokens.",
        "fix_steps": {
            "nginx": "Add to Nginx site config inside `server { ... }` block:\n  location ~ /\\.git {\n      deny all;\n      return 404;\n  }\nReload Nginx: `sudo systemctl reload nginx`",
            "apache": "In `/var/www/html/.htaccess` or virtual host config, add:\n  RedirectMatch 404 /\\.git\nOr:\n  <DirectoryMatch \"/\\.git\">\n      Require all denied\n  </DirectoryMatch>",
            "express_node": "Configure static middleware to ignore dotfiles:\n  app.use(express.static('public', { dotfiles: 'ignore' }));"
        },
        "verification_steps": f"Run: `curl -I {target_url}/.git/HEAD`. Verify that HTTP response status returns `404 Not Found` or `403 Forbidden`.",
        "rollback_note": "To undo: remove the block rule from Nginx/Apache configuration or express static options and restart server."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_sql_injection(finding_id: Optional[Any], check_name: str) -> Dict[str, Any]:
    title = "Use Parameterized Queries / Prepared Statements"
    rec = "Never concatenate user input directly into SQL query strings. Use parameterized queries or prepared statements via your database driver or ORM."
    snippet = (
        "# Python DB-API Parameterized Query Pattern Example:\n"
        "# Vulnerable: cursor.execute(f\"SELECT * FROM users WHERE name = '{user_input}'\")\n"
        "# Remediated:\n"
        "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))"
    )
    guide = {
        "plain_language_meaning": "User inputs (form fields, query parameters) are concatenated directly into SQL queries without escaping or parameterization.",
        "why_it_is_risky": "Allows malicious actors to manipulate SQL database commands, bypass authentication, read or modify confidential tables, or take over database hosts.",
        "fix_steps": {
            "express_node": "Use parameterized queries with node-postgres / mysql2:\n  db.query('SELECT * FROM users WHERE username = $1', [username]);\nOr use ORM models (Prisma/Sequelize).",
            "nginx": "Deploy ModSecurity WAF module with OWASP Core Rule Set (CRS) to detect and drop SQLi payload patterns (`UNION SELECT`, `' OR '1'='1`).",
            "apache": "Enable `mod_security2` module with OWASP Core Rule Set to inspect and block SQL injection request arguments."
        },
        "verification_steps": "Send test payload `q=' OR '1'='1--` to affected endpoint parameter and verify application returns validation error or normal results without executing injected SQL.",
        "rollback_note": "To undo code refactoring: revert SQL query string syntax to previous pattern, though parameterized queries are strongly recommended for safety."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "CODE_FIX",
        "full_fix_guide": guide,
    }


def _recommend_xss(finding_id: Optional[Any], check_name: str) -> Dict[str, Any]:
    title = "Implement Context-Aware Output Encoding and CSP"
    rec = "Encode all user-supplied input before rendering it in HTML contexts, and enforce a strict Content Security Policy (CSP)."
    snippet = "element.textContent = sanitizeHTML(userInput); // Use HTML entity encoding"
    guide = {
        "plain_language_meaning": "User input is rendered on web pages without sanitization or HTML entity encoding.",
        "why_it_is_risky": "Attackers can inject malicious scripts into victims' browsers, hijacking user sessions, stealing auth tokens, or redirecting to malware.",
        "fix_steps": {
            "express_node": "Use templating engines with auto-escaping (EJS/Handlebars) or DOMPurify library. Avoid `innerHTML`; use `textContent`:\n  element.textContent = userInput;",
            "nginx": "Add CSP header to block inline script execution:\n  add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
            "apache": "Add CSP header in virtual host:\n  Header set Content-Security-Policy \"default-src 'self'; script-src 'self';\""
        },
        "verification_steps": "Submit test string `<script>alert('xss')</script>` in input forms and verify HTML source displays `&lt;script&gt;` instead of raw tags.",
        "rollback_note": "To undo: remove CSP headers or output encoding functions."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "CODE_FIX",
        "full_fix_guide": guide,
    }


def _recommend_swagger(finding_id: Optional[Any], check_name: str) -> Dict[str, Any]:
    title = "Restrict Public Access to API Documentation"
    rec = "Restrict public web server access to interactive API documentation (Swagger/OpenAPI) in production environments via authentication middleware or IP restrictions."
    snippet = (
        "# Nginx Rule to restrict Swagger UI in production:\n"
        "location ~ ^/(swagger|docs|api-docs|openapi.json) {\n"
        "    allow 10.0.0.0/8;\n"
        "    deny all;\n"
        "}"
    )
    guide = {
        "plain_language_meaning": "Interactive Swagger UI or OpenAPI documentation routes are publicly visible.",
        "why_it_is_risky": "Provides attackers with a comprehensive directory of API endpoints, parameters, and internal architecture payload formats.",
        "fix_steps": {
            "nginx": "Restrict `/swagger`, `/docs` routes to private internal IPs:\n  location ~ ^/(swagger|docs) {\n      allow 10.0.0.0/8;\n      deny all;\n  }",
            "apache": "In Apache config:\n  <LocationMatch \"^/(swagger|docs)\">\n      Require ip 10.0.0.0/8\n  </LocationMatch>",
            "express_node": "Mount Swagger middleware only in non-production environments:\n  if (process.env.NODE_ENV !== 'production') {\n      app.use('/docs', swaggerUi.serve, swaggerUi.setup(specs));\n  }"
        },
        "verification_steps": "Request `/swagger-ui/index.html` from an external IP address and verify response is `403 Forbidden` or `404 Not Found`.",
        "rollback_note": "To undo: remove IP restriction location block or environment guard statement."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_ftp(finding_id: Optional[Any], check_name: str) -> Dict[str, Any]:
    title = "Disable Anonymous FTP and Restrict File Transfer Access"
    rec = "Disable anonymous FTP login and enforce secure encrypted protocols (SFTP/SSH) with strict firewall IP whitelist access controls."
    snippet = (
        "# vsftpd.conf:\n"
        "anonymous_enable=NO\n"
        "local_enable=YES\n"
        "write_enable=YES\n"
        "chroot_local_user=YES"
    )
    guide = {
        "plain_language_meaning": "An unencrypted FTP server is accessible publicly on port 21.",
        "why_it_is_risky": "FTP transmits login credentials and files in plaintext over network paths. Anonymous FTP allows unauthenticated file enumeration.",
        "fix_steps": {
            "nginx": "Block port 21 via host firewall:\n  sudo ufw deny 21/tcp",
            "apache": "Stop vsftpd/ftpd service:\n  sudo systemctl stop vsftpd && sudo systemctl disable vsftpd",
            "express_node": "Disable embedded Node FTP packages and enforce SFTP/SSH protocols for file ingestion."
        },
        "verification_steps": "Run: `nmap -p 21 localhost` or `curl ftp://localhost` to verify connection is refused.",
        "rollback_note": "To undo: restart vsftpd service with `sudo systemctl start vsftpd` or allow port 21 in firewall."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_metrics(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Secure Telemetry and Metrics Endpoints"
    rec = "Protect application performance metrics (/metrics) behind HTTP basic authentication or bind metrics exporters to private loopback interfaces."
    snippet = (
        "# Nginx basic auth for metrics endpoint:\n"
        "location /metrics {\n"
        "    auth_basic \"Metrics Restricted\";\n"
        "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "}"
    )
    guide = {
        "plain_language_meaning": "Prometheus or server telemetry endpoints (`/metrics`) are exposed publicly.",
        "why_it_is_risky": "Leaks sensitive operational data including server load, active connections, memory limits, and runtime versions.",
        "fix_steps": {
            "nginx": "Add HTTP basic authentication to `/metrics`:\n  location /metrics {\n      auth_basic \"Restricted\";\n      auth_basic_user_file /etc/nginx/.htpasswd;\n  }",
            "apache": "In Apache config:\n  <Location \"/metrics\">\n      AuthType Basic\n      AuthName \"Metrics Access\"\n      AuthUserFile /etc/apache2/.htpasswd\n      Require valid-user\n  </Location>",
            "express_node": "Add basic auth middleware to `/metrics` route:\n  app.use('/metrics', basicAuth({ users: { 'admin': 'secret' } }));"
        },
        "verification_steps": f"Run `curl -I {target_url}/metrics` and confirm response code is `401 Unauthorized`.",
        "rollback_note": "To undo: remove basic auth directives from `/metrics` location configuration."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_outdated(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Suppress Version Banners and Update Component Versions"
    rec = "Suppress web server technology banners (Server, X-Powered-By) in response headers and keep underlying server components updated to current LTS releases."
    snippet = (
        "# Nginx:\n"
        "server_tokens off;\n\n"
        "# php.ini:\n"
        "expose_php = Off"
    )
    guide = {
        "plain_language_meaning": "Server response headers disclose exact version numbers of underlying software packages.",
        "why_it_is_risky": "Attackers perform automated queries against disclosed version strings to match known zero-day exploits.",
        "fix_steps": {
            "nginx": "In `/etc/nginx/nginx.conf` inside `http { ... }` block:\n  server_tokens off;",
            "apache": "In `/etc/apache2/conf-available/security.conf`:\n  ServerTokens Prod\n  ServerSignature Off",
            "express_node": "Disable `X-Powered-By` header in Express:\n  app.disable('x-powered-by');"
        },
        "verification_steps": f"Run `curl -I {target_url}` and confirm version numbers are omitted from `Server` and `X-Powered-By` headers.",
        "rollback_note": "To undo: reset `server_tokens on;` or `ServerTokens Full` in web server configuration."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_cve_nuclei(finding_id: Optional[Any], check_name: str, evidence: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    patched_version = None

    if isinstance(metadata, dict):
        patched_version = metadata.get("patched_version") or metadata.get("remediation") or metadata.get("patch_version")
        if not patched_version and isinstance(metadata.get("info"), dict):
            patched_version = metadata["info"].get("remediation") or metadata["info"].get("patched_version")

    if not patched_version:
        match = re.search(r'(?:patched in|fixed in|update to|v)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', f"{check_name} {evidence}", re.IGNORECASE)
        if match:
            patched_version = f"v{match.group(1)}"

    if patched_version:
        rec = f"Apply security patch or update the affected component to version {patched_version} or higher to resolve this CVE vulnerability."
        snippet = f"# Upgrade component/package to fixed version:\n# e.g., update to version {patched_version}"
    else:
        rec = "Update the affected software component to the latest stable version and verify vendor security advisory details."
        snippet = "# Perform software package upgrade to latest stable version\n# Check official vendor CVE bulletin for patch instructions."

    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', check_name, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else "CVE Vulnerability"

    guide = {
        "plain_language_meaning": f"Nuclei scanner detected an unpatched vulnerability ({cve_id}) in an installed software component.",
        "why_it_is_risky": "Publicly known CVEs have published exploit vectors that attackers use for automated exploitation.",
        "fix_steps": {
            "nginx": f"Upgrade Nginx package:\n  sudo apt update && sudo apt install --only-upgrade nginx",
            "apache": f"Upgrade Apache package:\n  sudo apt update && sudo apt install --only-upgrade apache2",
            "express_node": f"Update Node package dependencies:\n  npm audit fix --force"
        },
        "verification_steps": f"Re-run scanner or Nuclei audit to confirm template match for {cve_id} no longer fires.",
        "rollback_note": "To undo: downgrade package using `apt-get install package=version` or revert `package.json` lockfile."
    }

    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": f"Patch and Update Software Component ({cve_id})",
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SOFTWARE_UPDATE",
        "full_fix_guide": guide,
    }


def _recommend_backup(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Delete Exposed Backup Archives and Files"
    rec = "Remove temporary backup files (.bak, .old, .zip, .tar.gz, ~) from public web server directories immediately."
    snippet = (
        "# Nginx block backup file extensions:\n"
        "location ~* \\.(bak|config|sql|tar|tgz|gz|zip|old|swp|~)$ {\n"
        "    deny all;\n"
        "    return 404;\n"
        "}"
    )
    guide = {
        "plain_language_meaning": f"Backup or source archive files matching '{check_name}' are publicly downloadable from the web server.",
        "why_it_is_risky": "Backup archives often contain old source code, database dumps, unencrypted passwords, and API keys.",
        "fix_steps": {
            "express_node": "Remove backup files from static assets directory:\n  rm public/*.bak public/*.zip public/*.tar.gz",
            "nginx": "Add location match block to Nginx config:\n  location ~* \\.(bak|config|sql|tar|tgz|gz|zip|old|swp|~)$ { deny all; return 404; }",
            "apache": "In `.htaccess` add:\n  <FilesMatch \"\\.(bak|config|sql|tar|tgz|gz|zip|old|swp|~)$\">\n      Require all denied\n  </FilesMatch>"
        },
        "verification_steps": f"Request `curl -I {target_url}/backup.zip` and verify response is 404 Not Found.",
        "rollback_note": "To undo: restore file from secure offline storage if needed."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "FILE_CLEANUP",
        "full_fix_guide": guide,
    }


def _recommend_sensitive_file(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Block Public Access to Environment and Secret Files"
    rec = "Ensure environment variables (.env), credentials, and secret configuration files are stored outside web server docroot or blocked."
    snippet = (
        "# Nginx rule for secret files:\n"
        "location ~* /\\.(env|secret|credentials|git) {\n"
        "    deny all;\n"
        "    return 404;\n"
        "}"
    )
    guide = {
        "plain_language_meaning": f"Sensitive file '{check_name}' containing credentials or environment variables was accessible via HTTP.",
        "why_it_is_risky": "Direct exposure of `.env` files exposes database credentials, JWT secrets, and API access keys to attackers.",
        "fix_steps": {
            "express_node": "Store `.env` file outside your web-accessible `public/` directory (in application root).",
            "nginx": "In Nginx `server { ... }` block add:\n  location ~* /\\.(env|secret|credentials) { deny all; return 404; }",
            "apache": "In `.htaccess` add:\n  <FilesMatch \"^\\.env\">\n      Require all denied\n  </FilesMatch>"
        },
        "verification_steps": f"Request `curl -I {target_url}/.env` and verify response status code is `404` or `403`.",
        "rollback_note": "To undo: verify file is placed in secure private root directory."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "ACCESS_CONTROL",
        "full_fix_guide": guide,
    }


def _recommend_directory_listing(finding_id: Optional[Any], check_name: str, target_url: str = "http://target-host") -> Dict[str, Any]:
    title = "Disable Directory Browsing on Web Server"
    rec = "Disable directory index listings (`autoindex off;`) across all web server location blocks."
    snippet = (
        "# Nginx:\n"
        "autoindex off;\n\n"
        "# Apache .htaccess:\n"
        "Options -Indexes"
    )
    guide = {
        "plain_language_meaning": "The web server presents an interactive list of files when requesting a directory without an `index.html` file.",
        "why_it_is_risky": "Directory browsing enables attackers to discover hidden uploaded files, backup files, and internal scripts.",
        "fix_steps": {
            "nginx": "Set `autoindex off;` inside Nginx `http { ... }` or `server { ... }` block and reload Nginx.",
            "apache": "In `.htaccess` or `/etc/apache2/apache2.conf` add:\n  Options -Indexes",
            "express_node": "Disable directory listing options in express static middleware:\n  app.use(express.static('public', { index: false }));"
        },
        "verification_steps": f"Request a directory path without trailing index file and verify server returns `403 Forbidden` or `404 Not Found`.",
        "rollback_note": "To undo: re-enable `autoindex on;` in test environments if needed."
    }
    return {
        "finding_id": finding_id,
        "check_name": check_name,
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "SERVER_CONFIG",
        "full_fix_guide": guide,
    }


def _recommend_fallback(finding_id: Optional[Any], check_name: str) -> Dict[str, Any]:
    title = "Manual Security Review Recommended"
    rec = f"Manual review recommended for finding '{check_name or 'Unrecognized Finding'}'. Inspect finding evidence and apply defense-in-depth security controls according to OWASP guidelines."
    snippet = "# Perform manual code/config audit for this finding.\n# Reference: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)"

    guide = {
        "plain_language_meaning": f"Security audit detected anomaly '{check_name or 'Unrecognized Finding'}' requiring human review.",
        "why_it_is_risky": "Unverified application behaviors may expose unforeseen security vulnerabilities.",
        "fix_steps": {
            "nginx": "Audit `/etc/nginx/nginx.conf` for weak directives or untrusted server locations.",
            "apache": "Audit `/etc/apache2/` virtual host configs for insecure overrides.",
            "express_node": "Audit Express application route definitions against OWASP Secure Coding Guidelines."
        },
        "verification_steps": "Inspect server access/error logs and test application workflow to confirm safe operation.",
        "rollback_note": "To undo: revert configuration edits to previous backup file."
    }

    return {
        "finding_id": finding_id,
        "check_name": check_name or "Unrecognized Finding",
        "recommendation_title": title,
        "recommendation": rec,
        "config_snippet": snippet,
        "remediation_type": "MANUAL_REVIEW",
        "full_fix_guide": guide,
    }
