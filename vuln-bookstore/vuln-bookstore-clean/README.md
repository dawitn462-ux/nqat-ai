# Vuln Bookstore — OWASP Top 10 (2021) Test Target

An intentionally insecure bookstore web app for exercising a vulnerability-assessment
and patching pipeline. **Do not deploy this publicly or reuse the code in production.**
Every flaw below is real (verified against the running app), tagged by OWASP category,
with its file/route and the fix your patching stage should apply.

## Run it

```bash
npm install
node server.js
# -> http://localhost:3000
```

Seed accounts: `admin` / `admin123`, `alice` / `password`, `bob` / `letmein`.

## Vulnerability map

### A01 — Broken Access Control
- `GET /admin` (`server.js`) — never checks `user.role === 'admin'`. Any visitor,
  authenticated or not, sees every user's email, role, and API key.
- `GET /account/:id` — IDOR: no check that the requester owns account `:id`.
- `GET /order/:id` — IDOR: no check that `order.user_id` matches the requester.
- **Fix**: add an auth middleware that loads the session user, then an authorization
  check (`role === 'admin'` for `/admin`; `order.user_id === user.id` for `/order/:id`,
  etc.) before touching the DB, returning 403 on failure.

### A02 — Cryptographic Failures
- `db/init.js`, `/register`, `/login` — passwords hashed with unsalted MD5.
- `server.js` — `JWT_SECRET` hardcoded in source; `jwt.verify(..., { algorithms: ['HS256','none'] })`
  accepts unsigned (`alg: none`) tokens.
- `/login` sets the auth cookie without `httpOnly`/`secure`/`sameSite`.
- **Fix**: hash passwords with bcrypt/argon2 (cost-tuned, salted); load the JWT secret
  from an environment variable/secret manager; restrict `algorithms` to `['HS256']` only;
  set `httpOnly: true, secure: true, sameSite: 'lax'` on the cookie.

### A03 — Injection
- `GET /search` and `GET /book/:id` (`server.js`) — user input concatenated directly
  into SQL strings. Verified payload: `q=nonexistent' OR '1'='1' -- ` returns every row;
  `username=admin' -- ` on `/login` logs in as admin with any password.
- `views/book.ejs` — review `comment` rendered with `<%- r.comment %>` (unescaped) →
  stored XSS.
- **Fix**: use parameterized queries (`db.prepare('... WHERE title LIKE ?').all('%'+q+'%')`)
  everywhere; render user content with `<%= %>` (auto-escaped) or sanitize with a library
  like DOMPurify if HTML must be allowed.

### A04 — Insecure Design
- `POST /checkout` — `price` arrives as a client-supplied hidden field and is trusted
  to compute `total`; quantity has no server-side bound.
- `/register` — no password-strength policy.
- **Fix**: recompute price/total server-side from the authoritative `books` table;
  validate quantity is a positive integer within a sane range; enforce a password
  policy (length + breached-password check) at registration.

### A05 — Security Misconfiguration
- `app.use('/static', express.static(__dirname, ...))` — serves the entire project
  directory, including `server.js` and `db/bookstore.db`.
- `GET /debug/env` — dumps the full process environment.
- `GET /version` — discloses exact dependency versions.
- SQL/fetch errors are returned verbatim to the client in `/search`, `/register`,
  `/fetch-cover`, `/import-catalog`.
- **Fix**: remove the debug/version endpoints (or gate behind admin auth + non-prod
  flag); serve only a designated `public/` directory; return generic error messages
  to clients and log details server-side only.

### A06 — Vulnerable and Outdated Components
- `package.json` pins dependencies with `^` ranges and includes no CI step that
  runs `npm audit` / Dependabot / Snyk against the lockfile.
- **Fix**: pin exact versions, commit the lockfile, and wire `npm audit --audit-level=high`
  (or equivalent SCA tool) into CI, failing the build on known-critical CVEs.

### A07 — Identification and Authentication Failures
- `/login` has no rate limiting, no lockout, and no delay after repeated failures
  (confirmed by the plaintext attempt log with no throttling logic).
- Session lifetime is a flat 7-day JWT with no revocation mechanism.
- **Fix**: add rate limiting/lockout (e.g. `express-rate-limit` + progressive delay),
  support token revocation (short-lived access token + refresh token, or a server-side
  session store), and log failed attempts without the raw password.

### A08 — Software and Data Integrity Failures
- `POST /import-catalog` — parses attacker-supplied XML; no allow-list/entity
  restriction in front of the parser (XXE-prone pattern).
- `POST /upload-cover` — accepts any file via `multer` with no type/signature/size
  validation and no checksum verification before it's served back.
- **Fix**: disable external entity resolution in the XML parser explicitly, validate
  uploaded file magic bytes and extension against an allow-list, cap file size, and
  store uploads outside the web root under randomized names.

### A09 — Security Logging and Monitoring Failures
- `/login` logs the **plaintext password** to the console on every attempt.
- No audit trail exists for admin actions, access-control denials, or failed logins
  beyond that single console line.
- **Fix**: never log credentials; add structured audit logging (who/what/when) for
  auth events and admin actions, shipped to a monitored log store with alerting on
  spikes in failed logins or 403s.

### A10 — Server-Side Request Forgery (SSRF)
- `GET /fetch-cover?url=` — server fetches any attacker-supplied URL with no
  allow-list and no blocking of internal/link-local/metadata IP ranges.
- **Fix**: restrict to an allow-list of trusted image hosts, resolve and block
  private/link-local/cloud-metadata IP ranges before connecting, and disable
  redirects (or re-validate the redirect target).

## Suggested workflow for your assessment platform

1. Run your scanner against `http://localhost:3000` and confirm it flags all 10
   categories above (route + parameter are listed for each so you can check recall).
2. Apply one fix at a time from the "Fix" notes, re-scan, and confirm the specific
   finding disappears without new regressions — this validates your patch-verification
   loop end to end.
3. Keep a "vulnerable" git tag and a "patched" branch so you can regression-test the
   scanner against both states repeatably.
