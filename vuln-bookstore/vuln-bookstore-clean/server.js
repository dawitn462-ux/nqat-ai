const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const http = require('http');
const https = require('https');
const xml2js = require('xml2js');
const db = require('./db/init');

const app = express();
const PORT = 3000;

app.use(
  '/.well-known',
  express.static(path.join(__dirname, '.well-known'))
);
// ---- A02: Cryptographic Failures — hardcoded, weak JWT secret committed to source ----
const JWT_SECRET = 'bookstore_secret_123';

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ---- A05: Security Misconfiguration — serves the whole project dir, directory listing on ----
app.use('/static', express.static(__dirname, { index: false, dotfiles: 'allow' }));
app.use('/img', express.static('public/img'));

const upload = multer({ dest: 'public/uploads/' }); // A08: no file-type/signature validation

// -------------------- Auth helpers --------------------
function currentUser(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try {
    // VULNERABLE (A02/A07): algorithms not restricted -> accepts "alg: none" tokens,
    // so a client can forge a token with no signature at all.
    return jwt.decode(token) && jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (e) {
    return null;
  }
}

// -------------------- Routes --------------------

app.get('/', (req, res) => {
  const books = db.prepare('SELECT * FROM books').all();
  res.render('home', { books, user: currentUser(req) });
});

// A03: SQL Injection — search term concatenated directly into the query
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT * FROM books WHERE title LIKE '%${q}%' OR author LIKE '%${q}%'`;
  let results = [];
  let error = null;
  try {
    results = db.prepare(sql).all();
  } catch (e) {
    // A05: Security Misconfiguration — raw stack trace / SQL error leaked to the client
    error = e.message;
  }
  res.render('search', { results, q, error, user: currentUser(req) });
});

app.get('/book/:id', (req, res) => {
  // Also injectable via string concat, kept consistent with /search for the scanner.
  const book = db.prepare(`SELECT * FROM books WHERE id = ${req.params.id}`).get();
  const reviews = db.prepare('SELECT * FROM reviews WHERE book_id = ?').all(req.params.id);
  res.render('book', { book, reviews, user: currentUser(req) });
});

// A03: Stored XSS — comment is rendered with <%- %> (unescaped) in book.ejs
app.post('/book/:id/review', (req, res) => {
  db.prepare('INSERT INTO reviews (book_id, username, comment) VALUES (?,?,?)')
    .run(req.params.id, req.body.username || 'anon', req.body.comment || '');
  res.redirect('/book/' + req.params.id);
});

// -------------------- Auth --------------------

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', (req, res) => {
  const crypto = require('crypto');
  const { username, password, email } = req.body;
  // A04: Insecure Design — no password policy enforced (length, complexity, breach list)
  // A02: Cryptographic Failures — MD5, no salt, no work factor
  const hash = crypto.createHash('md5').update(password).digest('hex');
  try {
    db.prepare('INSERT INTO users (username, password, email, role, api_key) VALUES (?,?,?,?,?)')
      .run(username, hash, email, 'user', crypto.randomBytes(8).toString('hex'));
    res.redirect('/login');
  } catch (e) {
    res.render('register', { error: e.message }); // A05: verbose error leakage
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', (req, res) => {
  const crypto = require('crypto');
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password || '').digest('hex');
  // A03: SQL Injection — classic auth-bypass point (e.g. username: admin' -- )
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${hash}'`;
  const user = db.prepare(sql).get();

  // A09: Logging Failures — credentials logged in plaintext, no audit trail on failure
  console.log(`[LOGIN ATTEMPT] user=${username} pass=${password} success=${!!user}`);
  // A07: Identification & Auth Failures — no rate limiting / lockout on repeated failed attempts

  if (!user) return res.render('login', { error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: false }); // A02: missing Secure/HttpOnly hardening, readable by JS
  res.redirect('/');
});

app.get('/logout', (req, res) => { res.clearCookie('token'); res.redirect('/'); });

// -------------------- Broken Access Control (A01) --------------------

// IDOR: any logged-in (or even anonymous) user can view/modify any account by guessing IDs
app.get('/account/:id', (req, res) => {
  const acct = db.prepare('SELECT id, username, email, role, api_key FROM users WHERE id = ?').get(req.params.id);
  res.render('account', { acct, user: currentUser(req) });
});

// Admin panel: role is trusted from the client-supplied JWT payload with no server-side re-check
// against a protected resource list, and the route itself never verifies role === 'admin'.
app.get('/admin', (req, res) => {
  const user = currentUser(req);
  // VULNERABLE (A01): missing check — should require user && user.role === 'admin'
  const users = db.prepare('SELECT id, username, email, role, api_key FROM users').all();
  res.render('admin', { users, user });
});

// IDOR on orders — no ownership check that order.user_id === currentUser.id
app.get('/order/:id', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  res.render('order', { order, user: currentUser(req) });
});

// -------------------- Insecure Design (A04) --------------------

// Price/quantity/total are trusted from the client instead of recalculated server-side.
app.post('/checkout', (req, res) => {
  const { book_id, quantity, price, address } = req.body;
  const total = Number(price) * Number(quantity); // client can send price=0.01, quantity=-5, etc.
  db.prepare('INSERT INTO orders (user_id, book_id, quantity, total, address) VALUES (?,?,?,?,?)')
    .run(currentUser(req)?.id || null, book_id, quantity, total, address);
  res.redirect('/');
});

// -------------------- Vulnerable & Outdated Components (A06) --------------------
// See package.json — intentionally pinned to older majors with known advisories,
// and no lockfile-based CI audit step wired up. Documented in README.md.

app.get('/version', (req, res) => {
  // A05: banner disclosure helps an attacker fingerprint exact dependency versions
  res.json({ app: 'vuln-bookstore', node: process.version, deps: require('./package.json').dependencies });
});

// -------------------- Software & Data Integrity Failures (A08) --------------------

// "Import book catalog" feature parses attacker-controlled XML with external entities enabled.
const xmlParser = new xml2js.Parser({ explicitArray: false });
app.post('/import-catalog', bodyParser.text({ type: '*/*' }), (req, res) => {
  // VULNERABLE: xml2js here has no entity restriction layer in front of it, and the
  // upstream libxml-based parsers this app is designed to be swapped with (documented
  // in README) are configured with noent/DTD loading enabled -> classic XXE.
  xmlParser.parseString(req.body, (err, result) => {
    if (err) return res.status(400).send('Bad XML: ' + err.message); // A05 leak too
    res.json(result);
  });
});

// Unsigned "plugin"/theme upload — no checksum or signature verification before use
app.post('/upload-cover', upload.single('cover'), (req, res) => {
  res.json({ path: '/uploads/' + req.file.filename });
});

// -------------------- Security Logging & Monitoring Failures (A09) --------------------
// Intentionally absent: no centralized audit log for admin actions, auth failures,
// access-control denials, or data exports. See README for what should be added.

// -------------------- SSRF (A10) --------------------

// "Fetch a cover image from a URL" — server makes the request with no allow-list,
// no blocking of internal/link-local ranges, and follows the client-supplied URL verbatim.
app.get('/fetch-cover', (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('missing url');
  const client = target.startsWith('https') ? https : http;
  client.get(target, (r) => {
    res.setHeader('content-type', r.headers['content-type'] || 'application/octet-stream');
    r.pipe(res);
  }).on('error', (e) => res.status(500).send('fetch failed: ' + e.message)); // A05 leak
});

// -------------------- Debug / misconfig extras (A05) --------------------
app.get('/debug/env', (req, res) => {
  // VULNERABLE: exposes full process environment (would include secrets in real deploys)
  res.json(process.env);
});

app.listen(PORT, () => console.log(`vuln-bookstore listening on http://localhost:${PORT}`));
