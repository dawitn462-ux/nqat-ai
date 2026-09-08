// db/init.js
// NOTE: Passwords are stored as plain MD5 (or plaintext) on purpose — see A02.
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(path.join(__dirname, 'bookstore.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,        -- VULNERABLE (A02): MD5 hash, no salt
  email TEXT,
  role TEXT DEFAULT 'user',
  api_key TEXT
);

CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  author TEXT,
  price REAL,
  description TEXT,
  cover_url TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  book_id INTEGER,
  quantity INTEGER,
  total REAL,
  address TEXT
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id INTEGER,
  username TEXT,
  comment TEXT  -- VULNERABLE (A03/XSS): rendered unescaped in views
);
`);

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }

const userCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
if (userCount === 0) {
  const insertUser = db.prepare(
    'INSERT INTO users (username, password, email, role, api_key) VALUES (?,?,?,?,?)'
  );
  // VULNERABLE (A05): default/weak credentials shipped in the seed data
  insertUser.run('admin', md5('admin123'), 'admin@bookstore.local', 'admin', crypto.randomBytes(8).toString('hex'));
  insertUser.run('alice', md5('password'), 'alice@example.com', 'user', crypto.randomBytes(8).toString('hex'));
  insertUser.run('bob', md5('letmein'), 'bob@example.com', 'user', crypto.randomBytes(8).toString('hex'));

  const insertBook = db.prepare(
    'INSERT INTO books (title, author, price, description, cover_url) VALUES (?,?,?,?,?)'
  );
  const books = [
    ['Clean Code', 'Robert C. Martin', 32.5, 'A handbook of agile software craftsmanship.', '/img/clean-code.jpg'],
    ['The Pragmatic Programmer', 'Andy Hunt', 29.99, 'From journeyman to master.', '/img/pragmatic.jpg'],
    ['Design Patterns', 'Gang of Four', 45.0, 'Elements of reusable OO software.', '/img/gof.jpg'],
    ['Introduction to Algorithms', 'CLRS', 60.0, 'Comprehensive algorithms textbook.', '/img/clrs.jpg'],
    ['Refactoring', 'Martin Fowler', 38.0, 'Improving the design of existing code.', '/img/refactoring.jpg'],
  ];
  const ins = db.prepare('INSERT INTO books (title, author, price, description, cover_url) VALUES (?,?,?,?,?)');
  for (const b of books) ins.run(...b);
}

module.exports = db;
