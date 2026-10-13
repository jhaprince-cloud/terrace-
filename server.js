'use strict';
require('dotenv').config();
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.13+, nothing to compile

const { PORT = 3000, NODE_ENV, JWT_SECRET, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, ADMIN_KEY,
  DB_FILE = './data/store.db', CURRENCY = 'usd' } = process.env;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const prod = NODE_ENV === 'production';
if (prod && (!JWT_SECRET || JWT_SECRET.length < 32)) { console.error('Set JWT_SECRET to 32+ characters.'); process.exit(1); }
if (!JWT_SECRET) console.warn('JWT_SECRET not set: using a temporary secret, logins reset on restart.');
const SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex');
const stripe = STRIPE_SECRET_KEY ? require('stripe')(STRIPE_SECRET_KEY) : null;

// ---- Business rules (all money in cents, enforced on the server only) ----
const PRINT = 1000, FREE_OVER = 9900, STD = 600, EXP = 1200, TAX_BP = 800, SIZES = ['S', 'M', 'L', 'XL'];

// ---- Database ----
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
const tx = fn => (...a) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(...a); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT DEFAULT (${NOW}));
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, club TEXT, league TEXT, type TEXT, price_cents INTEGER NOT NULL, old_cents INTEGER, c1 TEXT, c2 TEXT, pattern TEXT, tag TEXT, stock INTEGER NOT NULL DEFAULT 100);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending', email TEXT, name TEXT, phone TEXT, addr TEXT, city TEXT, zip TEXT, ship TEXT, subtotal INTEGER, shipping INTEGER, tax INTEGER, total INTEGER, card_last4 TEXT, stripe_session TEXT, created_at TEXT DEFAULT (${NOW}));
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL, size TEXT, qty INTEGER, print_text TEXT, unit_cents INTEGER);
CREATE INDEX IF NOT EXISTS ix_orders_user ON orders(user_id);`);
if (!db.prepare('SELECT COUNT(*) n FROM products').get().n) {
  const ins = db.prepare('INSERT INTO products(name,club,league,type,price_cents,old_cents,c1,c2,pattern,tag) VALUES(?,?,?,?,?,?,?,?,?,?)');
  [['Northgate Home', 'Northgate United', 'Premier', 'Home', 89, 0, '#c8102e', '#ffffff', 'stripes', 'New'],
   ['Northgate Away', 'Northgate United', 'Premier', 'Away', 89, 0, '#111827', '#ffd23f', 'plain', null],
   ['Rivermoor Home', 'FC Rivermoor', 'Premier', 'Home', 85, 0, '#1b6dff', '#ffffff', 'half', 'New'],
   ['Rivermoor Third', 'FC Rivermoor', 'Premier', 'Third', 85, 99, '#ffd23f', '#1b2a6b', 'sash', null],
   ['Costa Home', 'Real Costa', 'La Liga', 'Home', 92, 0, '#f4f4f4', '#1b2a6b', 'plain', 'Bestseller'],
   ['Costa Away', 'Real Costa', 'La Liga', 'Away', 92, 0, '#7a1fa2', '#e8c6ff', 'hoops', null],
   ['Solano Home', 'Atletico Solano', 'La Liga', 'Home', 88, 0, '#e11d2e', '#ffffff', 'stripes', null],
   ['Solano Retro 1996', 'Atletico Solano', 'La Liga', 'Retro', 75, 0, '#ffffff', '#e11d2e', 'hoops', 'Retro'],
   ['Tiger Home', 'Sao Tigre', 'Samba', 'Home', 79, 0, '#ffd23f', '#0b8f3c', 'plain', 'New'],
   ['Tiger Away', 'Sao Tigre', 'Samba', 'Away', 79, 0, '#0b8f3c', '#ffd23f', 'sash', null],
   ['Ferro Home', 'Ferro Torino', 'Calcio', 'Home', 86, 96, '#7b1e3a', '#f2c14e', 'half', null],
   ['Ferro Training', 'Ferro Torino', 'Calcio', 'Training', 55, 0, '#2a2f45', '#ff6a3d', 'plain', null]]
    .forEach(r => ins.run(r[0], r[1], r[2], r[3], r[4] * 100, r[5] ? r[5] * 100 : null, r[6], r[7], r[8], r[9]));
}

// ---- Helpers ----
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const safeEq = (a = '', b = '') => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const shapeProduct = p => ({ id: p.id, n: p.name, c: p.club, l: p.league, t: p.type, p: p.price_cents / 100, col: [p.c1, p.c2], pat: p.pattern, tag: p.tag || undefined, old: p.old_cents ? p.old_cents / 100 : undefined, stock: p.stock });
const shapeOrder = o => ({
  id: o.id, status: o.status, date: o.created_at, email: o.email, ship: o.ship === 'express' ? 'Express' : 'Standard', card: o.card_last4,
  to: { name: o.name, addr: o.addr, city: o.city, zip: o.zip },
  items: db.prepare('SELECT product_id id, size s, qty q, print_text x FROM order_items WHERE order_id=?').all(o.id),
  t: { s: o.subtotal / 100, shp: o.shipping / 100, tax: o.tax / 100, t: o.total / 100 }
});

// ---- App & security ----
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"],
  upgradeInsecureRequests: prod ? [] : null } } }));

const limiter = (limit) => rateLimit({ windowMs: 15 * 60 * 1000, limit, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Try again in a few minutes.' } });

// Stripe webhook needs the raw body, so it is registered before express.json().
const markPaid = tx(id => {
  const o = db.prepare('SELECT status FROM orders WHERE id=?').get(id);
  if (!o || o.status !== 'pending') return; // idempotent
  db.prepare("UPDATE orders SET status='paid' WHERE id=?").run(id);
  for (const i of db.prepare('SELECT product_id, qty FROM order_items WHERE order_id=?').all(id))
    db.prepare('UPDATE products SET stock=MAX(stock-?,0) WHERE id=?').run(i.qty, i.product_id);
});
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.sendStatus(404);
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET); }
  catch { return res.status(400).send('Invalid signature'); }
  const s = ev.data.object;
  if ((ev.type === 'checkout.session.completed' || ev.type === 'checkout.session.async_payment_succeeded') && s.payment_status === 'paid') markPaid(s.metadata && s.metadata.order_id);
  res.json({ received: true });
});

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use('/api', limiter(300));
app.use('/api', (req, res, next) => { // CSRF defence: state changes must be JSON (+ SameSite cookie)
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !req.is('json')) return next(httpErr(415, 'Requests must be JSON.'));
  next();
});

// ---- Auth ----
const setSession = (res, u) => res.cookie('tk', jwt.sign({ sub: u.id }, SECRET, { expiresIn: '7d' }), { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 7 * 864e5 });
app.use((req, res, next) => {
  req.user = null;
  try { const { sub } = jwt.verify(req.cookies.tk, SECRET); req.user = db.prepare('SELECT id,email,name FROM users WHERE id=?').get(sub) || null; } catch { /* anonymous */ }
  next();
});
const need = (req, res, next) => req.user ? next() : next(httpErr(401, 'Please log in.'));
const DUMMY = bcrypt.hashSync('not-a-real-password', 10);
const emailOk = e => typeof e === 'string' && e.length <= 120 && /^\S+@\S+\.\S+$/.test(e);

app.post('/api/auth/register', limiter(20), wrap(async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!emailOk(email)) throw httpErr(400, 'Enter a valid email address.');
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 60) throw httpErr(400, 'Enter your full name.');
  if (typeof password !== 'string' || password.length < 8 || password.length > 100) throw httpErr(400, 'Use a password with at least 8 characters.');
  const em = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(em)) throw httpErr(409, 'That email already has an account. Log in instead.');
  const id = db.prepare('INSERT INTO users(email,name,pw_hash) VALUES(?,?,?)').run(em, name.trim(), await bcrypt.hash(password, 12)).lastInsertRowid;
  const user = { id, email: em, name: name.trim() };
  setSession(res, user); res.status(201).json({ user: { email: em, name: user.name } });
}));
app.post('/api/auth/login', limiter(20), wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const u = emailOk(email) ? db.prepare('SELECT * FROM users WHERE email=?').get(email.trim().toLowerCase()) : null;
  const ok = await bcrypt.compare(String(password || ''), u ? u.pw_hash : DUMMY);
  if (!u || !ok) throw httpErr(401, 'Email or password is incorrect.');
  setSession(res, u); res.json({ user: { email: u.email, name: u.name } });
}));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('tk'); res.json({ ok: true }); });
app.get('/api/auth/me', (req, res) => res.json({ user: req.user ? { email: req.user.email, name: req.user.name } : null }));

// ---- Catalogue & config ----
app.get('/api/config', (req, res) => res.json({ payments: stripe ? 'stripe' : 'mock', currency: CURRENCY }));
app.get('/api/products', (req, res) => res.json({ products: db.prepare('SELECT * FROM products ORDER BY id').all().map(shapeProduct) }));

// ---- Checkout ----
function priceCart(items) {
  if (!Array.isArray(items) || !items.length || items.length > 20) throw httpErr(400, 'Your cart is empty.');
  let sub = 0; const lines = [];
  for (const it of items) {
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(Number(it.id)), q = Number(it.q);
    if (!p || !SIZES.includes(it.s) || !Number.isInteger(q) || q < 1 || q > 9) throw httpErr(400, 'One of the items in your cart is not valid.');
    const x = String(it.x || '').trim().toUpperCase().slice(0, 14);
    if (x && !/^[A-Z0-9 .'-]+$/.test(x)) throw httpErr(400, 'Name and number can only use letters, numbers and spaces.');
    const unit = p.price_cents + (x ? PRINT : 0); sub += unit * q; lines.push({ p, s: it.s, q, x, unit });
  }
  return { lines, sub };
}
function checkContact(c) {
  const s = (v, min, max = 120) => typeof v === 'string' && v.trim().length >= min && v.length <= max;
  if (!emailOk(c.email)) return 'Enter a valid email address.';
  if (!s(c.name, 2, 80)) return 'Enter the recipient name.';
  if (typeof c.phone !== 'string' || !/^[+\d][\d\s-]{6,19}$/.test(c.phone)) return 'Enter a phone number for the courier.';
  if (!s(c.addr, 6, 200)) return 'Enter your street address.';
  if (!s(c.city, 2, 80)) return 'Enter your city.';
  if (typeof c.zip !== 'string' || !/^[\w\s-]{4,10}$/.test(c.zip)) return 'Enter a valid PIN or ZIP code.';
}
app.post('/api/checkout', limiter(40), wrap(async (req, res) => {
  const { items, contact: c = {}, ship, last4 } = req.body || {};
  const { lines, sub } = priceCart(items);
  const bad = checkContact(c); if (bad) throw httpErr(400, bad);
  const fast = ship === 'express';
  const shipping = fast ? EXP : (sub >= FREE_OVER ? 0 : STD), tax = Math.round(sub * TAX_BP / 10000), total = sub + shipping + tax;
  const want = new Map(); lines.forEach(l => want.set(l.p.id, (want.get(l.p.id) || 0) + l.q));
  for (const l of lines) if (want.get(l.p.id) > l.p.stock) throw httpErr(409, `${l.p.name} has only ${l.p.stock} left in stock.`);
  if (!stripe && last4 === '0002') throw httpErr(402, 'Your card was declined. Try a different card.');

  const id = 'TK-' + crypto.randomBytes(6).toString('hex').toUpperCase();
  tx(() => {
    db.prepare('INSERT INTO orders(id,user_id,email,name,phone,addr,city,zip,ship,subtotal,shipping,tax,total,card_last4) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, req.user ? req.user.id : null, c.email.trim().toLowerCase(), c.name.trim(), c.phone.trim(), c.addr.trim(), c.city.trim(), c.zip.trim(), fast ? 'express' : 'standard', sub, shipping, tax, total, /^\d{4}$/.test(last4 || '') ? last4 : null);
    const ii = db.prepare('INSERT INTO order_items(order_id,product_id,size,qty,print_text,unit_cents) VALUES(?,?,?,?,?,?)');
    lines.forEach(l => ii.run(id, l.p.id, l.s, l.q, l.x || null, l.unit));
  })();

  if (!stripe) { markPaid(id); return res.json({ orderId: id, paid: true }); } // test mode: no real payment
  const extra = (name, amt) => amt > 0 ? [{ quantity: 1, price_data: { currency: CURRENCY, unit_amount: amt, product_data: { name } } }] : [];
  const session = await stripe.checkout.sessions.create({
    mode: 'payment', customer_email: c.email.trim(), client_reference_id: id, metadata: { order_id: id },
    line_items: [...lines.map(l => ({ quantity: l.q, price_data: { currency: CURRENCY, unit_amount: l.unit, product_data: { name: `${l.p.name} (${l.s})${l.x ? ' - ' + l.x : ''}` } } })),
      ...extra(fast ? 'Express delivery' : 'Standard delivery', shipping), ...extra('Estimated tax', tax)],
    success_url: `${BASE_URL}/?done=1#/order/${id}`, cancel_url: `${BASE_URL}/#/checkout`
  });
  db.prepare('UPDATE orders SET stripe_session=? WHERE id=?').run(session.id, id);
  res.json({ orderId: id, url: session.url });
}));

// ---- Orders ----
app.get('/api/orders', need, (req, res) =>
  res.json({ orders: db.prepare("SELECT * FROM orders WHERE user_id=? AND status<>'pending' ORDER BY created_at DESC LIMIT 50").all(req.user.id).map(shapeOrder) }));
app.get('/api/orders/:id', (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(String(req.params.id).slice(0, 30));
  // Guest orders are readable by their unguessable id; account orders only by their owner.
  if (!o || (o.user_id && (!req.user || req.user.id !== o.user_id))) return res.status(404).json({ error: 'Order not found.' });
  res.json({ order: shapeOrder(o) });
});

// ---- Admin (header: x-admin-key). The panel itself is public/admin.html at /admin ----
app.use('/api/admin', limiter(150));
const admin = (req, res, next) => ADMIN_KEY && safeEq(req.get('x-admin-key') || '', ADMIN_KEY) ? next() : next(httpErr(403, 'Forbidden.'));
app.get('/api/admin/orders', admin, (req, res) => res.json({ orders: db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200').all().map(o => ({ ...shapeOrder(o), phone: o.phone })) }));
app.patch('/api/admin/orders/:id', admin, (req, res) => {
  const { status } = req.body || {};
  if (!['paid', 'shipped', 'delivered', 'cancelled'].includes(status)) throw httpErr(400, 'Invalid status.');
  if (!db.prepare('UPDATE orders SET status=? WHERE id=?').run(status, req.params.id).changes) throw httpErr(404, 'Order not found.');
  res.json({ ok: true });
});
app.patch('/api/admin/products/:id', admin, (req, res) => {
  const { stock, price } = req.body || {};
  if (Number.isInteger(stock) && stock >= 0) db.prepare('UPDATE products SET stock=? WHERE id=?').run(stock, req.params.id);
  if (Number.isFinite(price) && price > 0) db.prepare('UPDATE products SET price_cents=? WHERE id=?').run(Math.round(price * 100), req.params.id);
  res.json({ ok: true });
});

// ---- Static site, 404s, errors ----
const ADMIN_PAGE = path.join(__dirname, 'public', 'admin.html');
app.get('/admin', (req, res) => fs.existsSync(ADMIN_PAGE) ? res.sendFile(ADMIN_PAGE) : res.status(404).send('admin.html is missing from the public folder.'));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: prod ? '1h' : 0, extensions: ['html'] }));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  const status = err.status && err.status < 600 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Something went wrong on our side. Try again.' : (err.type ? 'Invalid request.' : err.message) });
});
app.listen(PORT, () => {
  console.log(`Terrace Kit Co. running at ${BASE_URL} (payments: ${stripe ? 'Stripe' : 'test mode'})`);
  console.log(`Running from folder: ${__dirname}`);
  console.log(fs.existsSync(ADMIN_PAGE) ? `Admin panel: ${BASE_URL}/admin` : 'WARNING: public/admin.html not found, the admin page will not load.');
  console.log(ADMIN_KEY ? 'Admin key: set' : 'Admin key: NOT SET. Add ADMIN_KEY to .env and restart to use the admin panel.');
});
