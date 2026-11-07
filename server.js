require('dotenv').config();
const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'future-star.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, phone TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, name TEXT NOT NULL, price INTEGER NOT NULL, old_price INTEGER DEFAULT 0, audience TEXT, category TEXT, sizes TEXT, colors TEXT, badge TEXT, description TEXT, image TEXT, stock INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, order_number TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id), items_json TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'payment_pending', payment_id TEXT, razorpay_order_id TEXT, tracking_company TEXT, tracking_number TEXT, tracking_url TEXT, return_status TEXT, return_reason TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_rzp ON orders(razorpay_order_id);
`);

const required = ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET'];
const razorpay = required.every(k => process.env[k]) ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;
const jwtSecret = process.env.JWT_SECRET;
const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminHash = process.env.ADMIN_PASSWORD_HASH || '';
const cookieName = 'fs_session';
const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 };

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.path.startsWith('/api/') && req.get('origin')) {
    let allowed = ''; try { allowed = process.env.SITE_URL ? new URL(process.env.SITE_URL).origin : `${req.protocol}://${req.get('host')}`; } catch {}
    if (req.get('origin') !== allowed) return res.status(403).json({ error: 'Request origin is not allowed.' });
  }
  next();
});
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "https://checkout.razorpay.com"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'", 'https://api.razorpay.com'], frameSrc: ['https://api.razorpay.com', 'https://checkout.razorpay.com'], upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null } } }));
app.use(cookieParser());
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-7', legacyHeaders: false }));
app.post('/api/razorpay-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return res.status(503).send('Webhook secret is not configured');
  const signature = req.get('x-razorpay-signature') || '';
  const expected = crypto.createHmac('sha256', secret).update(req.body).digest('hex');
  const a = Buffer.from(expected); const b = Buffer.from(signature);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).send('Invalid signature');
  try {
    const event = JSON.parse(req.body.toString('utf8'));
    if (event.event === 'payment.captured') {
      const p = event.payload?.payment?.entity;
      if (p?.order_id) {
        const target = db.prepare("SELECT * FROM orders WHERE razorpay_order_id=? AND status='payment_pending'").get(p.order_id);
        if (target) {
          const settle = db.transaction(() => {
            db.prepare("UPDATE orders SET status='paid',payment_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='payment_pending'").run(p.id, target.id);
            for (const item of JSON.parse(target.items_json)) {
              const stock = db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(item.quantity, item.id, item.quantity);
              if (!stock.changes) db.prepare("UPDATE orders SET status='paid_stock_issue' WHERE id=?").run(target.id);
            }
          }); settle();
        }
      }
    }
    if (event.event === 'payment.failed') {
      const p = event.payload?.payment?.entity;
      if (p?.order_id) db.prepare("UPDATE orders SET status='payment_failed', updated_at=CURRENT_TIMESTAMP WHERE razorpay_order_id=? AND status='payment_pending'").run(p.order_id);
    }
    return res.json({ received: true });
  } catch { return res.status(400).send('Invalid webhook payload'); }
});
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function signIn(res, user) {
  if (!jwtSecret) throw new Error('JWT_SECRET is not configured');
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, jwtSecret, { expiresIn: '7d', issuer: 'future-star' });
  res.cookie(cookieName, token, cookieOptions);
}
function auth(req, res, next) {
  try {
    if (!jwtSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
    const token = req.cookies[cookieName];
    if (!token) return res.status(401).json({ error: 'Please sign in first.' });
    req.user = jwt.verify(token, jwtSecret, { issuer: 'future-star' });
    const current = db.prepare('SELECT id,name,email,phone,role FROM users WHERE id=?').get(req.user.id);
    if (!current || current.role !== req.user.role) return res.status(401).json({ error: 'Session is no longer valid.' });
    req.account = current; next();
  } catch { return res.status(401).json({ error: 'Please sign in again.' }); }
}
function customer(req, res, next) { auth(req, res, () => req.account.role === 'customer' ? next() : res.status(403).json({ error: 'Customer account required.' })); }
function owner(req, res, next) { auth(req, res, () => req.account.role === 'admin' ? next() : res.status(403).json({ error: 'Owner access only.' })); }
const upload = multer({ storage: multer.diskStorage({ destination: UPLOAD_DIR, filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase()) }), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) });
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', immutable: true }));

app.get('/api/health', (req, res) => res.json({ ok: true, store: 'Future Star' }));
app.get('/api/products', (req, res) => res.json(db.prepare('SELECT id,name,price,old_price AS oldPrice,audience,category,sizes,colors,badge,description,image,stock FROM products WHERE active=1 ORDER BY created_at DESC').all()));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });
app.post('/api/auth/register', loginLimiter, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    if (!name?.trim() || !/^\S+@\S+\.\S+$/.test(String(email || '')) || !/^\d{10}$/.test(String(phone || '').replace(/\D/g, '')) || String(password || '').length < 10) return res.status(400).json({ error: 'Enter your name, valid email, 10-digit phone and a password of at least 10 characters.' });
    if (adminEmail && String(email).trim().toLowerCase() === adminEmail) return res.status(403).json({ error: 'This email is reserved for the store owner.' });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'customer')").run(name.trim(), email.trim().toLowerCase(), String(phone).replace(/\D/g, ''), hash);
    const user = db.prepare('SELECT id,name,email,phone,role FROM users WHERE id=?').get(result.lastInsertRowid); signIn(res, user); res.json({ user });
  } catch (e) { res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ error: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'An account with this email already exists.' : 'Could not create account.' }); }
});
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {}; const user = db.prepare("SELECT * FROM users WHERE email=? AND role='customer'").get(String(email || '').trim().toLowerCase());
  if (!user || !await bcrypt.compare(String(password || ''), user.password_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  const safe = { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role }; signIn(res, safe); res.json({ user: safe });
});
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  if (!adminEmail || !adminHash || !jwtSecret) return res.status(503).json({ error: 'Owner login is not configured. Set ADMIN_EMAIL, ADMIN_PASSWORD_HASH and JWT_SECRET.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (email !== adminEmail) return res.status(401).json({ error: 'Owner email or password is incorrect.' });
  let stored = db.prepare("SELECT * FROM users WHERE email=? AND role='admin'").get(adminEmail);
  // First successful setup bootstraps the owner from the private hosting environment hash.
  if (!stored) {
    const result = db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES('Future Star Owner',?,'',?,'admin')").run(adminEmail, adminHash);
    stored = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
  }
  if (!await bcrypt.compare(String(req.body?.password || ''), stored.password_hash)) return res.status(401).json({ error: 'Owner email or password is incorrect.' });
  const user = { id: stored.id, name: stored.name, email: stored.email, phone: stored.phone, role: stored.role };
  signIn(res, user); res.json({ user });
});
app.post('/api/admin/change-password', owner, loginLimiter, async (req, res) => {
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (newPassword.length < 12) return res.status(400).json({ error: 'Choose a new password with at least 12 characters.' });
  const stored = db.prepare("SELECT id,password_hash FROM users WHERE id=? AND role='admin'").get(req.account.id);
  if (!stored || !await bcrypt.compare(currentPassword, stored.password_hash)) return res.status(401).json({ error: 'Current password is incorrect.' });
  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, stored.id);
  res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined });
  res.json({ ok: true, message: 'Password changed. Please sign in again.' });
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.account }));
app.post('/api/auth/logout', (req, res) => { res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined }); res.json({ ok: true }); });

app.post('/api/admin/products', owner, upload.single('image'), (req, res) => {
  try {
    const b = req.body; const price = Number(b.price), stock = Number(b.stock);
    if (!b.name?.trim() || !Number.isInteger(price) || price < 1 || !Number.isInteger(stock) || stock < 0) return res.status(400).json({ error: 'Product name, whole-number price and stock are required.' });
    const id = b.id || crypto.randomUUID(); const old = db.prepare('SELECT image FROM products WHERE id=?').get(id);
    const image = req.file ? '/uploads/' + req.file.filename : (old?.image || b.image || '');
    db.prepare(`INSERT INTO products(id,name,price,old_price,audience,category,sizes,colors,badge,description,image,stock,active) VALUES(@id,@name,@price,@old_price,@audience,@category,@sizes,@colors,@badge,@description,@image,@stock,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name,price=excluded.price,old_price=excluded.old_price,audience=excluded.audience,category=excluded.category,sizes=excluded.sizes,colors=excluded.colors,badge=excluded.badge,description=excluded.description,image=excluded.image,stock=excluded.stock,active=1`).run({ id, name: b.name.trim(), price, old_price: Number(b.oldPrice) || 0, audience: b.audience || 'Unisex', category: b.category || 'Other', sizes: b.sizes || '', colors: b.colors || '', badge: b.badge || '', description: b.description || '', image, stock });
    res.json({ ok: true, product: db.prepare('SELECT * FROM products WHERE id=?').get(id) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save product.' }); }
});
app.delete('/api/admin/products/:id', owner, (req, res) => { db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); res.json({ ok: true }); });
app.get('/api/admin/orders', owner, (req, res) => res.json(db.prepare(`SELECT o.*,u.name customer_name,u.email customer_email,u.phone customer_phone FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 300`).all().map(o => ({ ...o, items: JSON.parse(o.items_json) }))));
app.patch('/api/admin/orders/:id', owner, (req, res) => {
  const { status, trackingCompany, trackingNumber, trackingUrl } = req.body || {};
  const allowed = ['processing','shipped','out_for_delivery','delivered','cancelled'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid order status.' });
  if (trackingUrl && !/^https:\/\//i.test(trackingUrl)) return res.status(400).json({ error: 'Tracking link must use HTTPS.' });
  const result = db.prepare('UPDATE orders SET status=?,tracking_company=?,tracking_number=?,tracking_url=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, trackingCompany || '', trackingNumber || '', trackingUrl || '', req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Order not found.' }); res.json({ ok: true });
});
app.get('/api/orders', customer, (req, res) => res.json(db.prepare('SELECT id,order_number,items_json,amount,status,payment_id,tracking_company,tracking_number,tracking_url,return_status,return_reason,created_at,updated_at FROM orders WHERE user_id=? ORDER BY id DESC').all(req.account.id).map(o => ({ ...o, items: JSON.parse(o.items_json) }))));
app.post('/api/orders/:id/return', customer, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(req.params.id, req.account.id);
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (order.status !== 'delivered') return res.status(400).json({ error: 'Return requests are available only after delivery.' });
  if (order.return_status) return res.status(409).json({ error: 'A return request already exists for this order.' });
  const reason = String(req.body?.reason || '').trim().slice(0, 500); if (!reason) return res.status(400).json({ error: 'Please provide a return reason.' });
  db.prepare("UPDATE orders SET return_status='requested',return_reason=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(reason, order.id); res.json({ ok: true });
});
app.post('/api/admin/orders/:id/refund', owner, async (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if (!order || !order.payment_id || !razorpay) return res.status(400).json({ error: 'A captured Razorpay payment is required to process a refund.' });
  try {
    const refund = await razorpay.payments.refund(order.payment_id, { amount: order.amount * 100, notes: { order_number: order.order_number, reason: 'Future Star return/refund request' } });
    db.prepare("UPDATE orders SET status='refunded',return_status='refunded',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(order.id); res.json({ ok: true, refundId: refund.id });
  } catch (e) { console.error(e); res.status(502).json({ error: 'Razorpay could not process the refund. Check the payment dashboard.' }); }
});

app.post('/api/create-order', customer, async (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error: 'Razorpay is not configured. Use test keys after merchant setup.' });
    const items = req.body?.items;
    if (!Array.isArray(items) || !items.length || items.length > 30) return res.status(400).json({ error: 'Your cart is empty or invalid.' });
    const getProduct = db.prepare('SELECT id,name,price,stock,active FROM products WHERE id=?');
    const normalized = []; let amount = 0;
    for (const item of items) {
      const p = getProduct.get(String(item.id)); const qty = Math.max(1, Math.min(10, Number(item.quantity) || 1));
      if (!p || !p.active || p.stock < qty) return res.status(400).json({ error: `Not enough stock for ${p?.name || 'one item'}.` });
      amount += p.price * qty; normalized.push({ id: p.id, name: p.name, price: p.price, quantity: qty });
    }
    if (!Number.isSafeInteger(amount) || amount < 1 || amount > 500000) return res.status(400).json({ error: 'Order total is outside the allowed range.' });
    const orderNumber = 'FS' + Date.now().toString().slice(-8) + crypto.randomBytes(2).toString('hex').toUpperCase();
    const local = db.prepare("INSERT INTO orders(order_number,user_id,items_json,amount,status) VALUES(?,?,?,?,'payment_pending')").run(orderNumber, req.account.id, JSON.stringify(normalized), amount);
    const rzp = await razorpay.orders.create({ amount: amount * 100, currency: 'INR', receipt: orderNumber });
    db.prepare('UPDATE orders SET razorpay_order_id=? WHERE id=?').run(rzp.id, local.lastInsertRowid);
    res.json({ orderId: rzp.id, amount: rzp.amount, currency: rzp.currency, keyId: process.env.RAZORPAY_KEY_ID, localOrderId: local.lastInsertRowid, orderNumber });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Unable to create payment order.' }); }
});
app.post('/api/verify-payment', customer, (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, localOrderId } = req.body || {};
    const order = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(localOrderId, req.account.id);
    if (!order || order.razorpay_order_id !== razorpay_order_id || !razorpay_payment_id || !razorpay_signature) return res.status(400).json({ verified: false, error: 'Payment details do not match your order.' });
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '').update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
    const a = Buffer.from(expected, 'hex'), b = Buffer.from(String(razorpay_signature), 'hex');
    if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).json({ verified: false, error: 'Invalid payment signature.' });
    const settle = db.transaction(() => {
      const changed = db.prepare("UPDATE orders SET status='paid',payment_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='payment_pending'").run(razorpay_payment_id, order.id).changes;
      if (changed) {
        for (const item of JSON.parse(order.items_json)) {
          const stock = db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(item.quantity, item.id, item.quantity);
          if (!stock.changes) { db.prepare("UPDATE orders SET status='paid_stock_issue' WHERE id=?").run(order.id); throw new Error('Payment received but inventory needs owner review. Contact support before placing another order.'); }
        }
      }
    });
    settle();
    res.json({ verified: true, paymentId: razorpay_payment_id, orderNumber: order.order_number });
  } catch (e) { console.error(e); res.status(500).json({ verified: false, error: 'Payment verification error.' }); }
});

app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: ' + (process.env.SITE_URL || 'https://YOUR-DOMAIN.example') + '/sitemap.xml\n'));
app.get('/sitemap.xml', (req, res) => { const base = (process.env.SITE_URL || 'https://YOUR-DOMAIN.example').replace(/\/$/, ''); res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${base}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url></urlset>`); });
app.listen(PORT, () => console.log(`Future Star running on port ${PORT}`));
