import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import Stripe from 'stripe';

const db = new Database(process.env.DB_PATH || 'lexora.db');
db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists firms(id integer primary key, name text, created text default current_timestamp);
create table if not exists users(id integer primary key, firm_id int, email text unique, hash text, created text default current_timestamp);
create table if not exists sessions(token text primary key, user_id int, exp int);
create table if not exists state(firm_id int primary key, json text not null, v int not null default 0);
create table if not exists audit(id integer primary key, firm_id int, user_id int, action text, at text default current_timestamp);`);

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const BASE = process.env.BASE_URL || 'http://localhost:3000';
const prod = process.env.NODE_ENV === 'production';
const audit = (f, u, a) => db.prepare('insert into audit(firm_id,user_id,action) values(?,?,?)').run(f, u, a);
const hash = p => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const verify = (p, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(p, Buffer.from(s, 'hex'), 64), Buffer.from(k, 'hex')); };
const cookie = (req, n) => (req.headers.cookie || '').split(/;\s*/).map(c => c.split('=')).find(c => c[0] === n)?.[1];

function startSession(res, uid) {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('insert into sessions values(?,?,?)').run(t, uid, Date.now() + 14 * 864e5);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600${prod ? '; Secure' : ''}`);
}
const needAuth = (req, res, next) => {
  const t = cookie(req, 'sid');
  const u = t && db.prepare('select u.id,u.firm_id,u.email from sessions s join users u on u.id=s.user_id where s.token=? and s.exp>?').get(t, Date.now());
  if (!u) return res.status(401).json({ error: 'Not signed in' });
  req.u = u; next();
};
const tries = new Map();
const throttle = (req, res, next) => {
  const k = req.ip + (req.body?.email || ''), now = Date.now(), a = (tries.get(k) || []).filter(x => now - x < 9e5);
  if (a.length >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  a.push(now); tries.set(k, a); next();
};

// Server-side trust integrity: history is append-only and no client ledger may go negative.
function checkTrust(o, n) {
  const ot = o.trust || [], nt = n.trust;
  if (!Array.isArray(nt)) return 'Invalid state';
  for (let i = 0; i < ot.length; i++) {
    const a = ot[i], b = nt[i];
    if (!b || ['id', 'cid', 'amt', 'memo', 'date', 'rev'].some(k => a[k] !== b[k])) return 'Trust history is immutable. Post a reversing entry instead.';
  }
  const bal = {};
  for (const t of nt) {
    if (!Number.isFinite(t.amt)) return 'Invalid trust amount';
    bal[t.cid] = Math.round(((bal[t.cid] || 0) + t.amt) * 100) / 100;
    if (bal[t.cid] < 0) return 'Rejected: a client trust balance cannot go negative.';
  }
  return null;
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  if (prod) res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe) return res.sendStatus(404);
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); } catch { return res.sendStatus(400); }
  if (ev.type === 'checkout.session.completed') {
    const m = ev.data.object.metadata || {}, fid = +m.firm_id;
    const row = db.prepare('select json from state where firm_id=?').get(fid);
    if (row) {
      const s = JSON.parse(row.json), inv = (s.invoices || []).find(i => i.id == +m.invoice_id);
      if (inv && inv.status !== 'Paid') {
        inv.status = 'Paid';
        db.prepare('update state set json=?, v=v+1 where firm_id=?').run(JSON.stringify(s), fid);
        audit(fid, 0, 'invoice paid via Stripe: ' + inv.no);
      }
    }
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '2mb' }));

app.post('/api/signup', throttle, (req, res) => {
  const { email = '', password = '', firmName = '' } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email' });
  if (password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters' });
  if (db.prepare('select 1 from users where email=?').get(email.toLowerCase())) return res.status(409).json({ error: 'An account with that email already exists' });
  const uid = db.transaction(() => {
    const f = db.prepare('insert into firms(name) values(?)').run(firmName.slice(0, 120) || 'My Firm').lastInsertRowid;
    const u = db.prepare('insert into users(firm_id,email,hash) values(?,?,?)').run(f, email.toLowerCase(), hash(password)).lastInsertRowid;
    db.prepare('insert into state(firm_id,json) values(?,?)').run(f, '{}');
    audit(f, u, 'signup'); return u;
  })();
  startSession(res, uid); res.json({ ok: true });
});

app.post('/api/login', throttle, (req, res) => {
  const { email = '', password = '' } = req.body || {};
  const u = db.prepare('select * from users where email=?').get(email.toLowerCase());
  if (!u || !verify(password, u.hash)) return res.status(401).json({ error: 'Incorrect email or password' });
  audit(u.firm_id, u.id, 'login'); startSession(res, u.id); res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const t = cookie(req, 'sid'); if (t) db.prepare('delete from sessions where token=?').run(t);
  res.set('Set-Cookie', 'sid=; Path=/; Max-Age=0'); res.json({ ok: true });
});

app.get('/api/me', needAuth, (req, res) => res.json({ email: req.u.email, stripe: !!stripe }));

app.get('/api/state', needAuth, (req, res) => {
  const r = db.prepare('select json,v from state where firm_id=?').get(req.u.firm_id);
  res.json({ state: JSON.parse(r.json), v: r.v });
});

app.put('/api/state', needAuth, (req, res) => {
  const { v, state } = req.body || {};
  if (!state || typeof state !== 'object') return res.status(400).json({ error: 'Invalid state' });
  const cur = db.prepare('select json,v from state where firm_id=?').get(req.u.firm_id);
  if (v !== cur.v) return res.status(409).json({ error: 'Updated elsewhere. Reloaded the latest data.' });
  const old = JSON.parse(cur.json);
  if (state.trust || old.trust) {
    state.trust = state.trust || [];
    const err = checkTrust(old, state);
    if (err) return res.status(422).json({ error: err });
    if (state.trust.length !== (old.trust || []).length) audit(req.u.firm_id, req.u.id, 'trust transactions +' + (state.trust.length - (old.trust || []).length));
  }
  db.prepare('update state set json=?, v=v+1 where firm_id=?').run(JSON.stringify(state), req.u.firm_id);
  res.json({ v: cur.v + 1 });
});

app.post('/api/checkout', needAuth, async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'Stripe is not configured' });
  try {
    const s = JSON.parse(db.prepare('select json from state where firm_id=?').get(req.u.firm_id).json);
    const inv = (s.invoices || []).find(i => i.id == req.body?.invoiceId);
    if (!inv || inv.status === 'Paid') return res.status(404).json({ error: 'Invoice not payable' });
    const ses = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ quantity: 1, price_data: { currency: 'cad', unit_amount: Math.round((inv.sub + inv.tax) * 100), product_data: { name: 'Legal fees – ' + inv.no } } }],
      metadata: { firm_id: String(req.u.firm_id), invoice_id: String(inv.id) },
      success_url: BASE + '/?paid=1#invoices', cancel_url: BASE + '/#invoices'
    });
    res.json({ url: ses.url });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not start checkout' }); }
});

app.get('/healthz', (_, res) => res.send('ok'));
app.use(express.static('public'));
app.listen(process.env.PORT || 3000, () => console.log('Lexora listening'));
