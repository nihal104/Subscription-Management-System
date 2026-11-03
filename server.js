const express = require('express');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

pg.types.setTypeParser(1082, v => v);                 // keep DATE as 'YYYY-MM-DD'
pg.types.setTypeParser(1700, v => parseFloat(v));     // NUMERIC as number
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const SECRET = process.env.JWT_SECRET || 'change-me';
const app = express();
// Records a payment safely; the note makes repeat webhook deliveries harmless.
async function recordPayment(invoiceId, method, amount, note, userId = null) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const inv = (await c.query(`SELECT * FROM invoices WHERE id=$1 FOR UPDATE`, [invoiceId])).rows[0];
    if (!inv || inv.status !== 'Confirmed') { await c.query('ROLLBACK'); return false; }
    if ((await c.query(`SELECT 1 FROM payments WHERE invoice_id=$1 AND note=$2`, [invoiceId, note])).rowCount) { await c.query('ROLLBACK'); return true; }
    const paid = (await c.query(`SELECT COALESCE(sum(amount),0) AS s FROM payments WHERE invoice_id=$1`, [invoiceId])).rows[0].s;
    const amt = Math.min(amount, round(inv.total - paid));
    if (!(amt > 0)) { await c.query('ROLLBACK'); return false; }
    await c.query(`INSERT INTO payments(invoice_id,method,amount,note,created_by) VALUES($1,$2,$3,$4,$5)`, [invoiceId, method, amt, note, userId]);
    if (round(paid + amt) >= inv.total) await c.query(`UPDATE invoices SET status='Paid' WHERE id=$1`, [invoiceId]);
    await c.query('COMMIT'); return true;
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}

// Stripe tells us a card payment finished. Needs the raw body to check the signature, so it comes before express.json().
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), wrap(async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const sig = Object.fromEntries((req.headers['stripe-signature'] || '').split(',').map(p => p.split('=')));
  const expected = crypto.createHmac('sha256', secret || '').update(`${sig.t}.${req.body}`).digest('hex');
  const ok = secret && sig.v1 && sig.v1.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig.v1), Buffer.from(expected));
  if (!ok) return res.status(400).end();
  const ev = JSON.parse(req.body);
  if (ev.type === 'checkout.session.completed') {
    const o = ev.data.object;
    await recordPayment(+o.metadata.invoice_id, 'Card (Stripe)', o.amount_total / 100, o.id);
  }
  res.json({ received: true });
}));

app.use(express.json());
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static('public'));            // serves the web app from /public

const wrap = f => (req, res, next) => f(req, res, next).catch(next);
const q = (t, p) => pool.query(t, p);
const round = n => Math.round(n * 100) / 100;
const INTERVAL = { daily: '1 day', weekly: '7 days', monthly: '1 month', yearly: '1 year' };
const pwOk = p => typeof p === 'string' && p.length > 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[^A-Za-z0-9]/.test(p);

// Sends through Resend when RESEND_API_KEY is set; otherwise prints to the log (handy in development)
async function sendMail(to, subject, text) {
  if (!process.env.RESEND_API_KEY) return console.log(`MAIL to ${to}: ${subject}\n${text}`);
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.MAIL_FROM || 'Brightloop <onboarding@resend.dev>', to, subject, text })
  });
  if (!r.ok) console.error('Email failed with status', r.status);
}

// ---------- auth ----------
const auth = (...roles) => (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(t, SECRET);
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
    next();
  } catch { res.status(401).json({ error: 'Sign in required' }); }
};
const token = u => jwt.sign({ id: u.id, role: u.role, cid: u.cid || null }, SECRET, { expiresIn: '8h' });

app.post('/auth/signup', wrap(async (req, res) => {
  const { email, password, name } = req.body;
  if (!/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Enter a valid email.' });
  if (!pwOk(password)) return res.status(400).json({ error: 'Password needs more than 8 characters, with an uppercase letter, a lowercase letter and a special character.' });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const hash = await bcrypt.hash(password, 10);
    const u = await c.query(`INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,role`, [email, hash]);
    const cu = await c.query(`INSERT INTO customers(user_id,name) VALUES($1,$2) RETURNING id`, [u.rows[0].id, name || email.split('@')[0]]);
    await c.query('COMMIT');
    res.status(201).json({ token: token({ ...u.rows[0], cid: cu.rows[0].id }) });
  } catch (e) {
    await c.query('ROLLBACK');
    if (e.code === '23505') return res.status(409).json({ error: 'That email already has an account.' });
    throw e;
  } finally { c.release(); }
}));

app.post('/auth/login', wrap(async (req, res) => {
  const { rows } = await q(`SELECT u.id,u.role,u.password_hash,c.id AS cid FROM users u LEFT JOIN customers c ON c.user_id=u.id WHERE u.email=$1`, [req.body.email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  res.json({ token: token(u), role: u.role });
}));

app.post('/auth/forgot', wrap(async (req, res) => {
  const { rows } = await q(`SELECT id FROM users WHERE email=$1`, [req.body.email]);
  if (rows[0]) {
    const raw = crypto.randomBytes(32).toString('hex');
    await q(`INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')`,
      [rows[0].id, crypto.createHash('sha256').update(raw).digest('hex')]);
    sendMail(req.body.email, 'Reset your password', `Choose a new password (link works for one hour): ${process.env.APP_URL || ''}/?reset=${raw}`);
  }
  res.json({ ok: true });                              // same answer whether or not the email exists
}));

app.post('/auth/reset', wrap(async (req, res) => {
  if (!pwOk(req.body.password)) return res.status(400).json({ error: 'Password does not meet the rules.' });
  const h = crypto.createHash('sha256').update(req.body.token || '').digest('hex');
  const { rows } = await q(`UPDATE password_resets SET used=true WHERE token_hash=$1 AND used=false AND expires_at>now() RETURNING user_id`, [h]);
  if (!rows[0]) return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
  await q(`UPDATE users SET password_hash=$1 WHERE id=$2`, [await bcrypt.hash(req.body.password, 10), rows[0].user_id]);
  res.json({ ok: true });
}));

app.post('/staff', auth('admin'), wrap(async (req, res) => {   // only admin adds staff
  if (!pwOk(req.body.password)) return res.status(400).json({ error: 'Password does not meet the rules.' });
  const { rows } = await q(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'staff') RETURNING id,email`,
    [req.body.email, await bcrypt.hash(req.body.password, 10)]).catch(e => { if (e.code === '23505') return { rows: [] }; throw e; });
  rows[0] ? res.status(201).json(rows[0]) : res.status(409).json({ error: 'That email already has an account.' });
}));

// ---------- catalog ----------
app.get('/products', auth(), wrap(async (req, res) => res.json((await q(
  `SELECT p.*, COALESCE(json_agg(v) FILTER (WHERE v.id IS NOT NULL),'[]') AS variants FROM products p LEFT JOIN product_variants v ON v.product_id=p.id GROUP BY p.id ORDER BY p.id`)).rows)));
app.post('/products', auth('admin'), wrap(async (req, res) => {
  const b = req.body;
  const { rows } = await q(`INSERT INTO products(name,type,sales_price,cost_price,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`, [b.name, b.type, b.sales_price, b.cost_price || 0, b.notes]);
  for (const v of b.variants || []) await q(`INSERT INTO product_variants(product_id,attribute,value,extra_price) VALUES($1,$2,$3,$4)`, [rows[0].id, v.attribute, v.value, v.extra_price || 0]);
  res.status(201).json(rows[0]);
}));
app.get('/plans', auth(), wrap(async (req, res) => res.json((await q(
  `SELECT *, CASE WHEN available_to < CURRENT_DATE AND auto_close THEN 'Closed' ELSE status END AS effective_status FROM plans ORDER BY id`)).rows)));
app.post('/plans', auth('admin'), wrap(async (req, res) => {
  const b = req.body;
  const { rows } = await q(`INSERT INTO plans(name,billing_period,price,min_quantity,available_from,available_to,auto_close,allow_pause,allow_early_close,allow_renew)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [b.name, b.billing_period, b.price, b.min_quantity || 1, b.available_from, b.available_to, !!b.auto_close, !!b.allow_pause, !!b.allow_early_close, !!b.allow_renew]);
  res.status(201).json(rows[0]);
}));
app.patch('/plans/:id/status', auth('admin'), wrap(async (req, res) => {   // Open | Paused | Closed (Open = renew)
  const s = req.body.status, flag = { Paused: 'allow_pause', Closed: 'allow_early_close', Open: 'allow_renew' }[s];
  if (!flag) return res.status(400).json({ error: 'Status must be Open, Paused or Closed.' });
  const { rows } = await q(`UPDATE plans SET status=$1 WHERE id=$2 AND ${flag} RETURNING *`, [s, req.params.id]);
  rows[0] ? res.json(rows[0]) : res.status(409).json({ error: 'This plan does not allow that action.' });
}));

// ---------- taxes and discounts (admin only) ----------
app.get('/taxes', auth(), wrap(async (req, res) => res.json((await q(`SELECT * FROM taxes`)).rows)));
app.post('/taxes', auth('admin'), wrap(async (req, res) => res.status(201).json((await q(
  `INSERT INTO taxes(name,rate_pct,applies_to_type) VALUES($1,$2,$3) RETURNING *`, [req.body.name, req.body.rate_pct, req.body.applies_to_type || 'All'])).rows[0])));
app.get('/discounts', auth('admin', 'staff'), wrap(async (req, res) => res.json((await q(`SELECT * FROM discounts ORDER BY id`)).rows)));
app.post('/discounts', auth('admin'), wrap(async (req, res) => {
  const b = req.body;
  res.status(201).json((await q(`INSERT INTO discounts(code,kind,value,min_purchase,min_quantity,product_id,starts_on,ends_on,usage_limit)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`, [b.code, b.kind, b.value, b.min_purchase || 0, b.min_quantity || 1, b.product_id || null, b.starts_on || null, b.ends_on, b.usage_limit])).rows[0]);
}));

// ---------- subscriptions ----------
app.get('/subscriptions', auth(), wrap(async (req, res) => {
  const mine = req.user.role === 'customer';
  const { rows } = await q(`SELECT s.*, c.name AS customer FROM subscriptions s JOIN customers c ON c.id=s.customer_id
    WHERE ($1::text IS NULL OR s.status=$1) AND (NOT $2 OR s.customer_id=$3) ORDER BY s.id DESC LIMIT $4 OFFSET $5`,
    [req.query.status || null, mine, req.user.cid, Math.min(+req.query.limit || 25, 100), +req.query.offset || 0]);
  res.json(rows);
}));
app.post('/subscriptions', auth('admin', 'staff'), wrap(async (req, res) => {
  const b = req.body, c = await pool.connect();
  try {
    await c.query('BEGIN');
    let planId = b.plan_id, lines = b.lines || [], valid = +b.validity_days > 0 ? +b.validity_days : 30;
    if (b.template_id) {                                 // start from a quotation template
      const t = (await c.query(`SELECT * FROM quotation_templates WHERE id=$1`, [b.template_id])).rows[0];
      planId = t.plan_id; valid = +t.validity_days;
      lines = (await c.query(`SELECT product_id,variant_id,quantity FROM quotation_template_lines WHERE template_id=$1`, [t.id])).rows;
    }
    const s = (await c.query(`INSERT INTO subscriptions(customer_id,plan_id,start_date,expiry_date,payment_terms_days,next_billing_date,status,quote_valid_until)
      VALUES($1,$2,$3,$4,$5,$3,'Draft',CURRENT_DATE + $6::int) RETURNING *`, [b.customer_id, planId, b.start_date, b.expiry_date, b.payment_terms_days || 15, valid])).rows[0];
    for (const l of lines) {
      const p = (await c.query(`SELECT p.sales_price + COALESCE(v.extra_price,0) AS price FROM products p LEFT JOIN product_variants v ON v.id=$2 AND v.product_id=p.id WHERE p.id=$1`, [l.product_id, l.variant_id || null])).rows[0];
      await c.query(`INSERT INTO subscription_lines(subscription_id,product_id,variant_id,quantity,unit_price) VALUES($1,$2,$3,$4,$5)`, [s.id, l.product_id, l.variant_id || null, l.quantity, p.price]);
    }
    await c.query('COMMIT'); res.status(201).json(s);
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));
const NEXT = { Draft: 'Quotation', Quotation: 'Confirmed', Confirmed: 'Active', Active: 'Closed' };
app.patch('/subscriptions/:id/status', auth('admin', 'staff'), wrap(async (req, res) => {
  const cur = (await q(`SELECT status, (quote_valid_until < CURRENT_DATE) AS expired FROM subscriptions WHERE id=$1`, [req.params.id])).rows[0];
  if (!cur) return res.status(404).json({ error: 'Not found' });
  const to = req.body.status;
  if (cur.status === 'Quotation' && to === 'Confirmed' && cur.expired) return res.status(409).json({ error: 'This quotation has expired. Create a new one.' });
  if (to !== NEXT[cur.status] && !(to === 'Closed' && cur.status === 'Active')) return res.status(409).json({ error: `Cannot move from ${cur.status} to ${to}.` });
  res.json((await q(`UPDATE subscriptions SET status=$1 WHERE id=$2 RETURNING *`, [to, req.params.id])).rows[0]);
}));

// ---------- billing: invoices created from subscriptions ----------
async function runBilling() {
  const c = await pool.connect();
  let made = 0;
  try {
    await c.query('BEGIN');
    const today = (await c.query(`SELECT CURRENT_DATE::text AS d`)).rows[0].d;
    const subs = (await c.query(`SELECT s.*, p.billing_period FROM subscriptions s JOIN plans p ON p.id=s.plan_id
      WHERE s.status='Active' AND s.next_billing_date<=$1 AND s.next_billing_date<=s.expiry_date AND p.status='Open'
        AND NOT (p.auto_close AND p.available_to < $1::date)
      FOR UPDATE OF s SKIP LOCKED`, [today])).rows;
    const taxes = (await c.query(`SELECT * FROM taxes`)).rows;
    for (const s of subs) {
      const step = INTERVAL[s.billing_period];
      let start = s.next_billing_date, guard = 0;
      while (start <= today && start <= s.expiry_date && guard++ < 60) {
        const end = (await c.query(`SELECT ($1::date + $2::interval)::date::text AS d`, [start, step])).rows[0].d;
        const inv = (await c.query(`INSERT INTO invoices(subscription_id,customer_id,period_start,period_end,due_date)
          VALUES($1,$2,$3,$4,$3::date + $5::int) ON CONFLICT (subscription_id,period_start) DO NOTHING RETURNING id`,
          [s.id, s.customer_id, start, end, s.payment_terms_days])).rows[0];
        if (inv) {
          const lines = (await c.query(`SELECT sl.*, pr.name, pr.type FROM subscription_lines sl JOIN products pr ON pr.id=sl.product_id WHERE sl.subscription_id=$1`, [s.id])).rows;
          let sub = 0, taxGross = 0;
          for (const l of lines) {
            const amt = round(l.quantity * l.unit_price); sub += amt;
            taxGross += amt * taxes.filter(t => t.applies_to_type === 'All' || t.applies_to_type === l.type).reduce((a, t) => a + t.rate_pct, 0) / 100;
            await c.query(`INSERT INTO invoice_lines(invoice_id,description,quantity,unit_price,amount) VALUES($1,$2,$3,$4,$5)`, [inv.id, l.name, l.quantity, l.unit_price, amt]);
          }
          // discounts apply on their own until they expire or run out
          let disc = 0;
          const ds = (await c.query(`SELECT * FROM discounts WHERE active AND ends_on>=$1 AND (starts_on IS NULL OR starts_on<=$1) AND times_used<usage_limit`, [start])).rows;
          for (const d of ds) {
            const ls = d.product_id ? lines.filter(l => l.product_id === d.product_id) : lines;
            const base = ls.reduce((a, l) => a + l.quantity * l.unit_price, 0), qty = ls.reduce((a, l) => a + l.quantity, 0);
            if (!base || qty < d.min_quantity || sub < d.min_purchase) continue;
            const claim = await c.query(`UPDATE discounts SET times_used=times_used+1 WHERE id=$1 AND times_used<usage_limit`, [d.id]);
            if (!claim.rowCount) continue;
            const amt = round(d.kind === 'percent' ? base * d.value / 100 : Math.min(d.value, base)); disc += amt;
            await c.query(`INSERT INTO invoice_lines(invoice_id,description,quantity,unit_price,amount) VALUES($1,$2,1,$3,$3)`, [inv.id, 'Discount ' + d.code, -amt]);
          }
          const net = sub - disc, tax = sub ? round(net * taxGross / sub) : 0;
          await c.query(`UPDATE invoices SET subtotal=$2,discount_total=$3,tax_total=$4,total=$5 WHERE id=$1`, [inv.id, round(sub), round(disc), tax, round(net + tax)]);
          made++;
        }
        start = end;
      }
      await c.query(`UPDATE subscriptions SET next_billing_date=$2 WHERE id=$1`, [s.id, start]);
    }
    await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
  return made;
}
app.post('/billing/run', auth('admin', 'staff'), wrap(async (req, res) => res.json({ created: await runBilling() })));
setInterval(() => runBilling().catch(console.error), 60 * 60 * 1000);   // hourly safety run; use cron in production

// ---------- invoices and payments ----------
app.get('/invoices', auth(), wrap(async (req, res) => {
  const mine = req.user.role === 'customer', st = req.query.status;
  const { rows } = await q(`SELECT i.*, c.name AS customer, i.total - COALESCE((SELECT sum(amount) FROM payments WHERE invoice_id=i.id),0) AS balance,
      (i.status='Confirmed' AND i.due_date < CURRENT_DATE) AS overdue
    FROM invoices i JOIN customers c ON c.id=i.customer_id
    WHERE (NOT $1 OR i.customer_id=$2)
      AND ($3::text IS NULL OR ($3='overdue' AND i.status='Confirmed' AND i.due_date<CURRENT_DATE) OR i.status=$3)
    ORDER BY i.id DESC LIMIT $4 OFFSET $5`, [mine, req.user.cid, st || null, Math.min(+req.query.limit || 25, 100), +req.query.offset || 0]);
  res.json(rows);
}));
app.get('/invoices/:id', auth(), wrap(async (req, res) => {
  const inv = (await q(`SELECT * FROM invoices WHERE id=$1`, [req.params.id])).rows[0];
  if (!inv || (req.user.role === 'customer' && inv.customer_id !== req.user.cid)) return res.status(404).json({ error: 'Not found' });
  res.json({ ...inv, lines: (await q(`SELECT * FROM invoice_lines WHERE invoice_id=$1`, [inv.id])).rows, payments: (await q(`SELECT * FROM payments WHERE invoice_id=$1`, [inv.id])).rows });
}));
app.patch('/invoices/:id/status', auth('admin', 'staff'), wrap(async (req, res) => {   // Draft -> Confirmed, or cancel a Draft
  const ok = { Confirmed: 'Draft', Cancelled: 'Draft' }[req.body.status];
  const { rows } = await q(`UPDATE invoices SET status=$1 WHERE id=$2 AND status=$3 RETURNING *`, [req.body.status, req.params.id, ok || '']);
  rows[0] ? res.json(rows[0]) : res.status(409).json({ error: 'That change is not allowed for this invoice.' });
}));
app.post('/invoices/:id/payments', auth('admin', 'staff'), wrap(async (req, res) => {
  const { method, amount, paid_on, note } = req.body, c = await pool.connect();
  try {
    await c.query('BEGIN');
    const inv = (await c.query(`SELECT * FROM invoices WHERE id=$1 FOR UPDATE`, [req.params.id])).rows[0];
    if (!inv || inv.status !== 'Confirmed') { await c.query('ROLLBACK'); return res.status(409).json({ error: 'Only confirmed invoices take payments.' }); }
    const paid = (await c.query(`SELECT COALESCE(sum(amount),0) AS s FROM payments WHERE invoice_id=$1`, [inv.id])).rows[0].s;
    if (!(amount > 0) || amount > round(inv.total - paid)) { await c.query('ROLLBACK'); return res.status(400).json({ error: 'Amount must be above zero and within the balance.' }); }
    await c.query(`INSERT INTO payments(invoice_id,method,amount,paid_on,note,created_by) VALUES($1,$2,$3,COALESCE($4,CURRENT_DATE),$5,$6)`, [inv.id, method, amount, paid_on || null, note, req.user.id]);
    if (round(paid + amount) >= inv.total) await c.query(`UPDATE invoices SET status='Paid' WHERE id=$1`, [inv.id]);
    await c.query('COMMIT'); res.status(201).json({ ok: true });
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));

// Customer pays their own invoice online: we create a Stripe Checkout page and send them there.
app.post('/invoices/:id/pay', auth('customer'), wrap(async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) return res.status(501).json({ error: 'Online payments are not set up yet. Contact us and we will record your payment.' });
  const inv = (await q(`SELECT i.*, i.total - COALESCE((SELECT sum(amount) FROM payments WHERE invoice_id=i.id),0) AS balance FROM invoices i WHERE i.id=$1 AND i.customer_id=$2`, [req.params.id, req.user.cid])).rows[0];
  if (!inv || inv.status !== 'Confirmed' || !(inv.balance > 0)) return res.status(409).json({ error: 'This invoice cannot be paid online.' });
  const base = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
  const body = new URLSearchParams({
    mode: 'payment', success_url: base + '/?paid=1', cancel_url: base + '/',
    'line_items[0][quantity]': '1',
    'line_items[0][price_data][currency]': process.env.CURRENCY || 'usd',
    'line_items[0][price_data][unit_amount]': String(Math.round(inv.balance * 100)),
    'line_items[0][price_data][product_data][name]': 'Invoice ' + inv.number,
    'metadata[invoice_id]': String(inv.id)
  });
  const r = await fetch('https://api.stripe.com/v1/checkout/sessions', { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (!r.ok) return res.status(502).json({ error: 'The payment provider did not respond. Try again in a moment.' });
  res.json({ url: (await r.json()).url });
}));

// ---------- finance summary ----------
app.get('/reports/summary', auth('admin', 'staff'), wrap(async (req, res) => {
  const [a, r, o, od] = await Promise.all([
    q(`SELECT count(*)::int AS n FROM subscriptions WHERE status='Active'`),
    q(`SELECT COALESCE(sum(amount),0) AS s FROM payments WHERE ($1::date IS NULL OR paid_on>=$1) AND ($2::date IS NULL OR paid_on<=$2)`, [req.query.from || null, req.query.to || null]),
    q(`SELECT COALESCE(sum(i.total),0) - COALESCE((SELECT sum(p.amount) FROM payments p JOIN invoices x ON x.id=p.invoice_id WHERE x.status='Confirmed'),0) AS s FROM invoices i WHERE i.status='Confirmed'`),
    q(`SELECT i.id,i.number,c.name,i.due_date FROM invoices i JOIN customers c ON c.id=i.customer_id WHERE i.status='Confirmed' AND i.due_date<CURRENT_DATE ORDER BY i.due_date LIMIT 50`)]);
  res.json({ active_subscriptions: a.rows[0].n, revenue: r.rows[0].s, outstanding: o.rows[0].s, overdue: od.rows });
}));

app.get('/customers', auth('admin', 'staff'), wrap(async (req, res) => res.json((await q(`SELECT id,name FROM customers ORDER BY name`)).rows)));
app.get('/templates', auth('admin', 'staff'), wrap(async (req, res) => res.json((await q(`SELECT id,name,validity_days FROM quotation_templates ORDER BY id`)).rows)));

app.use((e, req, res, next) => { console.error(e); res.status(500).json({ error: 'Something went wrong. Try again.' }); });
app.listen(process.env.PORT || 3000, () => console.log('API running'));
