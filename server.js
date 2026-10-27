'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT || 3000);
const APP_URL = new URL(process.env.PUBLIC_APP_URL || `http://localhost:${PORT}`);
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const FREE_LABEL_LIMIT = 20;
const PRICE_CENTS = 500;
const SESSION_COOKIE = 'product_labels_session';
const SESSION_MAX_AGE = 365 * 24 * 60 * 60;

if (SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters.');
}
if (process.env.NODE_ENV === 'production' && APP_URL.protocol !== 'https:') {
  throw new Error('PUBLIC_APP_URL must use HTTPS in production.');
}
if (STRIPE_SECRET_KEY && !/^(sk|rk)_(test|live)_/.test(STRIPE_SECRET_KEY)) {
  throw new Error('STRIPE_SECRET_KEY must be a Stripe secret key (sk_test_/sk_live_/rk_...).');
}
if (STRIPE_WEBHOOK_SECRET && !STRIPE_WEBHOOK_SECRET.startsWith('whsec_')) {
  throw new Error('STRIPE_WEBHOOK_SECRET must start with whsec_.');
}
if (require.main === module) {
  if (!STRIPE_SECRET_KEY) console.warn('Stripe disabled: STRIPE_SECRET_KEY is not set.');
  if (!STRIPE_WEBHOOK_SECRET) {
    console.warn('Stripe webhook disabled: STRIPE_WEBHOOK_SECRET is not set (async payments, refunds and disputes will not be processed).');
  }
  if (process.env.NODE_ENV === 'production' && STRIPE_SECRET_KEY.includes('_test_')) {
    console.warn('NODE_ENV=production is using a Stripe test key.');
  }
}

const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const db = new Database(path.join(dataDir, 'product-labels.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS app_sessions (
    id TEXT PRIMARY KEY,
    labels_printed INTEGER NOT NULL DEFAULT 0 CHECK (labels_printed >= 0),
    unlocked INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS stripe_events (
    id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS stripe_purchases (
    payment_intent_id TEXT PRIMARY KEY,
    app_session_id TEXT REFERENCES app_sessions(id),
    status TEXT NOT NULL CHECK (status IN ('active', 'refunded', 'disputed')),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const insertSession = db.prepare('INSERT INTO app_sessions (id) VALUES (?)');
const selectSession = db.prepare(
  'SELECT id, labels_printed AS printedCount, unlocked FROM app_sessions WHERE id = ?'
);
const reserveLabels = db.prepare(`
  UPDATE app_sessions
  SET labels_printed = labels_printed + ?
  WHERE id = ? AND unlocked = 0 AND labels_printed + ? <= ?
`);
const savePurchase = db.prepare(`
  INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status)
  VALUES (?, ?, 'active')
  ON CONFLICT(payment_intent_id) DO UPDATE SET
    app_session_id = COALESCE(stripe_purchases.app_session_id, excluded.app_session_id),
    updated_at = CURRENT_TIMESTAMP
  WHERE stripe_purchases.app_session_id IS NULL
    OR stripe_purchases.app_session_id = excluded.app_session_id
`);
const savePendingPurchaseStatus = db.prepare(`
  INSERT INTO stripe_purchases (payment_intent_id, status)
  VALUES (?, ?)
  ON CONFLICT(payment_intent_id) DO UPDATE SET
    status = excluded.status,
    updated_at = CURRENT_TIMESTAMP
  WHERE stripe_purchases.app_session_id IS NULL
    AND stripe_purchases.status != 'refunded'
`);
const findPurchase = db.prepare(
  'SELECT app_session_id, status FROM stripe_purchases WHERE payment_intent_id = ?'
);
const updatePurchaseStatus = db.prepare(`
  UPDATE stripe_purchases SET status = ?, updated_at = CURRENT_TIMESTAMP
  WHERE payment_intent_id = ?
`);
const refreshEntitlement = db.prepare(`
  UPDATE app_sessions
  SET unlocked = CASE WHEN EXISTS (
    SELECT 1 FROM stripe_purchases
    WHERE stripe_purchases.app_session_id = app_sessions.id
      AND stripe_purchases.status = 'active'
  ) THEN 1 ELSE 0 END
  WHERE id = ?
`);
const recordStripeEvent = db.prepare('INSERT OR IGNORE INTO stripe_events (id) VALUES (?)');
const sessionExists = db.prepare('SELECT 1 FROM app_sessions WHERE id = ?');

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store'
  });
  next();
});

function sessionSignature(id) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('base64url');
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requestSession(req, res, next) {
  const raw = req.headers.cookie || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (match) {
    const [id, signature, extra] = decodeURIComponent(match[1]).split('.');
    if (id && signature && !extra && safeEqual(signature, sessionSignature(id))) {
      const session = selectSession.get(id);
      if (session) {
        req.appSession = session;
        req.appSessionId = id;
        next();
        return;
      }
    }
  }

  const id = crypto.randomBytes(32).toString('base64url');
  insertSession.run(id);
  const secure = APP_URL.protocol === 'https:' ? '; Secure' : '';
  res.append('Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(`${id}.${sessionSignature(id)}`)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}${secure}`);
  req.appSession = selectSession.get(id);
  req.appSessionId = id;
  next();
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('Origin');
  if (origin && origin !== APP_URL.origin) {
    res.status(403).json({ error: 'origin_not_allowed' });
    return;
  }
  next();
}

const checkoutLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});
const completeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});
const reserveLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function isPaidCheckout(session, appSessionId) {
  const paymentIntent = session && session.payment_intent;
  return session &&
    typeof appSessionId === 'string' &&
    session.mode === 'payment' &&
    session.payment_status === 'paid' &&
    session.amount_total === PRICE_CENTS &&
    session.currency === 'usd' &&
    session.client_reference_id === appSessionId &&
    session.metadata &&
    session.metadata.app_session_id === appSessionId &&
    (typeof paymentIntent === 'string' || (paymentIntent && typeof paymentIntent.id === 'string'));
}

function paymentIntentId(session) {
  return typeof session.payment_intent === 'string'
    ? session.payment_intent
    : session.payment_intent && session.payment_intent.id;
}

function activatePurchase(session, appSessionId) {
  const intentId = paymentIntentId(session);
  if (!intentId) return false;
  savePurchase.run(intentId, appSessionId);
  refreshEntitlement.run(appSessionId);
  return true;
}

function updatePurchaseFromCharge(charge, status) {
  const intentId = typeof charge.payment_intent === 'string'
    ? charge.payment_intent
    : charge.payment_intent && charge.payment_intent.id;
  if (!intentId) return;
  const purchase = findPurchase.get(intentId);
  if (!purchase) {
    savePendingPurchaseStatus.run(intentId, status);
    return;
  }
  if ((status === 'active' && purchase.status !== 'disputed') ||
      (status === 'disputed' && purchase.status === 'refunded')) return;
  updatePurchaseStatus.run(status, intentId);
  if (purchase.app_session_id) refreshEntitlement.run(purchase.app_session_id);
}

app.post('/api/stripe/webhook', express.raw({ type: 'application/json', limit: '64kb' }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    res.status(503).send('Stripe webhook is not configured.');
    return;
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.get('stripe-signature'),
      STRIPE_WEBHOOK_SECRET
    );
  } catch {
    res.status(400).send('Invalid webhook signature.');
    return;
  }

  if (event.type === 'checkout.session.completed' ||
      event.type === 'checkout.session.async_payment_succeeded') {
    const checkout = event.data.object;
    if (checkout.payment_status !== 'paid') {
      // Delayed payment methods: access is granted only on async_payment_succeeded.
    } else if (!isPaidCheckout(checkout, checkout.client_reference_id) ||
        !sessionExists.get(checkout.client_reference_id)) {
      console.warn(`Stripe event ${event.id} ignored: checkout did not match the expected purchase.`);
    } else {
      const markEventAndUnlock = db.transaction(() => {
        const result = recordStripeEvent.run(event.id);
        if (result.changes) activatePurchase(checkout, checkout.client_reference_id);
      });
      markEventAndUnlock();
    }
  } else if (event.type === 'charge.refunded') {
    const charge = event.data.object;
    if (charge.refunded === true) {
      const processRefund = db.transaction(() => {
        const result = recordStripeEvent.run(event.id);
        if (result.changes) updatePurchaseFromCharge(charge, 'refunded');
      });
      processRefund();
    }
  } else if (event.type === 'charge.dispute.created') {
    const processDispute = db.transaction(() => {
      const result = recordStripeEvent.run(event.id);
      if (result.changes) updatePurchaseFromCharge(event.data.object, 'disputed');
    });
    processDispute();
  } else if (event.type === 'charge.dispute.closed' && event.data.object.status === 'won') {
    const restorePurchase = db.transaction(() => {
      const result = recordStripeEvent.run(event.id);
      if (result.changes) updatePurchaseFromCharge(event.data.object, 'active');
    });
    restorePurchase();
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '8kb' }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api', apiLimiter, requireSameOrigin, requestSession);

app.get('/api/session', (req, res) => {
  const current = selectSession.get(req.appSessionId);
  res.json({
    printedCount: current.printedCount,
    freeLimit: FREE_LABEL_LIMIT,
    unlocked: current.unlocked === 1
  });
});

app.post('/api/labels/reserve', reserveLimiter, (req, res) => {
  const count = req.body && req.body.count;
  if (!Number.isInteger(count) || count < 1 || count > 999) {
    res.status(400).json({ error: 'invalid_label_count' });
    return;
  }
  const current = selectSession.get(req.appSessionId);
  if (current.unlocked === 1) {
    res.json({ printedCount: current.printedCount, unlocked: true });
    return;
  }
  const result = reserveLabels.run(count, req.appSessionId, count, FREE_LABEL_LIMIT);
  if (!result.changes) {
    res.status(402).json({
      error: 'free_limit_reached',
      printedCount: current.printedCount,
      freeLimit: FREE_LABEL_LIMIT
    });
    return;
  }
  const updated = selectSession.get(req.appSessionId);
  res.json({ printedCount: updated.printedCount, unlocked: false });
});

app.post('/api/checkout', checkoutLimiter, async (req, res, next) => {
  if (req.appSession.unlocked === 1) {
    res.status(409).json({ error: 'already_unlocked' });
    return;
  }
  if (!stripe) {
    res.status(503).json({ error: 'stripe_not_configured' });
    return;
  }
  try {
    const checkout = await stripe.checkout.sessions.create({
      mode: 'payment',
      client_reference_id: req.appSessionId,
      line_items: [{
        price_data: {
          currency: 'usd',
          unit_amount: PRICE_CENTS,
          product_data: { name: 'Product Labels - Lifetime Unlock' }
        },
        quantity: 1
      }],
      success_url: `${APP_URL.origin}/?checkout_session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL.origin}/?checkout=cancelled`,
      metadata: { app_session_id: req.appSessionId }
    });
    res.json({ url: checkout.url });
  } catch (error) {
    next(error);
  }
});

app.post('/api/checkout/complete', completeLimiter, async (req, res, next) => {
  const sessionId = req.body && req.body.sessionId;
  if (typeof sessionId !== 'string' || !/^cs_(test|live)_[A-Za-z0-9]+$/.test(sessionId)) {
    res.status(400).json({ error: 'invalid_checkout_session' });
    return;
  }
  if (!stripe) {
    res.status(503).json({ error: 'stripe_not_configured' });
    return;
  }
  try {
    let checkout;
    try {
      checkout = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (error) {
      if (error && error.type === 'StripeInvalidRequestError') {
        res.status(403).json({ error: 'purchase_not_verified' });
        return;
      }
      throw error;
    }
    if (checkout.payment_status !== 'paid' && checkout.status === 'complete' &&
        checkout.client_reference_id === req.appSessionId) {
      res.status(409).json({ error: 'payment_pending' });
      return;
    }
    if (!isPaidCheckout(checkout, req.appSessionId)) {
      res.status(403).json({ error: 'purchase_not_verified' });
      return;
    }
    const activated = db.transaction(() => activatePurchase(checkout, req.appSessionId));
    if (!activated()) {
      res.status(403).json({ error: 'purchase_not_verified' });
      return;
    }
    const current = selectSession.get(req.appSessionId);
    res.json({ unlocked: current.unlocked === 1, printedCount: current.printedCount });
  } catch (error) {
    next(error);
  }
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found' }));
app.get(['/', '/index.html'], (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/manifest.webmanifest', (_req, res) => res.sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/sw.js', (_req, res) => res.sendFile(path.join(__dirname, 'sw.js')));
app.get('/web-icon-192.svg', (_req, res) => res.sendFile(path.join(__dirname, 'web-icon-192.svg')));
app.get('/web-icon-512.svg', (_req, res) => res.sendFile(path.join(__dirname, 'web-icon-512.svg')));
app.use((_req, res) => res.status(404).send('Not found.'));
app.use((error, _req, res, _next) => {
  console.error('Request failed:', error.message);
  res.status(500).json({ error: 'internal_server_error' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Product Labels server listening on ${APP_URL.origin}`);
  });
}

module.exports = { app, db, stripe };
