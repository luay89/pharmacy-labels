'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');
const { openDatabase } = require('./db');
const { createMailer, templates, normalizeEmail, maskEmail } = require('./mail');

const PORT = Number(process.env.PORT || 3000);
const APP_URL = new URL(process.env.PUBLIC_APP_URL || `http://localhost:${PORT}`);
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const FREE_LABEL_LIMIT = 20;
const PRICE_CENTS = 500;
const SESSION_COOKIE = 'product_labels_session';
const SESSION_MAX_AGE = 365 * 24 * 60 * 60;
const HOUR = 60 * 60 * 1000;
const TRANSFER_CODE_TTL_MS = 10 * 60 * 1000;
const TRANSFER_CODE_MAX_ATTEMPTS = 5;
const OUTBOX_RETRY_DELAYS = [60_000, 5 * 60_000, 30 * 60_000, 2 * HOUR];
// Transfer codes live for 10 minutes, so their retries are short; expiry ends them anyway.
const TRANSFER_EMAIL_RETRY_DELAYS = [30_000, 60_000, 2 * 60_000, 3 * 60_000];
// SMTP-side outages (rejected login, unreachable server) say nothing about the message itself, so they
// postpone it without using up its attempts; transfer codes still end at their own expiry.
const MAIL_SERVICE_ERRORS = new Set(['EAUTH', 'ECONNECTION', 'ETIMEDOUT', 'ESOCKET', 'EDNS', 'ETLS']);
const MAIL_SERVICE_RETRY_MS = { transfer_code: 60_000, default: 5 * 60_000 };
const SUPPORT_EMAIL = normalizeEmail(process.env.SUPPORT_EMAIL || '');

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
// Only objects from the same Stripe mode as the secret key can unlock anything.
const STRIPE_LIVE_MODE = /^(sk|rk)_live_/.test(STRIPE_SECRET_KEY);
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
const { db, migration } = openDatabase(dataDir);
const mailer = createMailer(process.env);
const clock = { now: () => Date.now() };
const licenseKey = Buffer.from(
  crypto.hkdfSync('sha256', SESSION_SECRET, Buffer.alloc(0), 'product-labels/license-v1', 32)
);
// Separate key for the transfer codes that wait in the email outbox; a copied database alone cannot reveal them.
const outboxKey = Buffer.from(
  crypto.hkdfSync('sha256', SESSION_SECRET, Buffer.alloc(0), 'product-labels/outbox-v1', 32)
);
if (require.main === module) {
  if (migration.from !== migration.to) {
    console.log(`Database migrated from v${migration.from} to v${migration.to}${migration.backupPath ? ' (backup saved in DATA_DIR/backups)' : ''}.`);
  }
  if (!mailer.configured) {
    console.warn('Email disabled: SMTP_HOST is not set (purchase confirmations stay queued, license transfers are unavailable).');
  }
  const testPurchases = STRIPE_LIVE_MODE && db.prepare(
    "SELECT COUNT(*) AS n FROM stripe_purchases WHERE checkout_session_id LIKE 'cs\\_test\\_%' ESCAPE '\\'"
  ).get().n;
  if (testPurchases) {
    console.warn(`Live Stripe key, but this database holds ${testPurchases} purchase(s) from Stripe test mode that still unlock their devices. Start production with a fresh DATA_DIR.`);
  }
}

const insertSession = db.prepare('INSERT INTO app_sessions (id, last_seen_at) VALUES (?, ?)');
const selectSessionLastSeen = db.prepare(`
  SELECT COALESCE(last_seen_at, CAST(strftime('%s', created_at) AS INTEGER) * 1000) AS lastSeen
  FROM app_sessions WHERE id = ?
`);
const touchSession = db.prepare(
  'UPDATE app_sessions SET last_seen_at = ? WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)'
);
const selectSession = db.prepare(
  'SELECT id, labels_printed AS printedCount, unlocked FROM app_sessions WHERE id = ?'
);
const reserveLabels = db.prepare(`
  UPDATE app_sessions
  SET labels_printed = labels_printed + ?
  WHERE id = ? AND unlocked = 0 AND labels_printed + ? <= ?
`);
const savePurchase = db.prepare(`
  INSERT INTO stripe_purchases (
    payment_intent_id, app_session_id, status, checkout_session_id,
    email_hash, email_masked, order_ref, amount_total, currency
  )
  VALUES (
    @intentId, @appSessionId, 'active', @checkoutSessionId,
    @emailHash, @emailMasked, @orderRef, @amountTotal, @currency
  )
  ON CONFLICT(payment_intent_id) DO UPDATE SET
    app_session_id = COALESCE(stripe_purchases.app_session_id, excluded.app_session_id),
    checkout_session_id = COALESCE(stripe_purchases.checkout_session_id, excluded.checkout_session_id),
    email_hash = COALESCE(stripe_purchases.email_hash, excluded.email_hash),
    email_masked = COALESCE(stripe_purchases.email_masked, excluded.email_masked),
    order_ref = COALESCE(stripe_purchases.order_ref, excluded.order_ref),
    amount_total = COALESCE(stripe_purchases.amount_total, excluded.amount_total),
    currency = COALESCE(stripe_purchases.currency, excluded.currency),
    updated_at = CURRENT_TIMESTAMP
  WHERE stripe_purchases.app_session_id IS NULL
    OR stripe_purchases.app_session_id = excluded.app_session_id
`);
const savePendingPurchaseStatus = db.prepare(`
  INSERT INTO stripe_purchases (payment_intent_id, status, status_event_created)
  VALUES (?, ?, ?)
  ON CONFLICT(payment_intent_id) DO UPDATE SET
    status = excluded.status,
    status_event_created = excluded.status_event_created,
    updated_at = CURRENT_TIMESTAMP
  WHERE stripe_purchases.app_session_id IS NULL
    AND stripe_purchases.status != 'refunded'
`);
const PURCHASE_COLUMNS = `payment_intent_id, app_session_id, status, status_event_created, email_masked,
  order_ref, amount_total, currency, transfers_used, transfer_limit`;
const findPurchase = db.prepare(
  `SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases WHERE payment_intent_id = ?`
);
const findBoundPurchase = db.prepare(`
  SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases
  WHERE app_session_id = ? ORDER BY status = 'active' DESC, rowid DESC LIMIT 1
`);
const findPurchaseByEmail = db.prepare(`
  SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases
  WHERE email_hash = ?
  ORDER BY (status = 'active' AND transfers_used < transfer_limit) DESC, rowid DESC LIMIT 1
`);
const updatePurchaseStatus = db.prepare(`
  UPDATE stripe_purchases
  SET status = ?, status_event_created = MAX(COALESCE(status_event_created, 0), ?),
    updated_at = CURRENT_TIMESTAMP
  WHERE payment_intent_id = ?
`);
const transferPurchase = db.prepare(`
  UPDATE stripe_purchases
  SET app_session_id = @to, transfers_used = transfers_used + 1,
    last_transfer_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
  WHERE payment_intent_id = @intentId AND status = 'active'
    AND transfers_used < transfer_limit AND app_session_id IS @from
`);
const recordTransfer = db.prepare(
  'INSERT INTO license_transfers (payment_intent_id, from_app_session_id, to_app_session_id) VALUES (?, ?, ?)'
);
const findTransferFrom = db.prepare('SELECT 1 FROM license_transfers WHERE from_app_session_id = ? LIMIT 1');
const insertVerification = db.prepare(`
  INSERT INTO email_verifications (payment_intent_id, app_session_id, code_hash, expires_at, created_at)
  VALUES (?, ?, ?, ?, ?)
`);
const findOpenVerification = db.prepare(`
  SELECT id, payment_intent_id, code_hash, expires_at FROM email_verifications
  WHERE app_session_id = ? AND consumed_at IS NULL ORDER BY id DESC LIMIT 1
`);
const selectVerificationState = db.prepare('SELECT expires_at, consumed_at FROM email_verifications WHERE id = ?');
const closeSessionVerifications = db.prepare(
  'UPDATE email_verifications SET consumed_at = ? WHERE app_session_id = ? AND consumed_at IS NULL'
);
const closePurchaseVerifications = db.prepare(
  'UPDATE email_verifications SET consumed_at = ? WHERE payment_intent_id = ? AND consumed_at IS NULL'
);
const closeVerification = db.prepare(
  'UPDATE email_verifications SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL'
);
const failVerification = db.prepare(`
  UPDATE email_verifications
  SET attempts = attempts + 1, consumed_at = CASE WHEN attempts + 1 >= ? THEN ? ELSE NULL END
  WHERE id = ?
`);
const selectRateLimit = db.prepare('SELECT window_start, count FROM rate_limits WHERE key = ?');
const resetRateLimit = db.prepare(`
  INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
  ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = 1
`);
const bumpRateLimit = db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?');
const pruneRateLimits = db.prepare('DELETE FROM rate_limits WHERE window_start < ?');
const enqueueEmail = db.prepare(`
  INSERT OR IGNORE INTO email_outbox
    (kind, dedupe_key, payment_intent_id, to_address, payload, status, next_attempt_at, created_at)
  VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
`);
const selectDueEmails = db.prepare(`
  SELECT id, kind, to_address, payload, attempts FROM email_outbox
  WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY id LIMIT 20
`);
const markEmailSent = db.prepare(`
  UPDATE email_outbox SET status = 'sent', to_address = NULL, sent_at = ?, last_error = NULL,
    payload = CASE WHEN kind = 'transfer_code' THEN '{}' ELSE payload END
  WHERE id = ? AND status = 'pending'
`);
const markEmailRetry = db.prepare(`
  UPDATE email_outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
  WHERE id = ? AND status = 'pending'
`);
const deferEmail = db.prepare(`
  UPDATE email_outbox SET next_attempt_at = ?, last_error = ? WHERE id = ? AND status = 'pending'
`);
const deferPendingEmails = db.prepare(`
  UPDATE email_outbox
  SET next_attempt_at = MAX(next_attempt_at, CASE WHEN kind = 'transfer_code' THEN @codes ELSE @others END)
  WHERE status = 'pending'
`);
const markEmailFailed = db.prepare(`
  UPDATE email_outbox SET status = 'failed', attempts = attempts + 1, to_address = NULL, last_error = ?,
    payload = CASE WHEN kind = 'transfer_code' THEN '{}' ELSE payload END
  WHERE id = ? AND status = 'pending'
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
    'Content-Security-Policy': "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': 'no-store'
  });
  if (APP_URL.protocol === 'https:') res.set('Strict-Transport-Security', 'max-age=15552000');
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
  let cookieValue = '';
  if (match) {
    try {
      cookieValue = decodeURIComponent(match[1]);
    } catch {
      // Malformed cookie: fall through and issue a fresh session.
    }
  }
  if (cookieValue) {
    const [id, signature, extra] = cookieValue.split('.');
    if (id && signature && !extra && safeEqual(signature, sessionSignature(id))) {
      // The cookie carries no date, so the server enforces the same lifetime the browser does:
      // a session not renewed within SESSION_MAX_AGE is expired even if an old cookie is replayed.
      const activity = selectSessionLastSeen.get(id);
      if (activity && activity.lastSeen !== null && clock.now() - activity.lastSeen < SESSION_MAX_AGE * 1000) {
        req.appSession = selectSession.get(id);
        req.appSessionId = id;
        next();
        return;
      }
    }
  }

  const id = crypto.randomBytes(32).toString('base64url');
  insertSession.run(id, clock.now());
  setSessionCookie(res, id);
  req.appSession = selectSession.get(id);
  req.appSessionId = id;
  req.newAppSession = true;
  next();
}

function setSessionCookie(res, id) {
  const secure = APP_URL.protocol === 'https:' ? '; Secure' : '';
  res.append('Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(`${id}.${sessionSignature(id)}`)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}${secure}`);
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
    session.livemode === STRIPE_LIVE_MODE &&
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

function keyedHash(purpose, value) {
  return crypto.createHmac('sha256', licenseKey).update(`${purpose}:${value}`).digest('hex');
}

const ORDER_REF_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function orderReference(intentId) {
  const digest = crypto.createHmac('sha256', licenseKey).update(`order:${intentId}`).digest();
  return `PL-${Array.from(digest.subarray(0, 10), (byte) => ORDER_REF_ALPHABET[byte % 32]).join('')}`;
}

function errorCode(error) {
  return error && /^[A-Za-z_]{1,32}$/.test(error.code) ? error.code : 'send_failed';
}

// Must run inside a transaction; the confirmation email is queued once per payment intent.
function activatePurchase(session, appSessionId) {
  const intentId = paymentIntentId(session);
  if (!intentId) return false;
  const email = normalizeEmail(session.customer_details && session.customer_details.email);
  savePurchase.run({
    intentId,
    appSessionId,
    checkoutSessionId: typeof session.id === 'string' ? session.id : null,
    emailHash: email ? keyedHash('email', email) : null,
    emailMasked: email ? maskEmail(email) : null,
    orderRef: orderReference(intentId),
    amountTotal: session.amount_total,
    currency: session.currency
  });
  refreshEntitlement.run(appSessionId);
  const purchase = findPurchase.get(intentId);
  if (!email) {
    console.warn(`Order ${purchase.order_ref}: Stripe returned no customer email; confirmation and transfers are unavailable.`);
  } else if (purchase.status === 'active') {
    const now = clock.now();
    enqueueEmail.run('purchase_confirmation', `purchase_confirmation:${intentId}`, intentId, email,
      JSON.stringify({ orderRef: purchase.order_ref, amountTotal: purchase.amount_total, currency: purchase.currency }),
      now, now);
  }
  return true;
}

function updatePurchaseFromCharge(charge, status, eventCreated) {
  const intentId = typeof charge.payment_intent === 'string'
    ? charge.payment_intent
    : charge.payment_intent && charge.payment_intent.id;
  if (!intentId) return;
  const purchase = findPurchase.get(intentId);
  if (!purchase) {
    savePendingPurchaseStatus.run(intentId, status, eventCreated);
    return;
  }
  // Refunds are final. Dispute events older than the last applied one are stale replays.
  if (purchase.status === 'refunded') return;
  if (status !== 'refunded' && purchase.status_event_created &&
      eventCreated < purchase.status_event_created) return;
  if (status === 'active' && purchase.status !== 'disputed') return;
  updatePurchaseStatus.run(status, eventCreated, intentId);
  if (purchase.app_session_id) refreshEntitlement.run(purchase.app_session_id);
}

let outboxRun = null;
let outboxAgain = false;
// Single-flight, but a call during a run asks for another pass so mail queued at the tail end is not left waiting.
function processOutbox() {
  if (outboxRun) {
    outboxAgain = true;
    return outboxRun;
  }
  outboxRun = (async () => {
    do {
      outboxAgain = false;
      await deliverDueEmails();
    } while (outboxAgain);
  })().finally(() => { outboxRun = null; });
  return outboxRun;
}

function scheduleOutbox() {
  setImmediate(() => {
    processOutbox().catch((error) => console.error('Email outbox failed:', error.message));
  });
}

function sealTransferCode(code, verificationId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', outboxKey, iv);
  cipher.setAAD(Buffer.from(`transfer-code:${verificationId}`));
  const sealed = Buffer.concat([cipher.update(code, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString('base64');
}

function openTransferCode(value, verificationId) {
  const raw = Buffer.from(String(value), 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', outboxKey, raw.subarray(0, 12));
  decipher.setAAD(Buffer.from(`transfer-code:${verificationId}`));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

const TERMINAL_EMAIL_ERRORS = new Set(['invalid_outbox_item', 'code_unavailable']);
const outboxError = (code) => Object.assign(new Error('Email not sendable.'), { code });

function outboxMessage(item) {
  if (!item.to_address) throw outboxError('invalid_outbox_item');
  let payload;
  try {
    payload = JSON.parse(item.payload);
  } catch {
    throw outboxError('invalid_outbox_item');
  }
  if (item.kind === 'purchase_confirmation') {
    return templates.purchaseConfirmation({ ...payload, supportEmail: SUPPORT_EMAIL });
  }
  if (item.kind === 'transfer_unavailable') {
    return templates.transferUnavailable({ ...payload, supportEmail: SUPPORT_EMAIL });
  }
  if (item.kind === 'transfer_code') {
    // Never send a code that was used, replaced by a newer request, locked or (nearly) expired.
    const verification = selectVerificationState.get(payload.verificationId);
    const remaining = verification && verification.consumed_at === null ? verification.expires_at - clock.now() : 0;
    if (remaining < 60_000) throw outboxError('code_unavailable');
    let code;
    try {
      code = openTransferCode(payload.sealedCode, payload.verificationId);
    } catch {
      throw outboxError('invalid_outbox_item');
    }
    return templates.transferCode({
      code,
      minutes: Math.floor((remaining + 1000) / 60_000),
      orderRef: payload.orderRef,
      supportEmail: SUPPORT_EMAIL
    });
  }
  throw outboxError('invalid_outbox_item');
}

async function deliverDueEmails() {
  if (!mailer.configured) return;
  for (let due = selectDueEmails.all(clock.now()); due.length; due = selectDueEmails.all(clock.now())) {
    for (const item of due) {
      try {
        const message = outboxMessage(item);
        await mailer.send({ to: item.to_address, ...message });
        markEmailSent.run(clock.now(), item.id);
      } catch (error) {
        const code = errorCode(error);
        const status = Number.isInteger(error && error.smtpStatus) ? ` (SMTP ${error.smtpStatus})` : '';
        console.warn(`Email #${item.id} (${item.kind}) not delivered: ${code}${status}.`);
        if (MAIL_SERVICE_ERRORS.has(code) && !TERMINAL_EMAIL_ERRORS.has(code)) {
          // The whole queue would hit the same outage: hold it back so the SMTP server sees one
          // attempt per window instead of one per message.
          const now = clock.now();
          db.transaction(() => {
            deferEmail.run(now + (MAIL_SERVICE_RETRY_MS[item.kind] || MAIL_SERVICE_RETRY_MS.default), code, item.id);
            deferPendingEmails.run({ codes: now + MAIL_SERVICE_RETRY_MS.transfer_code, others: now + MAIL_SERVICE_RETRY_MS.default });
          })();
          return;
        }
        const delays = item.kind === 'transfer_code' ? TRANSFER_EMAIL_RETRY_DELAYS : OUTBOX_RETRY_DELAYS;
        if (item.attempts >= delays.length || TERMINAL_EMAIL_ERRORS.has(code)) {
          markEmailFailed.run(code, item.id);
        } else {
          markEmailRetry.run(clock.now() + delays[item.attempts], code, item.id);
        }
      }
    }
  }
}

const consumeRateLimit = db.transaction((key, limit, windowMs) => {
  const now = clock.now();
  const row = selectRateLimit.get(key);
  if (!row || now - row.window_start >= windowMs) {
    resetRateLimit.run(key, now);
    return true;
  }
  if (row.count >= limit) return false;
  bumpRateLimit.run(key);
  return true;
});

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

  // A webhook secret from the other Stripe mode is a configuration mistake: never let a test event
  // grant, refund or restore anything on a live server (or the reverse). Acknowledged so Stripe stops retrying.
  if (event.livemode !== STRIPE_LIVE_MODE) {
    console.warn(`Stripe event ${event.id} ignored: ${event.livemode ? 'live' : 'test'} event on a ${STRIPE_LIVE_MODE ? 'live' : 'test'} server.`);
    res.json({ received: true });
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
      markEventAndUnlock.immediate();
      scheduleOutbox();
    }
  } else if (event.type === 'charge.refunded') {
    const charge = event.data.object;
    if (charge.refunded === true) {
      const processRefund = db.transaction(() => {
        const result = recordStripeEvent.run(event.id);
        if (result.changes) updatePurchaseFromCharge(charge, 'refunded', event.created);
      });
      processRefund();
    }
  } else if (event.type === 'charge.dispute.created') {
    const processDispute = db.transaction(() => {
      const result = recordStripeEvent.run(event.id);
      if (result.changes) updatePurchaseFromCharge(event.data.object, 'disputed', event.created);
    });
    processDispute();
  } else if (event.type === 'charge.dispute.closed' && event.data.object.status === 'won') {
    const restorePurchase = db.transaction(() => {
      const result = recordStripeEvent.run(event.id);
      if (result.changes) updatePurchaseFromCharge(event.data.object, 'active', event.created);
    });
    restorePurchase();
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '8kb' }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api', apiLimiter, requireSameOrigin, requestSession);

app.get('/api/session', (req, res) => {
  // Sliding expiry: the page calls this on every load, so an active device keeps the same session
  // (and any license bound to it). Same id and signature; only the lifetime is extended.
  if (!req.newAppSession) {
    const now = clock.now();
    touchSession.run(now, req.appSessionId, now);
    setSessionCookie(res, req.appSessionId);
  }
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
  if (typeof sessionId !== 'string' || !new RegExp(`^cs_${STRIPE_LIVE_MODE ? 'live' : 'test'}_[A-Za-z0-9]+$`).test(sessionId)) {
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
    if (!activated.immediate()) {
      res.status(403).json({ error: 'purchase_not_verified' });
      return;
    }
    scheduleOutbox();
    const current = selectSession.get(req.appSessionId);
    res.json({ unlocked: current.unlocked === 1, printedCount: current.printedCount });
  } catch (error) {
    next(error);
  }
});

function verificationHash(appSessionId, intentId, code) {
  return keyedHash('transfer-code', `${appSessionId}:${intentId}:${code}`);
}

// Queues the code (or the reason it cannot be sent) in the outbox in the same transaction as the verification.
const startTransfer = db.transaction((email, emailHash, appSessionId) => {
  const purchase = findPurchaseByEmail.get(emailHash);
  if (!purchase || purchase.app_session_id === appSessionId) return { kind: 'none' };
  const now = clock.now();
  const reason = purchase.status !== 'active' ? 'license_unavailable'
    : purchase.transfers_used >= purchase.transfer_limit ? 'transfer_used' : null;
  if (reason) {
    enqueueEmail.run('transfer_unavailable', `transfer_unavailable:${crypto.randomUUID()}`, purchase.payment_intent_id,
      email, JSON.stringify({ orderRef: purchase.order_ref, reason }), now, now);
    return { kind: 'unavailable' };
  }
  closeSessionVerifications.run(now, appSessionId);
  const code = String(crypto.randomInt(0, 100_000_000)).padStart(8, '0');
  const verificationId = Number(insertVerification.run(purchase.payment_intent_id, appSessionId,
    verificationHash(appSessionId, purchase.payment_intent_id, code), now + TRANSFER_CODE_TTL_MS, now).lastInsertRowid);
  enqueueEmail.run('transfer_code', `transfer_code:${verificationId}`, purchase.payment_intent_id, email,
    JSON.stringify({ verificationId, orderRef: purchase.order_ref, sealedCode: sealTransferCode(code, verificationId) }),
    now, now);
  return { kind: 'code' };
});

const completeTransfer = db.transaction((appSessionId, code) => {
  const now = clock.now();
  const verification = findOpenVerification.get(appSessionId);
  if (!verification || verification.expires_at <= now) return { error: 'verification_failed' };
  if (!safeEqual(verificationHash(appSessionId, verification.payment_intent_id, code), verification.code_hash)) {
    failVerification.run(TRANSFER_CODE_MAX_ATTEMPTS, now, verification.id);
    return { error: 'verification_failed' };
  }
  closeVerification.run(now, verification.id);
  const purchase = findPurchase.get(verification.payment_intent_id);
  if (!purchase || purchase.status !== 'active') return { error: 'license_unavailable' };
  const moved = transferPurchase.run({
    to: appSessionId,
    from: purchase.app_session_id,
    intentId: purchase.payment_intent_id
  });
  if (!moved.changes) return { error: 'transfer_used' };
  recordTransfer.run(purchase.payment_intent_id, purchase.app_session_id, appSessionId);
  closePurchaseVerifications.run(now, purchase.payment_intent_id);
  if (purchase.app_session_id) refreshEntitlement.run(purchase.app_session_id);
  refreshEntitlement.run(appSessionId);
  return {
    orderRef: purchase.order_ref,
    transfersRemaining: Math.max(0, purchase.transfer_limit - purchase.transfers_used - 1)
  };
});

app.get('/api/license', (req, res) => {
  const purchase = findBoundPurchase.get(req.appSessionId);
  if (!purchase) {
    res.json({
      licensed: false,
      movedToAnotherDevice: Boolean(findTransferFrom.get(req.appSessionId)),
      transferService: mailer.configured,
      supportEmail: SUPPORT_EMAIL
    });
    return;
  }
  res.json({
    licensed: purchase.status === 'active',
    licenseStatus: purchase.status,
    emailMasked: purchase.email_masked,
    orderRef: purchase.order_ref,
    transferLimit: purchase.transfer_limit,
    transfersUsed: purchase.transfers_used,
    transfersRemaining: Math.max(0, purchase.transfer_limit - purchase.transfers_used),
    transferService: mailer.configured,
    supportEmail: SUPPORT_EMAIL
  });
});

app.post('/api/license/transfer/request', (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  if (!email) {
    res.status(400).json({ error: 'invalid_email' });
    return;
  }
  if (!mailer.configured) {
    res.status(503).json({ error: 'email_unavailable' });
    return;
  }
  if (selectSession.get(req.appSessionId).unlocked === 1) {
    res.status(409).json({ error: 'already_licensed' });
    return;
  }
  const emailHash = keyedHash('email', email);
  const allowed = consumeRateLimit.immediate(`transfer-request:ip:${keyedHash('ip', req.ip)}`, 10, HOUR) &&
    consumeRateLimit.immediate(`transfer-request:session:${req.appSessionId}`, 5, HOUR) &&
    consumeRateLimit.immediate(`transfer-request:email:${emailHash}`, 3, HOUR);
  if (!allowed) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  // The response never reveals whether the address owns a purchase; only the mailbox learns that.
  if (startTransfer.immediate(email, emailHash, req.appSessionId).kind !== 'none') scheduleOutbox();
  res.status(202).json({ status: 'sent_if_eligible', expiresInMinutes: TRANSFER_CODE_TTL_MS / 60_000 });
});

app.post('/api/license/transfer/confirm', (req, res) => {
  const raw = req.body && req.body.code;
  const code = typeof raw === 'string' ? raw.replace(/[\s-]/g, '') : '';
  if (!/^\d{8}$/.test(code)) {
    res.status(400).json({ error: 'invalid_code' });
    return;
  }
  const allowed = consumeRateLimit.immediate(`transfer-confirm:ip:${keyedHash('ip', req.ip)}`, 30, HOUR) &&
    consumeRateLimit.immediate(`transfer-confirm:session:${req.appSessionId}`, 10, HOUR);
  if (!allowed) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  if (selectSession.get(req.appSessionId).unlocked === 1) {
    res.status(409).json({ error: 'already_licensed' });
    return;
  }
  const result = completeTransfer.immediate(req.appSessionId, code);
  if (result.error) {
    res.status(result.error === 'verification_failed' ? 403 : 409).json({ error: result.error });
    return;
  }
  console.log(`License for order ${result.orderRef} transferred to a new device.`);
  res.json({ licensed: true, transfersRemaining: result.transfersRemaining });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found' }));
app.get(['/', '/index.html'], (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/manifest.webmanifest', (_req, res) => res.sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/sw.js', (_req, res) => res.sendFile(path.join(__dirname, 'sw.js')));
app.get('/web-icon-192.svg', (_req, res) => res.sendFile(path.join(__dirname, 'web-icon-192.svg')));
app.get('/web-icon-512.svg', (_req, res) => res.sendFile(path.join(__dirname, 'web-icon-512.svg')));
app.use((_req, res) => res.status(404).send('Not found.'));
const CLIENT_ERRORS = {
  'entity.parse.failed': [400, 'invalid_json'],
  'entity.too.large': [413, 'payload_too_large']
};
app.use((error, _req, res, _next) => {
  const clientError = CLIENT_ERRORS[error && error.type];
  if (clientError) {
    res.status(clientError[0]).json({ error: clientError[1] });
    return;
  }
  if (error && error.expose && error.status >= 400 && error.status < 500) {
    res.status(error.status).json({ error: 'invalid_request' });
    return;
  }
  console.error('Request failed:', error.message);
  res.status(500).json({ error: 'internal_server_error' });
});

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`Product Labels server listening on ${APP_URL.origin}`);
  });
  // Hosts send SIGTERM on every redeploy: finish in-flight requests and email sends, then checkpoint and close SQLite.
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.once(signal, () => {
      console.log(`${signal} received, shutting down.`);
      setTimeout(() => process.exit(1), 10_000).unref();
      server.close(async () => {
        await (outboxRun || Promise.resolve()).catch(() => {});
        db.close();
        process.exit(0);
      });
      server.closeIdleConnections();
    });
  }
  scheduleOutbox();
  setInterval(() => {
    pruneRateLimits.run(clock.now() - 24 * HOUR);
    scheduleOutbox();
  }, 60_000).unref();
}

module.exports = { app, db, stripe, mailer, clock, processOutbox };
