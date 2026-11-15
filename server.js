'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');
const { openDatabase } = require('./db');
const { createMailer, templates, normalizeEmail, maskEmail, isDisposableEmail } = require('./mail');
const { jwkThumbprint, readSigningConfig, TRIAL_MS } = require('./license-cert');

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
const ACCOUNT_COOKIE = 'product_labels_account';
// Absolute lifetime: a sign-in is never extended, the user confirms the email again after it.
const ACCOUNT_SESSION_MS = 30 * 24 * HOUR;
const ACCOUNT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MFA_MAX_ATTEMPTS = 5;
const DEVICE_CHALLENGE_TTL_MS = 2 * 60 * 1000;
// Domain separation: the device key signs only this kind of message, so a signature can never be
// replayed as something else. Must match device-key.js.
const DEVICE_PROOF_PREFIX = 'product-labels-device-proof:v1:';
const TRANSFER_CODE_TTL_MS = 10 * 60 * 1000;
const TRANSFER_CODE_MAX_ATTEMPTS = 5;
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const EMAIL_CODE_MAX_ATTEMPTS = 5;
const EMAIL_CODE_RESEND_MS = 60 * 1000;
const OUTBOX_RETRY_DELAYS = [60_000, 5 * 60_000, 30 * 60_000, 2 * HOUR];
// Emails that carry a one-time code: sealed in the outbox, wiped once sent or failed, never sent near expiry.
const CODE_EMAIL_KINDS = new Set(['transfer_code', 'email_verification_code']);
// Codes live for 10 minutes, so their retries are short; expiry ends them anyway.
const TRANSFER_EMAIL_RETRY_DELAYS = [30_000, 60_000, 2 * 60_000, 3 * 60_000];
// SMTP-side outages (rejected login, unreachable server) say nothing about the message itself, so they
// postpone it without using up its attempts; transfer codes still end at their own expiry.
const MAIL_SERVICE_ERRORS = new Set(['EAUTH', 'ECONNECTION', 'ETIMEDOUT', 'ESOCKET', 'EDNS', 'ETLS']);
const MAIL_SERVICE_RETRY_MS = { transfer_code: 60_000, email_verification_code: 60_000, default: 5 * 60_000 };
const SUPPORT_EMAIL = normalizeEmail(process.env.SUPPORT_EMAIL || '');
const licenseSigning = readSigningConfig(process.env);
const licenseSigner = licenseSigning.configured ? licenseSigning.signer : null;
const INLINE_SCRIPT_HASHES = [...fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8')
  .matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)]
  .map((match) => `'sha256-${crypto.createHash('sha256').update(match[1]).digest('base64')}'`);
const SCRIPT_POLICY = `script-src 'self' ${INLINE_SCRIPT_HASHES.join(' ')}`;

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
// Challenges are stateless: an HMAC under their own key, never the cookie key.
const deviceChallengeKey = Buffer.from(
  crypto.hkdfSync('sha256', SESSION_SECRET, Buffer.alloc(0), 'product-labels/device-challenge-v1', 32)
);
if (require.main === module) {
  if (migration.from !== migration.to) {
    console.log(`Database migrated from v${migration.from} to v${migration.to}${migration.backupPath ? ' (backup saved in DATA_DIR/backups)' : ''}.`);
  }
  if (!mailer.configured) {
    console.warn('Email disabled: SMTP_HOST is not set (purchase confirmations stay queued, license transfers are unavailable).');
  }
  if (!licenseSigner) console.warn('Offline licenses disabled: LICENSE_SIGNING_KEY_FILE and LICENSE_SIGNING_KEY are not set.');
  if (process.env.NODE_ENV === 'production') {
    const unclassifiedPurchases = db.prepare(`
      SELECT COUNT(*) AS n FROM stripe_purchases
      WHERE app_session_id IS NOT NULL AND status IN ('active', 'disputed') AND stripe_mode IS NULL
    `).get().n;
    if (unclassifiedPurchases) {
      throw new Error(`Production startup blocked: ${unclassifiedPurchases} active or disputed purchase(s) with unknown Stripe mode may affect entitlements. Review each purchase in Stripe and reconcile it with "npm run reconcile-purchase".`);
    }

    if (STRIPE_LIVE_MODE) {
      const testPurchases = db.prepare(`
        SELECT COUNT(*) AS n FROM stripe_purchases
        WHERE app_session_id IS NOT NULL AND status IN ('active', 'disputed')
          AND stripe_mode = 'test' AND excluded_from_entitlements = 0
      `).get().n;
      if (testPurchases) {
        throw new Error(`Production startup blocked: ${testPurchases} active or disputed test-mode purchase(s) may affect entitlements while Stripe Live is configured. Review the database before startup.`);
      }
    }
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
    email_hash, email_masked, order_ref, amount_total, currency, account_id, license_policy, stripe_mode
  )
  VALUES (
    @intentId, @appSessionId, 'active', @checkoutSessionId,
    @emailHash, @emailMasked, @orderRef, @amountTotal, @currency, @accountId, @licensePolicy, @stripeMode
  )
  ON CONFLICT(payment_intent_id) DO UPDATE SET
    app_session_id = COALESCE(stripe_purchases.app_session_id, excluded.app_session_id),
    checkout_session_id = COALESCE(stripe_purchases.checkout_session_id, excluded.checkout_session_id),
    email_hash = COALESCE(stripe_purchases.email_hash, excluded.email_hash),
    email_masked = COALESCE(stripe_purchases.email_masked, excluded.email_masked),
    order_ref = COALESCE(stripe_purchases.order_ref, excluded.order_ref),
    amount_total = COALESCE(stripe_purchases.amount_total, excluded.amount_total),
    currency = COALESCE(stripe_purchases.currency, excluded.currency),
    account_id = COALESCE(stripe_purchases.account_id, excluded.account_id),
    license_policy = CASE WHEN stripe_purchases.license_policy = 'legacy' AND excluded.account_id IS NOT NULL
      THEN 'single_device' ELSE stripe_purchases.license_policy END,
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
  order_ref, amount_total, currency, transfers_used, transfer_limit, license_policy, account_id`;
const findPurchase = db.prepare(
  `SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases WHERE payment_intent_id = ?`
);
const findBoundPurchase = db.prepare(`
  SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases
  WHERE app_session_id = ? ORDER BY status = 'active' DESC, rowid DESC LIMIT 1
`);
const findPurchaseByEmail = db.prepare(`
  SELECT ${PURCHASE_COLUMNS} FROM stripe_purchases
  WHERE email_hash = ? AND license_policy = 'legacy'
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
    AND license_policy = 'legacy'
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
const insertAccountCode = db.prepare(`
  INSERT INTO account_codes (email_hash, app_session_id, code_hash, expires_at, created_at)
  VALUES (?, ?, ?, ?, ?)
`);
const findOpenAccountCode = db.prepare(`
  SELECT id, code_hash, expires_at FROM account_codes
  WHERE app_session_id = ? AND email_hash = ? AND consumed_at IS NULL ORDER BY id DESC LIMIT 1
`);
const selectAccountCodeState = db.prepare('SELECT expires_at, consumed_at FROM account_codes WHERE id = ?');
const closeSessionAccountCodes = db.prepare(
  'UPDATE account_codes SET consumed_at = ? WHERE app_session_id = ? AND consumed_at IS NULL'
);
const closeAccountCode = db.prepare(
  'UPDATE account_codes SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL'
);
const failAccountCode = db.prepare(`
  UPDATE account_codes
  SET attempts = attempts + 1, consumed_at = CASE WHEN attempts + 1 >= ? THEN ? ELSE NULL END
  WHERE id = ? AND consumed_at IS NULL
`);
const insertAccount = db.prepare(`
  INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES (?, ?, ?, ?)
  ON CONFLICT(email_hash) DO NOTHING
`);
const findAccountByEmail = db.prepare('SELECT id, status, email_masked FROM accounts WHERE email_hash = ?');
const findTotpByAccount = db.prepare('SELECT secret_sealed, enabled_at FROM account_totp WHERE account_id = ?');
const saveTotpSecret = db.prepare(`
  INSERT INTO account_totp (account_id, secret_sealed, enabled_at, updated_at) VALUES (?, ?, NULL, ?)
  ON CONFLICT(account_id) DO UPDATE SET secret_sealed = excluded.secret_sealed, updated_at = excluded.updated_at
  WHERE account_totp.enabled_at IS NULL
`);
const enableTotp = db.prepare('UPDATE account_totp SET enabled_at = ?, updated_at = ? WHERE account_id = ? AND enabled_at IS NULL');
const deleteTotp = db.prepare('DELETE FROM account_totp WHERE account_id = ?');
const insertMfaChallenge = db.prepare(`
  INSERT INTO account_mfa_challenges (token_hash, account_id, app_session_id, intent, replaced_token_hash, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const findMfaChallenge = db.prepare(`
  SELECT token_hash, account_id, app_session_id, intent, replaced_token_hash, attempts, created_at, expires_at, consumed_at
  FROM account_mfa_challenges WHERE token_hash = ?
`);
const failMfaChallenge = db.prepare(`
  UPDATE account_mfa_challenges SET attempts = attempts + 1,
    consumed_at = CASE WHEN attempts + 1 >= ? THEN ? ELSE consumed_at END
  WHERE token_hash = ? AND consumed_at IS NULL
`);
const consumeMfaChallenge = db.prepare('UPDATE account_mfa_challenges SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL');
const insertRecoveryCode = db.prepare('INSERT INTO account_recovery_codes (account_id, code_hash, created_at) VALUES (?, ?, ?)');
const useRecoveryCode = db.prepare('UPDATE account_recovery_codes SET used_at = ? WHERE account_id = ? AND code_hash = ? AND used_at IS NULL');
const clearRecoveryCodes = db.prepare('DELETE FROM account_recovery_codes WHERE account_id = ?');
const findAccountTrial = db.prepare('SELECT device_thumbprint, started_at, expires_at FROM trials WHERE account_id = ?');
const insertAccountTrial = db.prepare('INSERT INTO trials (account_id, device_thumbprint, started_at, expires_at) VALUES (?, ?, ?, ?)');
const findActiveAccountPurchase = db.prepare(`
  SELECT payment_intent_id FROM stripe_purchases
  WHERE account_id = ? AND license_policy = 'single_device' AND status = 'active'
  ORDER BY updated_at DESC, rowid DESC LIMIT 1
`);
const insertLicenseCertificate = db.prepare(`
  INSERT INTO license_certificates (jti, device_id, kind, kid, issued_at, expires_at, revalidate_at, grace_until)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const insertAccountSession = db.prepare(`
  INSERT INTO account_sessions (token_hash, account_id, app_session_id, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?)
`);
const findAccountSession = db.prepare(`
  SELECT account_sessions.account_id, account_sessions.app_session_id, account_sessions.expires_at,
    accounts.status, accounts.email_masked
  FROM account_sessions JOIN accounts ON accounts.id = account_sessions.account_id
  WHERE account_sessions.token_hash = ? AND account_sessions.revoked_at IS NULL
`);
const revokeAccountSession = db.prepare(
  'UPDATE account_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL'
);
const insertAuditEvent = db.prepare(
  'INSERT INTO audit_events (at, event, outcome, account_id, ip_hash) VALUES (?, ?, ?, ?, ?)'
);
const findDeviceByThumbprint = db.prepare('SELECT id, account_id, revoked_at FROM devices WHERE key_thumbprint = ?');
const findActiveDevice = db.prepare(`
  SELECT id, key_thumbprint, registered_at, last_validated_at FROM devices WHERE account_id = ? AND revoked_at IS NULL
`);
const findDevice = db.prepare(
  'SELECT id, account_id, key_thumbprint, public_key_jwk, revoked_at FROM devices WHERE id = ?'
);
const insertDevice = db.prepare(`
  INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at, last_validated_at)
  VALUES (?, ?, ?, ?, ?, ?)
`);
// A proof counts only for a challenge issued after the previous proof, which makes every challenge single use.
const markDeviceValidated = db.prepare(`
  UPDATE devices SET last_validated_at = ?
  WHERE id = ? AND account_id = ? AND revoked_at IS NULL AND (last_validated_at IS NULL OR last_validated_at < ?)
`);
const selectAccountStatus = db.prepare('SELECT status FROM accounts WHERE id = ?');
const insertDeviceAudit = db.prepare(
  'INSERT INTO audit_events (at, event, outcome, account_id, device_id, ip_hash) VALUES (?, ?, ?, ?, ?, ?)'
);
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
    payload = CASE WHEN kind IN ('transfer_code', 'email_verification_code') THEN '{}' ELSE payload END
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
  SET next_attempt_at = MAX(next_attempt_at,
    CASE WHEN kind IN ('transfer_code', 'email_verification_code') THEN @codes ELSE @others END)
  WHERE status = 'pending'
`);
const markEmailFailed = db.prepare(`
  UPDATE email_outbox SET status = 'failed', attempts = attempts + 1, to_address = NULL, last_error = ?,
    payload = CASE WHEN kind IN ('transfer_code', 'email_verification_code') THEN '{}' ELSE payload END
  WHERE id = ? AND status = 'pending'
`);
const refreshEntitlement = db.prepare(`
  UPDATE app_sessions
  SET unlocked = CASE WHEN EXISTS (
    SELECT 1 FROM stripe_purchases
    WHERE stripe_purchases.app_session_id = app_sessions.id
      AND stripe_purchases.status = 'active'
      AND stripe_purchases.excluded_from_entitlements = 0
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
    'Content-Security-Policy': `${SCRIPT_POLICY}; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'`,
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

function safeErrorCode(error) {
  return typeof error?.code === 'string' && /^[A-Z0-9_]{1,32}$/.test(error.code)
    ? error.code
    : 'unknown';
}

function readCookie(req, name) {
  const match = (req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!match) return '';
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return ''; // Malformed cookie: treated as absent.
  }
}

function requestSession(req, res, next) {
  const cookieValue = readCookie(req, SESSION_COOKIE);
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

function setAccountCookie(res, token, maxAgeSeconds) {
  const secure = APP_URL.protocol === 'https:' ? '; Secure' : '';
  res.append('Set-Cookie',
    `${ACCOUNT_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`);
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
  const accountId = session && session.metadata && session.metadata.account_id;
  const accountBindingValid = accountId === undefined || accountId === '' ||
    (/^[A-Za-z0-9_-]{16,64}$/.test(accountId) && session.metadata.license_policy === 'single_device');
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
    accountBindingValid &&
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

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  if (typeof value !== 'string' || !/^[A-Z2-7]+$/.test(value)) return null;
  let bits = 0;
  let current = 0;
  const bytes = [];
  for (const char of value) {
    current = (current << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAt(secret, timeMs) {
  const key = base32Decode(secret);
  if (!key) return '';
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timeMs / 30_000)));
  const digest = crypto.createHmac('sha1', key).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

function validTotp(secret, code, now = clock.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  for (const drift of [-1, 0, 1]) {
    if (safeEqual(totpAt(secret, now + drift * 30_000), code)) return true;
  }
  return false;
}

function normalizedRecoveryCode(value) {
  return typeof value === 'string' && /^[A-Za-z2-7]{4}-[A-Za-z2-7]{4}-[A-Za-z2-7]{4}-[A-Za-z2-7]{4}$/.test(value)
    ? value.replace(/-/g, '').toUpperCase()
    : null;
}

function newRecoveryCode() {
  const raw = base32Encode(crypto.randomBytes(10));
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function verifyTotpOrRecovery(accountId, sealedSecret, code, now = clock.now()) {
  let secret;
  try { secret = openCode(sealedSecret, `account-totp:${accountId}`); } catch { return false; }
  if (validTotp(secret, code, now)) return true;
  const normalized = normalizedRecoveryCode(code);
  if (!normalized) return false;
  return useRecoveryCode.run(now, accountId, keyedHash('recovery-code', `${accountId}:${normalized}`)).changes === 1;
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
  const accountId = session.metadata && typeof session.metadata.account_id === 'string' ? session.metadata.account_id : null;
  const email = normalizeEmail(session.customer_details && session.customer_details.email);
  savePurchase.run({
    intentId,
    appSessionId,
    checkoutSessionId: typeof session.id === 'string' ? session.id : null,
    emailHash: email ? keyedHash('email', email) : null,
    emailMasked: email ? maskEmail(email) : null,
    orderRef: orderReference(intentId),
    amountTotal: session.amount_total,
    currency: session.currency,
    accountId,
    licensePolicy: accountId ? 'single_device' : 'legacy',
    stripeMode: session.livemode ? 'live' : 'test'
  });
  refreshEntitlement.run(appSessionId);
  const purchase = findPurchase.get(intentId);
  if (!email) {
    console.warn(`Order ${purchase.order_ref}: Stripe returned no customer email; confirmation and transfers are unavailable.`);
  } else if (purchase.status === 'active') {
    const now = clock.now();
    enqueueEmail.run('purchase_confirmation', `purchase_confirmation:${intentId}`, intentId, email,
      JSON.stringify({ orderRef: purchase.order_ref, amountTotal: purchase.amount_total, currency: purchase.currency, licensePolicy: purchase.license_policy }),
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
    processOutbox().catch((error) => console.error(`Email outbox failed (${safeErrorCode(error)}).`));
  });
}

// The context (purpose and row id) is authenticated, so a sealed code only opens for the row it was made for.
function sealCode(code, context) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', outboxKey, iv);
  cipher.setAAD(Buffer.from(context));
  const sealed = Buffer.concat([cipher.update(code, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString('base64');
}

function openCode(value, context) {
  const raw = Buffer.from(String(value), 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', outboxKey, raw.subarray(0, 12));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

const TERMINAL_EMAIL_ERRORS = new Set(['invalid_outbox_item', 'code_unavailable']);
const outboxError = (code) => Object.assign(new Error('Email not sendable.'), { code });

// Never send a code that was used, replaced by a newer request, locked or (nearly) expired.
function openQueuedCode(state, sealedCode, context) {
  const remaining = state && state.consumed_at === null ? state.expires_at - clock.now() : 0;
  if (remaining < 60_000) throw outboxError('code_unavailable');
  try {
    return { code: openCode(sealedCode, context), minutes: Math.floor((remaining + 1000) / 60_000) };
  } catch {
    throw outboxError('invalid_outbox_item');
  }
}

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
    const { code, minutes } = openQueuedCode(selectVerificationState.get(payload.verificationId),
      payload.sealedCode, `transfer-code:${payload.verificationId}`);
    return templates.transferCode({ code, minutes, orderRef: payload.orderRef, supportEmail: SUPPORT_EMAIL });
  }
  if (item.kind === 'email_verification_code') {
    const { code, minutes } = openQueuedCode(selectAccountCodeState.get(payload.codeId),
      payload.sealedCode, `email-verification-code:${payload.codeId}`);
    return templates.emailVerificationCode({ code, minutes, supportEmail: SUPPORT_EMAIL });
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
        const delays = CODE_EMAIL_KINDS.has(item.kind) ? TRANSFER_EMAIL_RETRY_DELAYS : OUTBOX_RETRY_DELAYS;
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
  if (!stripe) {
    res.status(503).json({ error: 'stripe_not_configured' });
    return;
  }
  const account = signedInAccount(req, res);
  if (!account) return;
  if (!findActiveDevice.get(account.id)) {
    res.status(409).json({ error: 'device_not_registered' });
    return;
  }
  if (req.appSession.unlocked === 1) {
    res.status(409).json({ error: 'already_unlocked' });
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
      metadata: { app_session_id: req.appSessionId, account_id: account.id, license_policy: 'single_device' }
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
    const checkoutAccountId = checkout.metadata && checkout.metadata.account_id;
    if (checkoutAccountId && currentAccount(req).account?.id !== checkoutAccountId) {
      res.status(403).json({ error: 'purchase_not_verified' });
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
    JSON.stringify({ verificationId, orderRef: purchase.order_ref, sealedCode: sealCode(code, `transfer-code:${verificationId}`) }),
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
  if (!purchase || purchase.status !== 'active' || purchase.license_policy !== 'legacy') return { error: 'license_unavailable' };
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

// Email verification only proves that this browser session can read the mailbox. It creates no account
// and grants nothing: the successful, single-use consumption of a code is the only proof, so later phases
// must act inside the same transaction rather than trust a stored or consumed account_codes row.
function emailCodeHash(appSessionId, emailHash, code) {
  return keyedHash('email-verification-code', `${appSessionId}:${emailHash}:${code}`);
}

// A new request replaces any open code of this session; the code row and its email are queued together.
const startEmailVerification = db.transaction((email, emailHash, appSessionId) => {
  const now = clock.now();
  closeSessionAccountCodes.run(now, appSessionId);
  const code = String(crypto.randomInt(0, 100_000_000)).padStart(8, '0');
  const codeId = Number(insertAccountCode.run(emailHash, appSessionId,
    emailCodeHash(appSessionId, emailHash, code), now + EMAIL_CODE_TTL_MS, now).lastInsertRowid);
  enqueueEmail.run('email_verification_code', `email_verification_code:${codeId}`, null, email,
    JSON.stringify({ codeId, sealedCode: sealCode(code, `email-verification-code:${codeId}`) }), now, now);
});

// Must run inside a transaction. True only for the one call that consumes a matching, live code.
function consumeEmailCode(appSessionId, emailHash, code, now) {
  const pending = findOpenAccountCode.get(appSessionId, emailHash);
  if (!pending) return false;
  if (pending.expires_at <= now) {
    closeAccountCode.run(now, pending.id);
    return false;
  }
  if (!safeEqual(emailCodeHash(appSessionId, emailHash, code), pending.code_hash)) {
    failAccountCode.run(EMAIL_CODE_MAX_ATTEMPTS, now, pending.id);
    return false;
  }
  return closeAccountCode.run(now, pending.id).changes === 1;
}

const completeEmailVerification = db.transaction((appSessionId, emailHash, code) =>
  consumeEmailCode(appSessionId, emailHash, code, clock.now()));

function readEmailCode(body) {
  const raw = body && body.code;
  const code = typeof raw === 'string' ? raw.replace(/[\s-]/g, '') : '';
  return /^\d{8}$/.test(code) ? code : null;
}

function emailCodeChecksAllowed(req) {
  // Shared by verify, signup and login, so switching routes buys no extra guesses.
  return consumeRateLimit.immediate(`email-code-verify:ip:${keyedHash('ip', req.ip)}`, 30, HOUR) &&
    consumeRateLimit.immediate(`email-code-verify:session:${req.appSessionId}`, 10, HOUR);
}

app.post('/api/email-verification/request', (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  if (!email) {
    res.status(400).json({ error: 'invalid_email' });
    return;
  }
  if (isDisposableEmail(email)) {
    res.status(400).json({ error: 'email_not_allowed' });
    return;
  }
  if (!mailer.configured) {
    res.status(503).json({ error: 'email_unavailable' });
    return;
  }
  const emailHash = keyedHash('email', email);
  // The resend cooldown is checked before the hourly address limit so a too-early retry does not use it up.
  const allowed = consumeRateLimit.immediate(`email-code-request:ip:${keyedHash('ip', req.ip)}`, 10, HOUR) &&
    consumeRateLimit.immediate(`email-code-request:session:${req.appSessionId}`, 5, HOUR) &&
    consumeRateLimit.immediate(`email-code-request:resend:${emailHash}`, 1, EMAIL_CODE_RESEND_MS) &&
    consumeRateLimit.immediate(`email-code-request:email:${emailHash}`, 3, HOUR);
  if (!allowed) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  // Same answer for every address: nothing here looks at accounts or purchases.
  startEmailVerification.immediate(email, emailHash, req.appSessionId);
  scheduleOutbox();
  res.status(202).json({ status: 'queued', expiresInMinutes: EMAIL_CODE_TTL_MS / 60_000 });
});

app.post('/api/email-verification/verify', (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  const code = readEmailCode(req.body);
  if (!email) {
    res.status(400).json({ error: 'invalid_email' });
    return;
  }
  if (!code) {
    res.status(400).json({ error: 'invalid_code' });
    return;
  }
  if (!emailCodeChecksAllowed(req)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  if (!completeEmailVerification.immediate(req.appSessionId, keyedHash('email', email), code)) {
    res.status(403).json({ error: 'verification_failed' });
    return;
  }
  res.json({ verified: true, emailMasked: maskEmail(email) });
});

// Signed-in state comes only from a server-side account_sessions row: the anonymous app session cookie
// proves nothing about an account, and nothing in a request body can name or change the account.
function currentAccount(req) {
  const token = readCookie(req, ACCOUNT_COOKIE);
  if (!ACCOUNT_TOKEN_PATTERN.test(token)) return { presented: Boolean(token), account: null };
  const tokenHash = keyedHash('account-session', token);
  const row = findAccountSession.get(tokenHash);
  const usable = row && row.expires_at > clock.now() && row.app_session_id === req.appSessionId && row.status === 'active';
  return {
    presented: true,
    tokenHash,
    account: usable ? { id: row.account_id, emailMasked: row.email_masked } : null
  };
}

// Consuming the code, creating the account (signup only) and opening the sign-in commit together or not at all.
// The account row is unique by email_hash in the database, so concurrent signups end on one account.
const signInWithCode = db.transaction(({ intent, email, emailHash, code, appSessionId, ipHash, replacedTokenHash }) => {
  const now = clock.now();
  const audit = (event, outcome, accountId = null) => insertAuditEvent.run(now, event, outcome, accountId, ipHash);
  if (!consumeEmailCode(appSessionId, emailHash, code, now)) {
    audit(intent, 'bad_code');
    return { error: 'verification_failed' };
  }
  const created = intent === 'signup' &&
    insertAccount.run(crypto.randomBytes(16).toString('base64url'), emailHash, maskEmail(email), now).changes === 1;
  const account = findAccountByEmail.get(emailHash);
  if (!account) {
    audit(intent, 'no_account');
    return { error: 'account_not_found' };
  }
  if (created) audit('account_created', 'ok', account.id);
  if (account.status !== 'active') {
    audit(intent, 'account_unavailable', account.id);
    return { error: 'account_unavailable' };
  }
  const totp = findTotpByAccount.get(account.id);
  if (totp && totp.enabled_at !== null) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    insertMfaChallenge.run(
      keyedHash('mfa-challenge', challenge), account.id, appSessionId, intent,
      replacedTokenHash, now, now + MFA_CHALLENGE_TTL_MS
    );
    audit('mfa_challenge', 'issued', account.id);
    return { mfaRequired: true, challenge, created, emailMasked: account.email_masked };
  }
  // A fresh token at every sign-in: nothing presented before authentication can become a signed-in session.
  if (replacedTokenHash) revokeAccountSession.run(now, replacedTokenHash);
  const token = crypto.randomBytes(32).toString('base64url');
  insertAccountSession.run(keyedHash('account-session', token), account.id, appSessionId, now, now + ACCOUNT_SESSION_MS);
  audit(intent, 'ok', account.id);
  return { token, created, emailMasked: account.email_masked };
});

const SIGN_IN_ERRORS = { verification_failed: 403, account_not_found: 404, account_unavailable: 403 };

function signInRoute(intent) {
  return (req, res) => {
    const email = normalizeEmail(req.body && req.body.email);
    const code = readEmailCode(req.body);
    if (!email) {
      res.status(400).json({ error: 'invalid_email' });
      return;
    }
    if (intent === 'signup' && isDisposableEmail(email)) {
      res.status(400).json({ error: 'email_not_allowed' });
      return;
    }
    if (!code) {
      res.status(400).json({ error: 'invalid_code' });
      return;
    }
    if (!emailCodeChecksAllowed(req)) {
      res.status(429).json({ error: 'rate_limited' });
      return;
    }
    const result = signInWithCode.immediate({
      intent,
      email,
      emailHash: keyedHash('email', email),
      code,
      appSessionId: req.appSessionId,
      ipHash: keyedHash('ip', req.ip),
      replacedTokenHash: currentAccount(req).tokenHash || null
    });
    if (result.error) {
      res.status(SIGN_IN_ERRORS[result.error]).json({ error: result.error });
      return;
    }
    if (result.mfaRequired) {
      res.status(202).json({ mfaRequired: true, challenge: result.challenge });
      return;
    }
    setAccountCookie(res, result.token, ACCOUNT_SESSION_MS / 1000);
    res.status(result.created ? 201 : 200).json({ authenticated: true, created: result.created, emailMasked: result.emailMasked });
  };
}

// Signup creates the account if the address has none (an existing account is signed in, never duplicated);
// login never creates one.
app.post('/api/account/signup', signInRoute('signup'));
app.post('/api/account/login', signInRoute('login'));

app.post('/api/account/mfa/verify', (req, res) => {
  const challenge = req.body && req.body.challenge;
  const code = req.body && req.body.code;
  if (typeof challenge !== 'string' || !ACCOUNT_TOKEN_PATTERN.test(challenge) ||
      typeof code !== 'string' || code.length > 32) {
    res.status(400).json({ error: 'invalid_mfa_input' });
    return;
  }
  if (!emailCodeChecksAllowed(req)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  const result = db.transaction(() => {
    const now = clock.now();
    const tokenHash = keyedHash('mfa-challenge', challenge);
    const pending = findMfaChallenge.get(tokenHash);
    if (!pending || pending.app_session_id !== req.appSessionId || pending.consumed_at !== null ||
        pending.expires_at <= now || pending.attempts >= MFA_MAX_ATTEMPTS) {
      return { error: 'mfa_failed' };
    }
    const totp = findTotpByAccount.get(pending.account_id);
    if (!totp || totp.enabled_at === null || !verifyTotpOrRecovery(pending.account_id, totp.secret_sealed, code, now)) {
      failMfaChallenge.run(MFA_MAX_ATTEMPTS, now, tokenHash);
      insertAuditEvent.run(now, 'mfa_verify', 'bad_code', pending.account_id, keyedHash('ip', req.ip));
      return { error: 'mfa_failed' };
    }
    if (consumeMfaChallenge.run(now, tokenHash).changes !== 1) return { error: 'mfa_failed' };
    const account = db.prepare('SELECT status, email_masked FROM accounts WHERE id = ?').get(pending.account_id);
    if (!account || account.status !== 'active') return { error: 'account_unavailable' };
    if (pending.replaced_token_hash) revokeAccountSession.run(now, pending.replaced_token_hash);
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    insertAccountSession.run(keyedHash('account-session', sessionToken), pending.account_id, req.appSessionId,
      now, now + ACCOUNT_SESSION_MS);
    insertAuditEvent.run(now, 'mfa_verify', 'ok', pending.account_id, keyedHash('ip', req.ip));
    return { token: sessionToken, intent: pending.intent, emailMasked: account.email_masked };
  }).immediate();
  if (result.error) {
    res.status(403).json({ error: result.error });
    return;
  }
  setAccountCookie(res, result.token, ACCOUNT_SESSION_MS / 1000);
  res.json({ authenticated: true, emailMasked: result.emailMasked });
});

app.get('/api/account', (req, res) => {
  const { presented, account } = currentAccount(req);
  if (!account) {
    if (presented) setAccountCookie(res, '', 0);
    res.json({ authenticated: false });
    return;
  }
  res.json({ authenticated: true, emailMasked: account.emailMasked });
});

app.get('/api/account/totp', (req, res) => {
  const { account } = currentAccount(req);
  if (!account) {
    res.status(401).json({ error: 'not_authenticated' });
    return;
  }
  const row = findTotpByAccount.get(account.id);
  const recovery = db.prepare('SELECT COUNT(*) AS count FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL').get(account.id);
  res.json({ enabled: Boolean(row && row.enabled_at !== null), recoveryCodesRemaining: recovery.count });
});

app.post('/api/account/totp/setup', (req, res) => {
  const { account } = currentAccount(req);
  if (!account) {
    res.status(401).json({ error: 'not_authenticated' });
    return;
  }
  const existing = findTotpByAccount.get(account.id);
  if (existing && existing.enabled_at !== null) {
    res.status(409).json({ error: 'totp_already_enabled' });
    return;
  }
  const secret = base32Encode(crypto.randomBytes(20));
  const result = saveTotpSecret.run(account.id, sealCode(secret, `account-totp:${account.id}`), clock.now());
  if (!result.changes) {
    res.status(409).json({ error: 'totp_already_enabled' });
    return;
  }
  res.json({ secret, issuer: 'Product Labels', account: account.emailMasked });
});

app.post('/api/account/totp/enable', (req, res) => {
  const { account } = currentAccount(req);
  if (!account) {
    res.status(401).json({ error: 'not_authenticated' });
    return;
  }
  const code = req.body && req.body.code;
  const row = findTotpByAccount.get(account.id);
  if (!row || row.enabled_at !== null || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    res.status(400).json({ error: 'invalid_totp_setup' });
    return;
  }
  let secret;
  try { secret = openCode(row.secret_sealed, `account-totp:${account.id}`); } catch {
    res.status(500).json({ error: 'totp_unavailable' });
    return;
  }
  const now = clock.now();
  if (!validTotp(secret, code, now)) {
    res.status(403).json({ error: 'invalid_totp_code' });
    return;
  }
  const recoveryCodes = Array.from({ length: 10 }, newRecoveryCode);
  db.transaction(() => {
    if (!enableTotp.run(now, now, account.id).changes) throw new Error('TOTP enrollment changed concurrently.');
    clearRecoveryCodes.run(account.id);
    for (const recoveryCode of recoveryCodes) {
      const normalized = normalizedRecoveryCode(recoveryCode);
      insertRecoveryCode.run(account.id, keyedHash('recovery-code', `${account.id}:${normalized}`), now);
    }
    insertAuditEvent.run(now, 'totp_enabled', 'ok', account.id, keyedHash('ip', req.ip));
  }).immediate();
  res.json({ enabled: true, recoveryCodes });
});

app.post('/api/account/totp/disable', (req, res) => {
  const { account } = currentAccount(req);
  if (!account) {
    res.status(401).json({ error: 'not_authenticated' });
    return;
  }
  const code = req.body && req.body.code;
  const row = findTotpByAccount.get(account.id);
  if (!row || row.enabled_at === null || typeof code !== 'string' || code.length > 32) {
    res.status(400).json({ error: 'invalid_totp_code' });
    return;
  }
  const now = clock.now();
  const removed = db.transaction(() => {
    if (!verifyTotpOrRecovery(account.id, row.secret_sealed, code, now)) return false;
    deleteTotp.run(account.id);
    clearRecoveryCodes.run(account.id);
    insertAuditEvent.run(now, 'totp_disabled', 'ok', account.id, keyedHash('ip', req.ip));
    return true;
  }).immediate();
  if (!removed) {
    res.status(403).json({ error: 'invalid_totp_code' });
    return;
  }
  res.json({ enabled: false });
});

app.post('/api/account/logout', (req, res) => {
  const { tokenHash, account } = currentAccount(req);
  if (tokenHash) {
    db.transaction(() => {
      const now = clock.now();
      if (revokeAccountSession.run(now, tokenHash).changes && account) {
        insertAuditEvent.run(now, 'logout', 'ok', account.id, keyedHash('ip', req.ip));
      }
    }).immediate();
  }
  setAccountCookie(res, '', 0);
  res.json({ authenticated: false });
});

// Device keys: an ECDSA P-256 key pair made in the browser (device-key.js) whose private half never leaves
// it. A device exists only after the key signed a fresh server challenge; neither the account cookie nor
// anything about the browser stands in for that signature.
const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function readPublicKey(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.hasOwn(value, 'd')) return null;
  const { kty, crv, x, y } = value;
  if (kty !== 'EC' || crv !== 'P-256' || !COORDINATE_PATTERN.test(x) || !COORDINATE_PATTERN.test(y)) return null;
  const jwk = { kty, crv, x, y };
  let key;
  try {
    key = crypto.createPublicKey({ key: jwk, format: 'jwk' }); // Also rejects points that are not on the curve.
  } catch {
    return null;
  }
  return { jwk, key, thumbprint: jwkThumbprint(jwk) };
}

// The browser binding is a hash, so the challenge never shows the HttpOnly session id to page scripts.
const challengeSession = (req) => keyedHash('device-challenge-session', req.appSessionId).slice(0, 32);
const challengeMac = (body) => crypto.createHmac('sha256', deviceChallengeKey).update(body).digest('base64url');

function issueDeviceChallenge(claims) {
  const body = Buffer.from(JSON.stringify({ v: 1, ...claims, n: crypto.randomBytes(16).toString('base64url') }))
    .toString('base64url');
  return `${body}.${challengeMac(body)}`;
}

function readDeviceChallenge(token, purpose, now) {
  if (typeof token !== 'string' || token.length > 1024) return null;
  const [body, mac, extra] = token.split('.');
  if (!body || !mac || extra !== undefined || !safeEqual(mac, challengeMac(body))) return null;
  let claims;
  try {
    claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  const valid = claims && claims.v === 1 && claims.p === purpose &&
    Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) && claims.iat <= now && now < claims.exp;
  return valid ? claims : null;
}

function verifyDeviceSignature(key, challenge, signature) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  try {
    return crypto.verify('sha256', Buffer.from(DEVICE_PROOF_PREFIX + challenge),
      { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

function signedInAccount(req, res) {
  const { account } = currentAccount(req);
  if (!account) res.status(401).json({ error: 'not_authenticated' });
  return account;
}

function deviceLimitsAllowed(kind, accountId, req, perAccount) {
  return consumeRateLimit.immediate(`device-${kind}:ip:${keyedHash('ip', req.ip)}`, 60, HOUR) &&
    consumeRateLimit.immediate(`device-${kind}:account:${accountId}`, perAccount, HOUR);
}

// One active device per account: checked here under the write lock and enforced again by devices_one_active.
const registerDevice = db.transaction(({ accountId, publicKey, now, ipHash }) => {
  const audit = (outcome, deviceId = null) => insertDeviceAudit.run(now, 'device_register', outcome, accountId, deviceId, ipHash);
  const account = selectAccountStatus.get(accountId);
  if (!account || account.status !== 'active') {
    audit('account_unavailable');
    return { error: 'account_unavailable' };
  }
  if (findDeviceByThumbprint.get(publicKey.thumbprint)) {
    audit('key_unavailable');
    return { error: 'key_unavailable' };
  }
  if (findActiveDevice.get(accountId)) {
    audit('device_limit_reached');
    return { error: 'device_limit_reached' };
  }
  const id = crypto.randomBytes(16).toString('base64url');
  insertDevice.run(id, accountId, publicKey.thumbprint, JSON.stringify(publicKey.jwk), now, now);
  audit('ok', id);
  return { registeredAt: now };
});

app.get('/api/devices', (req, res) => {
  const account = signedInAccount(req, res);
  if (!account) return;
  const device = findActiveDevice.get(account.id);
  res.json({ device: device ? {
    keyThumbprint: device.key_thumbprint,
    registeredAt: device.registered_at,
    lastValidatedAt: device.last_validated_at
  } : null });
});

app.post('/api/devices/challenge', (req, res) => {
  const account = signedInAccount(req, res);
  if (!account) return;
  const purpose = req.body && req.body.purpose;
  if (purpose !== 'register' && purpose !== 'prove' && purpose !== 'certificate') {
    res.status(400).json({ error: 'invalid_purpose' });
    return;
  }
  const publicKey = readPublicKey(req.body.publicKey);
  if (!publicKey) {
    res.status(400).json({ error: 'invalid_public_key' });
    return;
  }
  if (!deviceLimitsAllowed('challenge', account.id, req, 30)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  const active = findActiveDevice.get(account.id);
  let deviceId = null;
  if (purpose === 'register') {
    const owner = findDeviceByThumbprint.get(publicKey.thumbprint);
    const error = owner ? (owner.account_id === account.id && owner.revoked_at === null ? 'already_registered' : 'key_unavailable')
      : active ? 'device_limit_reached' : null;
    if (error) {
      res.status(409).json({ error });
      return;
    }
  } else {
    if (!active || active.key_thumbprint !== publicKey.thumbprint) {
      res.status(409).json({ error: 'device_not_registered' });
      return;
    }
    deviceId = active.id;
  }
  const now = clock.now();
  const challenge = issueDeviceChallenge({
    p: purpose, acc: account.id, ses: challengeSession(req), key: publicKey.thumbprint, dev: deviceId,
    iat: now, exp: now + DEVICE_CHALLENGE_TTL_MS
  });
  res.json({ challenge, expiresInSeconds: DEVICE_CHALLENGE_TTL_MS / 1000 });
});

app.get('/api/license/keys', (_req, res) => {
  if (!licenseSigner) {
    res.status(503).json({ error: 'license_signing_not_configured' });
    return;
  }
  res.json({ keys: { [licenseSigner.kid]: licenseSigner.publicJwk } });
});

app.post('/api/license/certificate', (req, res) => {
  const account = signedInAccount(req, res);
  if (!account) return;
  if (!licenseSigner) {
    res.status(503).json({ error: 'license_signing_not_configured' });
    return;
  }
  const publicKey = readPublicKey(req.body && req.body.publicKey);
  if (!publicKey) {
    res.status(400).json({ error: 'invalid_public_key' });
    return;
  }
  if (!deviceLimitsAllowed('proof', account.id, req, 20)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  const now = clock.now();
  const ipHash = keyedHash('ip', req.ip);
  const claims = readDeviceChallenge(req.body.challenge, 'certificate', now);
  const device = claims && typeof claims.dev === 'string' ? findDevice.get(claims.dev) : null;
  const proven = device && device.account_id === account.id && device.revoked_at === null &&
    claims.acc === account.id && claims.ses === challengeSession(req) &&
    claims.key === device.key_thumbprint && claims.key === publicKey.thumbprint &&
    verifyDeviceSignature(crypto.createPublicKey({ key: JSON.parse(device.public_key_jwk), format: 'jwk' }),
      req.body.challenge, req.body.signature);
  if (!proven) {
    insertDeviceAudit.run(now, 'license_certificate', 'proof_failed', account.id, device && device.account_id === account.id ? device.id : null, ipHash);
    res.status(403).json({ error: 'proof_failed' });
    return;
  }
  const result = db.transaction(() => {
    const changed = markDeviceValidated.run(now, device.id, account.id, claims.iat).changes === 1;
    if (!changed) return { error: 'proof_failed' };
    const accountStatus = selectAccountStatus.get(account.id);
    if (!accountStatus || accountStatus.status !== 'active') return { error: 'account_unavailable' };
    const purchase = findActiveAccountPurchase.get(account.id);
    let issued;
    if (purchase) {
      issued = licenseSigner.issuePaid({ accountId: account.id, deviceThumbprint: device.key_thumbprint, now });
    } else {
      let trial = findAccountTrial.get(account.id);
      if (!trial) {
        insertAccountTrial.run(account.id, device.key_thumbprint, now, now + TRIAL_MS);
        trial = findAccountTrial.get(account.id);
      }
      if (trial.device_thumbprint !== device.key_thumbprint) return { error: 'trial_already_used' };
      if (trial.expires_at <= now) return { error: 'trial_expired' };
      issued = licenseSigner.issueTrial({ accountId: account.id, deviceThumbprint: device.key_thumbprint, now, trialExpiresAt: trial.expires_at });
    }
    const { jti, typ, kid, iat, exp, rva, grc } = issued.claims;
    insertLicenseCertificate.run(jti, device.id, typ, kid, iat, exp || null, rva || null, grc || null);
    insertDeviceAudit.run(now, 'license_certificate', 'issued', account.id, device.id, ipHash);
    return { certificate: issued.token, type: typ, expiresAt: exp || null, revalidateAt: rva || null, graceUntil: grc || null };
  }).immediate();
  if (result.error) {
    res.status(result.error === 'account_unavailable' ? 403 : 409).json({ error: result.error });
    return;
  }
  res.json(result);
});

app.post('/api/devices/register', (req, res) => {
  const account = signedInAccount(req, res);
  if (!account) return;
  const publicKey = readPublicKey(req.body && req.body.publicKey);
  if (!publicKey) {
    res.status(400).json({ error: 'invalid_public_key' });
    return;
  }
  if (!deviceLimitsAllowed('proof', account.id, req, 20)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  const now = clock.now();
  const ipHash = keyedHash('ip', req.ip);
  const claims = readDeviceChallenge(req.body.challenge, 'register', now);
  // Proof of possession: the challenge is ours, current, for this account, browser and key, and that key signed it.
  const proven = claims && claims.acc === account.id && claims.ses === challengeSession(req) &&
    claims.key === publicKey.thumbprint && claims.dev === null &&
    verifyDeviceSignature(publicKey.key, req.body.challenge, req.body.signature);
  if (!proven) {
    insertDeviceAudit.run(now, 'device_register', 'proof_failed', account.id, null, ipHash);
    res.status(403).json({ error: 'proof_failed' });
    return;
  }
  // A key can be registered once, ever (key_thumbprint is unique), so a register challenge succeeds at most once.
  const result = registerDevice.immediate({ accountId: account.id, publicKey, now, ipHash });
  if (result.error) {
    res.status(409).json({ error: result.error });
    return;
  }
  res.status(201).json({ registered: true, keyThumbprint: publicKey.thumbprint, registeredAt: result.registeredAt });
});

app.post('/api/devices/verify', (req, res) => {
  const account = signedInAccount(req, res);
  if (!account) return;
  const publicKey = readPublicKey(req.body && req.body.publicKey);
  if (!publicKey) {
    res.status(400).json({ error: 'invalid_public_key' });
    return;
  }
  if (!deviceLimitsAllowed('proof', account.id, req, 20)) {
    res.status(429).json({ error: 'rate_limited' });
    return;
  }
  const now = clock.now();
  const ipHash = keyedHash('ip', req.ip);
  const claims = readDeviceChallenge(req.body.challenge, 'prove', now);
  const device = claims && typeof claims.dev === 'string' ? findDevice.get(claims.dev) : null;
  // The signature is checked with the key stored at registration, never with the one in the request.
  const proven = device && device.account_id === account.id && device.revoked_at === null &&
    claims.acc === account.id && claims.ses === challengeSession(req) &&
    claims.key === device.key_thumbprint && claims.key === publicKey.thumbprint &&
    verifyDeviceSignature(crypto.createPublicKey({ key: JSON.parse(device.public_key_jwk), format: 'jwk' }),
      req.body.challenge, req.body.signature);
  const verified = Boolean(proven) && db.transaction(() => {
    const changed = markDeviceValidated.run(now, device.id, account.id, claims.iat).changes === 1;
    insertDeviceAudit.run(now, 'device_verify', changed ? 'ok' : 'challenge_used', account.id, device.id, ipHash);
    return changed;
  }).immediate();
  if (!verified) {
    if (!proven) {
      const ownDevice = device && device.account_id === account.id ? device.id : null;
      insertDeviceAudit.run(now, 'device_verify', 'proof_failed', account.id, ownDevice, ipHash);
    }
    res.status(403).json({ error: 'proof_failed' });
    return;
  }
  res.json({ verified: true, keyThumbprint: device.key_thumbprint, lastValidatedAt: now });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found' }));
app.get(['/', '/index.html'], (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/manifest.webmanifest', (_req, res) => res.sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/sw.js', (_req, res) => res.sendFile(path.join(__dirname, 'sw.js')));
app.get('/device-key.js', (_req, res) => res.sendFile(path.join(__dirname, 'device-key.js')));
app.get('/license-client.js', (_req, res) => res.sendFile(path.join(__dirname, 'license-client.js')));
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
  // Provider and database exceptions can echo request data. Keep operational logs free of
  // attacker-controlled values, credentials, and customer data.
  console.error(`Request failed (${safeErrorCode(error)}).`);
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
