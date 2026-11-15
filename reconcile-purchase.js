'use strict';

const path = require('node:path');
const { openDatabase } = require('./db');

const USAGE = 'Usage: npm run reconcile-purchase -- <payment_intent_id> <test|live> <review-reference> --operator-reviewed [--exclude-from-entitlements]';

function main(args) {
  const [paymentIntentId, stripeMode, reviewReference, confirmation, ...options] = args;
  const excludeFromEntitlements = options.length === 1 && options[0] === '--exclude-from-entitlements';
  if ((options.length > 0 && !excludeFromEntitlements) ||
      !/^pi_[A-Za-z0-9]+$/.test(paymentIntentId || '') ||
      !['test', 'live'].includes(stripeMode) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,63}$/.test(reviewReference || '') ||
      confirmation !== '--operator-reviewed' ||
      (excludeFromEntitlements && stripeMode !== 'test')) {
    throw new Error(USAGE);
  }

  const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
  const { db } = openDatabase(dataDir);
  try {
    const result = db.transaction(() => {
      const purchase = db.prepare(`
        SELECT stripe_mode, stripe_mode_review_reference, app_session_id, status, excluded_from_entitlements
        FROM stripe_purchases WHERE payment_intent_id = ?
      `).get(paymentIntentId);
      if (!purchase) throw new Error('Purchase was not found.');
      if (purchase.stripe_mode !== null && purchase.stripe_mode !== stripeMode) {
        throw new Error('Reviewed Stripe mode does not match the stored Checkout ID classification; no change was made.');
      }
      if (purchase.stripe_mode_review_reference !== null) {
        throw new Error('Purchase already has an operator review; no change was made.');
      }

      const couldEntitle = purchase.app_session_id !== null &&
        ['active', 'disputed'].includes(purchase.status) &&
        purchase.excluded_from_entitlements === 0;
      if (stripeMode === 'test' && couldEntitle && !excludeFromEntitlements) {
        throw new Error('An active or disputed test purchase requires the explicit --exclude-from-entitlements decision.');
      }
      if (excludeFromEntitlements && !couldEntitle) {
        throw new Error('This purchase cannot affect an entitlement; exclusion is not applicable.');
      }

      const update = db.prepare(`
        UPDATE stripe_purchases SET
          stripe_mode = ?, stripe_mode_review_reference = ?, stripe_mode_reviewed_at = ?,
          excluded_from_entitlements = ?
        WHERE payment_intent_id = ? AND stripe_mode_review_reference IS NULL
      `).run(stripeMode, reviewReference, Date.now(), excludeFromEntitlements ? 1 : 0, paymentIntentId);
      if (update.changes !== 1) throw new Error('Purchase changed during reconciliation; no change was made.');

      if (excludeFromEntitlements) {
        db.prepare(`
          UPDATE app_sessions
          SET unlocked = CASE WHEN unlocked = 1 AND NOT EXISTS (
              SELECT 1 FROM stripe_purchases
              WHERE stripe_purchases.app_session_id = app_sessions.id
                AND stripe_purchases.status = 'active'
                AND stripe_purchases.excluded_from_entitlements = 0
            ) THEN 0 ELSE unlocked END
          WHERE id = ?
        `).run(purchase.app_session_id);
      }
      return true;
    }).immediate();

    if (result) {
      console.log(excludeFromEntitlements
        ? 'Stripe mode recorded; the reviewed test purchase was excluded from entitlements. Purchase status was not changed.'
        : 'Stripe mode recorded after operator review; purchase status and entitlements were not changed.');
    }
  } finally {
    db.close();
  }
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`Purchase reconciliation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
