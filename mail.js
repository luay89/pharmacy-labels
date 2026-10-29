'use strict';

const nodemailer = require('nodemailer');

const APP_NAME = 'Product Labels';
// Deliberately narrower than RFC 5322: no quotes, comments, brackets or separators reach the mailer.
const EMAIL_PATTERN = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL_PATTERN.test(email) ? email : null;
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  const labels = domain.split('.');
  const tld = labels.pop();
  const visible = local.length > 2 ? local.slice(0, 2) : local.slice(0, 1);
  return `${visible}***@${labels.join('.').slice(0, 1)}***.${tld}`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function formatAmount(cents, currency) {
  return `${(cents / 100).toFixed(2)} ${String(currency).toUpperCase()}`;
}

function layout(title, paragraphs) {
  const text = [title, '', ...paragraphs, '', `— ${APP_NAME}`].join('\n');
  const html = `<!doctype html><html><body style="font-family:Arial,sans-serif;line-height:1.5;color:#1f2933;max-width:560px;margin:0 auto;padding:24px">
<h2 style="margin-top:0">${escapeHtml(title)}</h2>
${paragraphs.map((p) => `<p>${escapeHtml(p)}</p>`).join('\n')}
<p style="color:#6b7280;font-size:13px">— ${escapeHtml(APP_NAME)}</p>
</body></html>`;
  return { text, html };
}

function supportLine(supportEmail) {
  return supportEmail
    ? `Need help? Reply to this email or contact ${supportEmail} and include your order reference.`
    : 'Need help? Reply to this email and include your order reference.';
}

const templates = {
  purchaseConfirmation({ orderRef, amountTotal, currency, supportEmail }) {
    const subject = `${APP_NAME}: purchase confirmed (${orderRef})`;
    return { subject, ...layout('Your purchase is complete', [
      `Thank you for buying ${APP_NAME}. Your payment of ${formatAmount(amountTotal, currency)} was confirmed.`,
      `Order reference: ${orderRef}`,
      'Your license is active on one device at a time: the device you used to complete the purchase.',
      'If you move to a new device, you can transfer the license once from the app by confirming this email address.',
      supportLine(supportEmail)
    ]) };
  },
  transferCode({ code, minutes, orderRef, supportEmail }) {
    const subject = `${APP_NAME}: license transfer code`;
    return { subject, ...layout('License transfer request', [
      `Someone asked to move the ${APP_NAME} license for order ${orderRef} to a new device.`,
      `Your verification code is: ${code}`,
      `The code expires in ${minutes} minutes and can be used only once. Never share it with anyone.`,
      'Completing the transfer disables the license on the previous device and uses your only allowed transfer.',
      'If you did not request this, ignore this email; the license stays where it is. ' + supportLine(supportEmail)
    ]) };
  },
  transferUnavailable({ orderRef, reason, supportEmail }) {
    const subject = `${APP_NAME}: license transfer not available`;
    const explanation = reason === 'transfer_used'
      ? 'The one transfer allowed for this license has already been used, so it cannot be moved again automatically.'
      : 'This license is not active (for example, the payment was refunded or is under dispute), so it cannot be transferred.';
    return { subject, ...layout('License transfer not available', [
      `We received a request to move the ${APP_NAME} license for order ${orderRef} to a new device.`,
      explanation,
      'If you did not make this request, no action is needed. ' + supportLine(supportEmail)
    ]) };
  }
};

function readMailConfig(env) {
  const host = (env.SMTP_HOST || '').trim();
  if (!host) return { configured: false };
  const port = Number(env.SMTP_PORT || 587);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SMTP_PORT must be a valid port number.');
  if (env.SMTP_SECURE && !['true', 'false'].includes(env.SMTP_SECURE)) {
    throw new Error('SMTP_SECURE must be "true" or "false".');
  }
  const user = env.SMTP_USER || '';
  const pass = env.SMTP_PASS || '';
  if (Boolean(user) !== Boolean(pass)) throw new Error('SMTP_USER and SMTP_PASS must be set together.');
  const from = normalizeEmail(env.MAIL_FROM || '');
  if (!from) throw new Error('MAIL_FROM must be a plain email address when SMTP_HOST is set.');
  return {
    configured: true,
    host,
    port,
    secure: env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : port === 465,
    auth: user ? { user, pass } : undefined,
    from,
    requireTLS: env.NODE_ENV === 'production'
  };
}

function createMailer(env) {
  const config = readMailConfig(env);
  const mailer = {
    configured: config.configured,
    async send() {
      throw Object.assign(new Error('Email delivery is not configured.'), { code: 'mail_not_configured' });
    }
  };
  if (!config.configured) return mailer;
  const transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    requireTLS: !config.secure && config.requireTLS,
    auth: config.auth,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000
  });
  mailer.send = async ({ to, subject, text, html }) => {
    if (!normalizeEmail(to)) throw Object.assign(new Error('Invalid recipient.'), { code: 'invalid_recipient' });
    try {
      await transport.sendMail({ from: `${APP_NAME} <${config.from}>`, to, subject, text, html });
    } catch (error) {
      // Never surface transport details (they can echo credentials or recipient addresses).
      const code = /^[A-Za-z_]{1,32}$/.test(error && error.code) ? error.code : 'send_failed';
      // The numeric SMTP status (e.g. 525) is safe to log and pinpoints the cause; the reply text is not kept.
      const status = Number.isInteger(error && error.responseCode) ? error.responseCode : undefined;
      throw Object.assign(new Error('Email delivery failed.'), { code, smtpStatus: status });
    }
  };
  return mailer;
}

module.exports = { createMailer, readMailConfig, templates, normalizeEmail, maskEmail, APP_NAME };
