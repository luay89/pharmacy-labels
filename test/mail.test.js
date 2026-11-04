'use strict';

const assert = require('node:assert/strict');
const net = require('node:net');
const { test } = require('node:test');
const { createMailer, readMailConfig, templates, normalizeEmail, maskEmail } = require('../mail');

test('SMTP settings are validated and read only from the environment', () => {
  assert.deepEqual(readMailConfig({}), { configured: false });
  assert.equal(createMailer({}).configured, false);
  assert.throws(() => readMailConfig({ SMTP_HOST: 'smtp.example.test', SMTP_PORT: '99999', MAIL_FROM: 'a@example.com' }), /SMTP_PORT/);
  assert.throws(() => readMailConfig({ SMTP_HOST: 'smtp.example.test', SMTP_SECURE: 'yes', MAIL_FROM: 'a@example.com' }), /SMTP_SECURE/);
  assert.throws(() => readMailConfig({ SMTP_HOST: 'smtp.example.test', SMTP_USER: 'user', MAIL_FROM: 'a@example.com' }), /SMTP_USER and SMTP_PASS/);
  assert.throws(() => readMailConfig({ SMTP_HOST: 'smtp.example.test', MAIL_FROM: 'Labels <a@example.com>' }), /MAIL_FROM/);
  const config = readMailConfig({
    SMTP_HOST: 'smtp.example.test', SMTP_PORT: '465', SMTP_USER: 'user', SMTP_PASS: 'pass',
    MAIL_FROM: 'Sales@Example.com', NODE_ENV: 'production'
  });
  assert.equal(config.secure, true);
  assert.equal(config.from, 'sales@example.com');
  assert.equal(config.requireTLS, true);
});

test('unconfigured mailer refuses to send', async () => {
  await assert.rejects(createMailer({}).send({ to: 'a@example.com', subject: 's', text: 't' }),
    (error) => error.code === 'mail_not_configured');
});

test('SMTP connection failures are reported without credentials or recipients', async () => {
  const blocker = net.createServer((socket) => socket.destroy());
  await new Promise((resolve) => blocker.listen(0, '127.0.0.1', resolve));
  const { port } = blocker.address();
  try {
    const mailer = createMailer({
      SMTP_HOST: '127.0.0.1', SMTP_PORT: String(port), SMTP_SECURE: 'false',
      SMTP_USER: 'smtp-user', SMTP_PASS: 'SuperSecretPass', MAIL_FROM: 'labels@example.com'
    });
    await assert.rejects(mailer.send({ to: 'buyer@example.com', subject: 'Hello', text: 'Body' }), (error) => {
      assert.equal(error.message, 'Email delivery failed.');
      assert.match(error.code, /^[A-Za-z_]+$/);
      assert.doesNotMatch(JSON.stringify({ message: error.message, code: error.code, stack: error.stack }),
        /SuperSecretPass|smtp-user|buyer@example\.com/);
      return true;
    });
    await assert.rejects(mailer.send({ to: 'bad"address@example.com', subject: 's', text: 't' }),
      (error) => error.code === 'invalid_recipient');
  } finally {
    blocker.close();
  }
});

test('an SMTP login rejected by IP policy reports EAUTH and status 525 without the reply text', async () => {
  // Minimal SMTP peer that answers AUTH like Brevo does for an IP that is not on the authorized list.
  const fake = net.createServer((socket) => {
    socket.write('220 fake.smtp.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      for (const line of chunk.toString().split('\r\n').filter(Boolean)) {
        if (/^EHLO/i.test(line)) socket.write('250-fake.smtp.test\r\n250 AUTH PLAIN LOGIN\r\n');
        else if (/^AUTH/i.test(line)) socket.write('525 5.7.1 Unauthorized IP address 203.0.113.9\r\n');
        else if (/^QUIT/i.test(line)) socket.end('221 bye\r\n');
      }
    });
  });
  await new Promise((resolve) => fake.listen(0, '127.0.0.1', resolve));
  try {
    const mailer = createMailer({
      SMTP_HOST: '127.0.0.1', SMTP_PORT: String(fake.address().port), SMTP_SECURE: 'false',
      SMTP_USER: 'login@smtp-brevo.com', SMTP_PASS: 'xsmtpsib-NotARealKey', MAIL_FROM: 'labels@example.com'
    });
    await assert.rejects(mailer.send({ to: 'buyer@example.com', subject: 's', text: 't' }), (error) => {
      assert.equal(error.code, 'EAUTH');
      assert.equal(error.smtpStatus, 525);
      assert.doesNotMatch(JSON.stringify({ ...error, message: error.message }), /Unauthorized|203\.0\.113|xsmtpsib|login@/);
      return true;
    });
  } finally {
    fake.close();
  }
});

test('email helpers normalize, mask and escape safely', () => {
  assert.equal(normalizeEmail('  Person@Example.COM '), 'person@example.com');
  for (const bad of ['a b@example.com', 'a@b', '"q"@example.com', 'a@example.com,b@example.com', 'x(y)@example.com', null, 5]) {
    assert.equal(normalizeEmail(bad), null);
  }
  assert.equal(maskEmail('person@mail.example.com'), 'pe***@m***.com');
  assert.equal(maskEmail('ab@example.org'), 'a***@e***.org');

  const confirmation = templates.purchaseConfirmation({
    orderRef: 'PL-ABCDEFGHJK', amountTotal: 500, currency: 'usd', supportEmail: 'help@example.com'
  });
  assert.match(confirmation.subject, /PL-ABCDEFGHJK/);
  assert.match(confirmation.text, /5\.00 USD/);
  assert.match(confirmation.text, /one device at a time/);
  assert.match(confirmation.text, /help@example\.com/);

  const accountConfirmation = templates.purchaseConfirmation({
    orderRef: 'PL-ACCOUNT123', amountTotal: 500, currency: 'usd', licensePolicy: 'single_device', supportEmail: null
  });
  assert.match(accountConfirmation.text, /attached to the account/);
  assert.doesNotMatch(accountConfirmation.text, /transfer the license once/);

  const transfer = templates.transferCode({ code: '12345678', minutes: 10, orderRef: '<b>PL</b>', supportEmail: null });
  assert.match(transfer.text, /12345678/);
  assert.match(transfer.text, /expires in 10 minutes/);
  assert.match(transfer.text, /Never share it/);
  assert.match(transfer.text, /disables the license on the previous device/);
  assert.match(transfer.html, /&lt;b&gt;PL&lt;\/b&gt;/);
  assert.doesNotMatch(transfer.html, /<b>PL<\/b>/);
});
