# Product Labels: Engineering Handoff for Codex

State as of 2026-10-31. Branch `server-checkout`. Verify this document against the code before acting on it; the code wins.

## Current state override (2026-11-03)

This update supersedes older implementation, validation, phase-approval, and known-gap statements below when they conflict. The owner explicitly authorized continued local implementation, checks, and deployment preparation. Do not commit, push, merge, contact production, or deploy without explicit authorization. Keep all existing uncommitted work.

- Current schema is v7. Email-code accounts, TOTP and one-use recovery codes, device-key proofs, support recovery, account-bound new checkout, signed trial/paid certificates, browser verification, offline grace/read-only behavior, and security headers are implemented in the current tree. The corresponding local tests are in `test/`; verify details there and in source rather than relying on the older phase table.
- Latest local run on 2026-11-03: `npm run check` passed; `npm test` passed 147/147 with 0 skipped; Chromium/CDP browser suites ran; `git diff --check` passed; Android `index.html` copies match. No real database, Gradle build, real email, or payment was used.
- `.github/workflows/ci.yml` is an uncommitted local workflow scoped to `server-checkout`. It runs dependency audit, checks, tests, an image build, Chromium availability, whitespace checks, and Android asset comparison. GitHub reports no workflow file or run on the remote `server-checkout` branch yet. Do not commit or push merely to trigger it.
- `README.md` now contains production preparation guidance. The local `.env` configuration was checked without printing values: it is development/test-mode configuration, and no license signing key or key id is configured. Do not treat local settings as production-ready.
- `npm audit --omit=dev` could not reach `registry.npmjs.org` (`EAI_AGAIN`). A read-only Stripe test-mode balance request was guarded to refuse non-test keys but could not connect; no checkout or payment was created. Reattempt these when network access is available.
- Docker Engine is not accessible in this workspace and no rootless OCI builder or Buildx is installed. A local production-configured health smoke test was blocked by sandbox TCP binding. CI builds the image on GitHub's hosted Ubuntu runner once the workflow is published and run.
- Items still requiring owner or external setup: permission to commit/push for remote Actions verification; HTTPS hosting and domain, persistent production storage and backup destination, deployment secrets (production `SESSION_SECRET`, Stripe keys/webhook secret when approved, SMTP sender/provider credentials, and P-256 license key plus `LICENSE_SIGNING_KID`); a real owned mailbox for delivery smoke checks. Never use Live Stripe for tests.
- Re-audit older §12 bullets against current code; several are stale. Legacy purchase claiming, retention periods for account sessions/audit events, and operational account suspension are not confirmed as completed and may require policy choices. Android remains a separate scope; do not run Gradle without a new request.

## 1. Read this first

- **Nothing from Phase 3 onward is committed.** All of it sits in the working tree on `server-checkout`. Do not run `git stash`, `git reset`, `git checkout -- <file>` or `git clean`.
- **Do not start the server against the default data directory.** `server.js` opens `DATA_DIR` (default `./data`) on `require`, and `openDatabase` migrates on open. `npm start` or a bare `require('./server')` would migrate the real database from v0 to v5.
- **`main` feeds the live GitHub Pages site**, which cannot run `server.js`. Never merge to `main` before the server is deployed on HTTPS.
- **Work is phase-gated.** The owner approves each phase explicitly. No phase is approved right now. Stop and ask if a task needs a business decision or leaves the approved scope.

## 2. What the product is and where it is going

Product Labels is a web app for making and printing barcode and QR labels for products, aimed at shops and pharmacies. Products live in the browser's `localStorage`, and rendering and printing happen client-side. It is available in 11 languages (`en`, `ar`, `zh`, `hi`, `es`, `fr`, `pt`, `ur`, `ru`, `ja`, `de`). The license is a one-time payment of $5 USD through Stripe.

**The goal of the current work** is to replace an anonymous cookie license with an account-and-device license that survives offline use and resists copying:

| Topic | Today (running code) | Target (confirmed by the owner, 2026-10-30) |
| --- | --- | --- |
| Identity | Anonymous signed cookie | Passwordless email-code account, in addition to the cookie |
| Trial | 20 labels per session, counted on the server | 48 hours of server time, starting after email verification |
| New licenses | Bound to the anonymous session, one transfer | One account on one device, no transfer |
| Device recovery | None | Support only, about once per 12 months, after proving account and purchase ownership |
| Legacy purchases | Cookie license with one transfer | Keep working and keep transfer rights until claimed from the browser holding the license, after an email code |
| Offline | App locks when the server is unreachable | Trial works offline until it ends. Paid certificates revalidate every 30 days, with 14 days of grace if the server is unreachable. After grace, read-only |
| Read-only mode | Does not exist | View, search, browse and Excel export allowed. Creating labels, printing and import blocked |

Fixed: price stays $5 USD, the stack stays Express, SQLite and Brevo SMTP, there is no separate licensing service, the signing key stays separate from `SESSION_SECRET`, and disposable email domains are blocked by a maintained list that is not the only defence. Android is out of scope until a later phase of its own.

## 3. Stack and commands

Node 22.9 or newer, Express 5, better-sqlite3 (WAL, `foreign_keys=ON`, `user_version` migrations, `VACUUM INTO` backups), Stripe 18, nodemailer through Brevo SMTP, express-rate-limit. Browser code is plain JavaScript inside `index.html`, with no build step.

```
npm run check     # node --check on server.js, db.js, mail.js, backup.js, license-cert.js, device-key.js
npm test          # node --test; every test uses a temporary DATA_DIR
git diff --check
```

Run a single file with `node --test test/<name>.test.js`. Browser tests drive headless Chromium over CDP and skip when no browser is found (`CHROME_PATH` overrides detection).

## 4. Repository map

| Path | Role |
| --- | --- |
| `server.js` | All routes, prepared statements, sessions, outbox delivery, rate limiting |
| `db.js` | Migrations, backup, `openDatabase`. `SCHEMA_VERSION` is `MIGRATIONS.length`, currently 5 |
| `mail.js` | SMTP mailer, templates, `normalizeEmail`, `maskEmail`, disposable domain list |
| `license-cert.js` | ECDSA P-256 offline certificates. **Node only and isolated:** the app imports only `jwkThumbprint` from it |
| `device-key.js` | Browser device key (WebCrypto and IndexedDB). Served at `/device-key.js`, loaded on demand |
| `index.html` | The whole web app, about 1.3 MB: UI, 11-language `I18N`, embedded libraries |
| `sw.js` | Service worker, cache `product-labels-v8` |
| `android/app/src/main/assets/index.html` | Byte-identical copy of `index.html`, enforced by `test/ui.test.js` |
| `test/` | 17 files, 138 tests |

## 5. What has been built

Git history holds the Stripe checkout, the 20-label trial and the legacy transfer (`7f0cc85`, `f00e143`, `90c90fb`). `90c90fb` and `f00e143` are local only: `origin/server-checkout` is two commits behind, as of the last fetch.

Everything below is uncommitted:

| Phase | Result | Main files |
| --- | --- | --- |
| 3 | Additive migration v4: `accounts`, `account_codes`, `devices`, `trials`, `license_certificates`, `audit_events`, plus `license_policy` (default `legacy`) and `account_id` on purchases | `db.js` |
| 4 | Certificate signing and verification, not wired into the app | `license-cert.js` |
| 5 | Email verification codes through the existing outbox | `server.js`, `mail.js` |
| 6 | Accounts, passwordless sign-in, migration v5 `account_sessions` | `server.js`, `db.js` |
| 7 | Device key registration and cryptographic proof of possession | `device-key.js`, `server.js` |
| 7a | `device-key.js` precached; uncached assets no longer fall back to `index.html` | `sw.js` |
| 7b | Audit only: how to keep the Android copy in sync | none |
| 7c | Account and device panel in the UI, in all 11 languages; Android asset synced | `index.html`, Android asset |

## 6. Identity model

These layers are separate on purpose. Do not merge them.

1. **Anonymous app session.** Cookie `product_labels_session`, HMAC-signed, one-year sliding lifetime. Legacy licenses are bound to its id through `stripe_purchases.app_session_id`, so **this id must never rotate.** It proves nothing about an account.
2. **Account session.** Cookie `product_labels_account`: 32 random bytes, a fresh token at every sign-in, stored only as a keyed hash in `account_sessions`, 30-day absolute lifetime, valid only together with the app session that signed in. `currentAccount(req)` is the single source of signed-in state.
3. **Device key.** Non-extractable ECDSA P-256 pair in IndexedDB (database `product-labels-device`, store `keys`, record `device-key-v1`). A `devices` row exists only after that key signed a server challenge. `key_thumbprint` is an RFC 7638 thumbprint and is unique forever.
4. **Entitlement.** Still only `app_sessions.unlocked`, derived from purchases. **Nothing links layers 2 and 3 to entitlement yet.** An account or a device unlocks nothing.

## 7. API contract

Under `/api`, every route runs `apiLimiter`, `requireSameOrigin` and `requestSession`. `/api/health` and the Stripe webhook sit before that chain.

| Route | Auth | Success | Notable errors |
| --- | --- | --- | --- |
| `POST /api/email-verification/request {email}` | app session | 202 `{status:'queued',expiresInMinutes:10}` | 400 `invalid_email`, `email_not_allowed`; 503 `email_unavailable`; 429 |
| `POST /api/email-verification/verify {email,code}` | app session | 200 `{verified:true,emailMasked}`; proves nothing lasting | 400; 403 `verification_failed`; 429 |
| `POST /api/account/signup {email,code}` | app session | 201 `created:true`, or 200 `created:false` if the account exists | as above, plus 403 `account_unavailable` |
| `POST /api/account/login {email,code}` | app session | 200 | as above, plus 404 `account_not_found` |
| `GET /api/account` | none | `{authenticated,emailMasked?}`; clears a dead cookie | |
| `POST /api/account/logout` | none | 200 `{authenticated:false}`; revokes the token | |
| `GET /api/devices` | account | `{device:null}` or `{device:{keyThumbprint,registeredAt,lastValidatedAt}}` | 401 `not_authenticated` |
| `POST /api/devices/challenge {purpose,publicKey}` | account | 200 `{challenge,expiresInSeconds:120}` | 400 `invalid_purpose`, `invalid_public_key`; 409 `already_registered`, `key_unavailable`, `device_limit_reached`, `device_not_registered` |
| `POST /api/devices/register {publicKey,challenge,signature}` | account | 201 `{registered,keyThumbprint,registeredAt}` | 403 `proof_failed`; 409 `key_unavailable`, `device_limit_reached`, `account_unavailable` |
| `POST /api/devices/verify {publicKey,challenge,signature}` | account | 200 `{verified,keyThumbprint,lastValidatedAt}` | 403 `proof_failed` |

Existing routes, unchanged in behaviour: `GET /api/session`, `POST /api/labels/reserve`, `POST /api/checkout`, `POST /api/checkout/complete`, `POST /api/stripe/webhook`, `GET /api/license`, `POST /api/license/transfer/request`, `POST /api/license/transfer/confirm`.

## 8. Security mechanisms already in place

**Email codes.** 8 digits from `crypto.randomInt`, 10-minute lifetime, 5 wrong attempts lock the code. Stored as a keyed HMAC bound to purpose, session and email hash. Sealed with AES-GCM in `email_outbox`, and wiped there after sending or failure. A new request closes the session's open codes.

**Atomic sign-in.** `signInWithCode` runs in one `.immediate()` transaction: consume the code, insert the account with `ON CONFLICT(email_hash) DO NOTHING`, open the session, write the audit row. Later phases must act inside that transaction. Never treat an `account_codes` row as proof.

**Device proof.** Challenges are stateless HMAC tokens with their own HKDF key, binding purpose, account, a hash of the app session, key thumbprint and device id, valid for 2 minutes. The device signs `product-labels-device-proof:v1:` + challenge (raw 64-byte P1363). `verify` checks against the stored key, never the request's key. Single use comes from two facts: a thumbprint can register only once, and a proof needs `last_validated_at < challenge.iat`.

**One active device.** Checked at challenge time, again inside the transaction, and enforced by the partial unique index `devices_one_active`.

**Rate limits.** Security limits live in the SQLite `rate_limits` table, through `consumeRateLimit.immediate`, so they hold across processes:

- Code requests: 10 per hour per IP, 5 per session, 3 per address, 1 per 60 seconds per address.
- Code checks (shared by verify, signup and login): 30 per hour per IP, 10 per session.
- Device challenges: 60 per hour per IP, 30 per account.
- Device proofs: 60 per hour per IP, 20 per account.

`apiLimiter` is in memory only.

## 9. Hard rules

- Never print secrets, keys, tokens, cookies, verification codes or customer data, and never commit `.env`, `data/`, databases or backups.
- Do not open, modify or migrate `data/product-labels.sqlite`. It is still schema v0 with test data. Migrations are tested on temporary databases only.
- No `git push`, no branch changes, no merges and no commits without explicit approval. Never use `git add .` or `git add -A`. Never stage `.vscode/`.
- No real email, and no calls to Stripe or Brevo. Do not change the price (`PRICE_CENTS` and `UNLOCK_PRICE_USD` must match), Stripe keys, webhook settings, SMTP credentials or `SESSION_SECRET`.
- No live mode, no deploy, no hosting, domain, DNS or Cloudflare decisions.
- No new packages. If one is unavoidable, stop and report.
- Android: `assets/index.html` may change only as a byte-for-byte copy of the root file, and only when the phase approves it. Never hand-edit it, never add other assets, and do not run Gradle.
- Migrations are additive, safe to re-run and never lower or re-term legacy purchases. Keep `license_policy='legacy'` on every existing purchase.
- Do not change `load()`, `persist()`, `KEY`, `billing`, `appLocked`, `setLockedState`, `reserveLabels`, `syncBilling`, transfer handlers or checkout handlers unless the phase is about them.
- Do not weaken or delete tests to get a pass. Fix the cause and report failures honestly.

## 10. Traps that already cost time

- Never call `/api/account` in parallel with `/api/session` on page load. On a first visit each request creates its own anonymous session and the wrong cookie can win. The page uses `syncBilling().then(syncAccount)`, and a test guards this.
- `index.html` changes must end with `cp index.html android/app/src/main/assets/index.html`, then `cmp`, then `test/ui.test.js`.
- Any `device-key.js` change needs a `CACHE_NAME` bump in `sw.js`, because non-page files are served cache-first. Update `test/sw.test.js` and `test/device-browser.test.js` with it.
- `cache.addAll` is all-or-nothing, so a host that lacks `device-key.js` keeps users on the old worker.
- `keys.thumbprint()` and `keys.publicJwk()` create a key if none exists. Use `keys.storedThumbprint()` just to look.
- New UI text needs all 11 dictionaries. `test/ui.test.js` compares keys and placeholders, and rejects languages that copy English.
- SQLite lets a `TEXT PRIMARY KEY` hold NULL, so write `NOT NULL` explicitly.
- CDP offline emulation does not reach a service worker's own fetches. To test an outage, stop the test server.
- Delivery runs on `setImmediate`, so an outbox row may already be wiped when a test reads it.
- Test ports (31877 to 31911) are hard-coded per file. Pick a free one for a new file.

## 11. Current status

Last full validation: 2026-10-31.

| Check | Result |
| --- | --- |
| `npm run check` | Pass |
| `npm test` | 138 of 138 in the 3 runs after the last fix; 0 failed, 0 skipped |
| `git diff --check` | Clean |
| `cmp` of both `index.html` files | Identical |
| Real database | Unchanged, still v0 |

Not tested: Safari, Firefox, a real Android WebView, a real SMTP send of the new codes, and any Gradle build. Live Stripe has never been used.

An intermittent failure is on record: the `ui-browser` help-dialog test failed once during Phase 5 and has not returned, including under artificial CPU load. Its error text was lost. A fixed `sleep(100)` is the suspected cause, not a proven one, so the test was left alone.

## 12. Known gaps

- **Device to entitlement.** Certificate issuance must demand a fresh device proof in the same request, with a new challenge purpose such as `certificate`. It must not rely on a recent `last_validated_at`.
- **Browser certificate check.** `license-cert.js` cannot run in a browser. A WebCrypto verifier with shared test vectors is needed, plus a way to distribute public keys offline.
- **Signing key operations.** `LICENSE_SIGNING_KEY_FILE`, `LICENSE_SIGNING_KEY` and `LICENSE_SIGNING_KID` are not in `.env.example` or the README, and there is no production key procedure.
- **Lost key.** Clearing browser data or using a private window leaves the device row active and holds the account's only slot. Only recovery can release it, and recovery does not exist yet.
- **Recovery storage.** `audit_events` has no reason or actor column, so documented support overrides need an additive migration v6, for example a `device_recoveries` table and an `audit_events.detail` column. Counting past recoveries already works through `devices.revoke_reason`.
- **Account suspension.** Sessions stop working through the status check, but no tool revokes all sessions of an account. Offline certificates would outlive suspension by up to 44 days.
- **Read-only mode.** `setLockedState` disables `btn-export` today, which conflicts with the target. `appLocked` also locks the whole app when offline.
- **XSS hardening.** The CSP has no `script-src`, and `index.html` has 4 inline scripts, so hashes are needed. `p.id` is rendered unescaped; the risk looks low because ids are app-generated. A page script can use the device key even though it cannot export it.
- **Checkout.** New purchases still default to `legacy` and do not require an account. `single_device`, the claim flow for legacy purchases, and limiting transfer routes to legacy purchases are all unbuilt.
- **Retention.** `account_sessions` and `audit_events` are never pruned.
- **Help content.** The purchase help dialog does not describe accounts or devices.
- **A second account in one browser profile.** It gets `key_unavailable`. This matches the one-account-per-device rule but needs care on shared computers.

## 13. Proposed road to the goal

Only stage 8 is named by the owner, and none of this is approved. The order and numbering after 7 are a proposal.

| Stage | Scope | Acceptance |
| --- | --- | --- |
| 7e | Server hardening: revoke all sessions, suspension handling, escape `p.id`, then a separate CSP step | Suspension ends all sessions; CSP breaks no page or test |
| 7f | Support recovery: migration v6, signed recovery request, server-side CLI approval. No public approval route | No device without approval; second recovery in 12 months refused unless overridden with reason and ticket; v5 to v6 additive |
| 8 | 48-hour trial certificates: proof in the same request, browser verifier, key distribution | Shared Node and browser vectors pass; no certificate without proof; one trial per account and key, ever |
| Later | Account-bound checkout with `single_device`, legacy claim flow, paid certificates, revalidation, grace, read-only UI, limiting transfer to legacy, help text | Legacy buyers keep their rights; offline rules match section 2 |
| Release | Full regression, commit, push, HTTPS hosting with persistent storage, real database migration with backup, Stripe live mode | Each step separately approved by the owner |

Android remains a separate decision: it runs from `file://` with no API, so printing stays locked there, and Play policy may require Play Billing.

## 14. Open decisions for the owner

1. Commit the Phase 3 to 7c work, and push `f00e143` and `90c90fb`?
2. Hosting choice, which also settles the same-origin HTTPS assumption.
3. Signing key storage. A secret file with an offline backup is recommended.
4. What users see when they lose the device key, before recovery exists.
5. Whether shared computers need any accommodation under the one-account-per-device rule.

The 12-month recovery limit is settled: strict by default, with support exceptions that are documented.

## 15. How to start

1. Read sections 1, 6 and 9.
2. Run `git status` and `npm run check`. Run `npm test` only with the default test setup, which uses temporary directories.
3. Read `server.js` from `signInWithCode` onward, then `device-key.js`, then the account section of `index.html` (search for `account and device`).
4. Ask the owner which stage is approved. Report which files changed, why, exact test counts and any failure, and confirm that nothing was committed, pushed or deployed.

## Current validation update (2026-11-04)

This update supersedes earlier validation and remaining-gap notes above where they conflict.

- `npm test` now runs sequentially by default (`node --test --test-concurrency=1`), avoiding local process/socket exhaustion from parallel test files. Latest complete run: 147 passed, 0 failed, 0 skipped. Chromium/CDP browser tests ran. The first serial run found three stale help-dialog assertions after the account-help section was added; those expectations now check the correct localized headings. A later rerun again passed 147/147.
- `npm run check`, `git diff --check`, and the root/Android HTML byte comparison pass. Both the HTTP error handler and background email-outbox failure logger emit only a bounded error code rather than arbitrary exception text. Latest full run after this change: 147 passed, 0 failed, 0 skipped.
- `express-rate-limit` was updated in `package.json` and `package-lock.json` to 8.7.3, which includes the upstream fix for the MemoryStore skip-request counter issue. Manifest/lock ranges match and `npm ci --dry-run --ignore-scripts --offline` completes without modifying `node_modules`; no 8.7.3 package tarball is cached, so the installed version remains 8.7.1. `npm audit --omit=dev` still fails with `EAI_AGAIN` for the default `registry.npmjs.org`; DNS lookup also fails for `github.com`, while local hostname resolution works. No DNS/proxy configuration was altered because shell network access is restricted.
- GitHub reports zero Actions runs for `server-checkout`; the remote `.github/workflows` directory is absent. The local workflow is uncommitted. No commit or push was made.
- Docker Engine and rootless builders are unavailable. Flutter reports Android SDK 36 and accepted licenses at the Unity-bundled SDK path, but `adb` cannot start under sandbox socket restrictions. Python `socket.if_nameindex()` returns `PermissionError(EPERM)`, explaining Gradle’s failure to find a usable wildcard IP. An isolated Android debug build in `/tmp` failed during Gradle startup; the checkout and existing build outputs were untouched. No network/interface restrictions were bypassed. Docker image and APK builds remain unverified locally.
- The production runbook is in `README.md`. No production deployment, real email, or payment was performed. Production hosting/domain, managed secrets, persistent storage/backups, a test mailbox, and authorized test-mode Stripe webhook configuration are external prerequisites. Keep product/legal decisions on legacy-claim and retention policy open.
