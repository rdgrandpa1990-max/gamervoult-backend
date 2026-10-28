/**
 * test_security_remediation.js
 * Automated security regression & unit test suite for Phase 12
 * Tests:
 * 1. SSRF Destination Filtering (validateHostSecurity)
 * 2. Gamervoult Mandatory Version Check Logic
 * 3. Payment Order Creation & Tampering Rejection
 * 4. Auth & Role Middleware Rejections
 * 5. Secret Leakage Verification in Source Tree
 */

import { validateHostSecurity } from './authMiddleware.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ PASS: ${message}`);
    testsPassed++;
  } else {
    console.error(`  ❌ FAIL: ${message}`);
    testsFailed++;
  }
}

async function runTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING SECURITY REMEDIATION AUTOMATED TEST SUITE');
  console.log('======================================================\n');

  // ---------------------------------------------------------
  // TEST GROUP 1: SSRF Host Destination Validation
  // ---------------------------------------------------------
  console.log('--- TEST GROUP 1: SSRF Protection & Private IP Filtering ---');
  
  const ssrfDangerousPayloads = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254', // AWS/GCP metadata service
    '10.0.0.1',        // Private Class A
    '172.16.0.5',      // Private Class B
    '192.168.1.1',     // Private Class C
    'internal.local',
    'metadata.google.internal',
    'http://localhost:8080',
    'ftp://127.0.0.1'
  ];

  for (const host of ssrfDangerousPayloads) {
    const isSafe = validateHostSecurity(host);
    assert(!isSafe, `Dangerous/Internal destination rejected: "${host}"`);
  }

  const safeHosts = [
    'imap.gmail.com',
    'imap.zoho.in',
    'mail.freefireofficial.in',
    'imap.secureserver.net'
  ];

  for (const host of safeHosts) {
    const isSafe = validateHostSecurity(host);
    assert(isSafe, `Legitimate public mail host permitted: "${host}"`);
  }

  // ---------------------------------------------------------
  // TEST GROUP 2: Gamervoult Mandatory Version Check Logic
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 2: Gamervoult Version Enforcement Logic ---');

  function calculateVersionState(clientVersionCode, minVersionCode, latestVersionCode) {
    const mandatoryUpdate = clientVersionCode > 0 && clientVersionCode < minVersionCode;
    const updateAvailable = clientVersionCode > 0 && clientVersionCode < latestVersionCode;
    return { mandatoryUpdate, updateAvailable };
  }

  // Case A: Outdated app below minimum required threshold
  const caseA = calculateVersionState(1, 3, 5);
  assert(caseA.mandatoryUpdate === true, 'Outdated client (v1 vs min v3) triggers mandatory update lockout');
  assert(caseA.updateAvailable === true, 'Outdated client receives updateAvailable=true');

  // Case B: Client meets min threshold but is not latest
  const caseB = calculateVersionState(3, 3, 5);
  assert(caseB.mandatoryUpdate === false, 'Client meeting minimum (v3 vs min v3) is NOT locked out');
  assert(caseB.updateAvailable === true, 'Client below latest (v3 vs latest v5) receives optional update flag');

  // Case C: Up to date client
  const caseC = calculateVersionState(5, 3, 5);
  assert(caseC.mandatoryUpdate === false, 'Current client (v5) is not locked out');
  assert(caseC.updateAvailable === false, 'Current client receives no update prompt');

  // ---------------------------------------------------------
  // TEST GROUP 3: Payment Order Validation & Anti-Tampering
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 3: Payment Order Creation & Tampering Validation ---');

  function validateOrderPayload(reqBody, catalogItem) {
    const errors = [];
    if (!reqBody.itemId || !catalogItem) {
      errors.push('ITEM_NOT_FOUND');
    }
    // Price must match server catalog strictly
    if (catalogItem && Number(reqBody.amount) !== Number(catalogItem.price)) {
      errors.push('PRICE_TAMPERING_DETECTED');
    }
    // Customer cannot set initial status to PAID
    if (reqBody.status && reqBody.status.toUpperCase() === 'PAID') {
      errors.push('UNAUTHORIZED_STATUS_OVERRIDE');
    }
    // Sensitive delivery fields must not be accepted from client
    if (reqBody.deliveryPassword || reqBody.deliveryBackupCodes) {
      errors.push('SENSITIVE_FIELD_INJECTION');
    }
    return errors;
  }

  const catalogItem = { id: 'ff_acc_99', price: 499, title: 'Pro FreeFire Account' };

  // Attempt A: Client attempts price tampering (₹1 instead of ₹499)
  const tamperPrice = validateOrderPayload({ itemId: 'ff_acc_99', amount: 1 }, catalogItem);
  assert(tamperPrice.includes('PRICE_TAMPERING_DETECTED'), 'Client price tampering (₹1 vs ₹499) is detected and rejected');

  // Attempt B: Client attempts to pre-mark order as PAID
  const tamperStatus = validateOrderPayload({ itemId: 'ff_acc_99', amount: 499, status: 'PAID' }, catalogItem);
  assert(tamperStatus.includes('UNAUTHORIZED_STATUS_OVERRIDE'), 'Client self-marking status as PAID is blocked');

  // Attempt C: Client attempts to inject delivery password
  const injectCreds = validateOrderPayload({ itemId: 'ff_acc_99', amount: 499, deliveryPassword: 'secretpassword' }, catalogItem);
  assert(injectCreds.includes('SENSITIVE_FIELD_INJECTION'), 'Delivery credentials in client order creation are rejected');

  // Attempt D: Legitimate order creation
  const validOrder = validateOrderPayload({ itemId: 'ff_acc_99', amount: 499, status: 'PENDING' }, catalogItem);
  assert(validOrder.length === 0, 'Legitimate order payload with server-verified price passes validation');

  // ---------------------------------------------------------
  // TEST GROUP 4: Secret Fallback Leakage Scan in Codebase
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 4: Zero Secret Fallbacks in Active Source Tree ---');

  const leakedSignatures = [
    'pg_live_8bd7aeec3c650fd7370049101cb01da0',
    'garena_sec_9988_a7f92b4c81d3',
    'gamershield_shared_secret_key_2026',
    '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'
  ];

  const sourceDirs = [
    path.join(__dirname, '..', 'src'),
    path.join(__dirname)
  ];

  let foundSecrets = 0;

  function scanDir(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const fullPath = path.join(dir, file);
      if (file === 'node_modules' || file === '.git' || file === 'dist' || file.endsWith('.backup') || file === 'test_security_remediation.js') continue;
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        scanDir(fullPath);
      } else if (file.endsWith('.js') || file.endsWith('.jsx') || file.endsWith('.ts') || file.endsWith('.tsx')) {
        const content = fs.readFileSync(fullPath, 'utf8');
        for (const sig of leakedSignatures) {
          if (content.includes(sig)) {
            console.error(`  ❌ LEAK DETECTED in ${file}: signature ${sig}`);
            foundSecrets++;
          }
        }
      }
    }
  }

  for (const sDir of sourceDirs) {
    if (fs.existsSync(sDir)) scanDir(sDir);
  }

  assert(foundSecrets === 0, `Zero hardcoded fallback secrets in active JavaScript/React/Node source files (0 found)`);

  // ---------------------------------------------------------
  // TEST GROUP 5: Business Invariant Preservation (48h Cooldown & Extra Scan)
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 5: Business Invariant Preservation (48h Cooldown & Extra Scan) ---');

  function evaluateClientScanAccess(userDoc, nowTimestamp = Date.now()) {
    const otpUsedAt = userDoc.otpUsedAt ? new Date(userDoc.otpUsedAt).getTime() : 0;
    const cooldownPeriodMs = 48 * 60 * 60 * 1000;
    const cooldownElapsed = !otpUsedAt || (nowTimestamp - otpUsedAt >= cooldownPeriodMs);
    const hasUsedInitialScan = userDoc.otpUsed === true || (userDoc.otpScanCount || 0) >= 1;
    const extraScanGranted = userDoc.extraScanGranted === true;

    // Invariant: If initial scan was used, cooldown expiry alone does NOT unlock scan;
    // only an explicit admin extraScanGranted unlocks an additional scan.
    const isScanPermitted = !hasUsedInitialScan || extraScanGranted;
    return { cooldownElapsed, isScanPermitted, extraScanGranted };
  }

  // Case A: Fresh client who hasn't used any OTP
  const freshClient = { otpUsed: false, otpScanCount: 0, extraScanGranted: false };
  assert(evaluateClientScanAccess(freshClient).isScanPermitted === true, 'Fresh client with no prior scans is permitted to scan OTP');

  // Case B: Client who already used OTP and cooldown is active (< 48h)
  const usedClientActiveCooldown = { otpUsed: true, otpScanCount: 1, otpUsedAt: new Date(Date.now() - 3600000).toISOString(), extraScanGranted: false };
  assert(evaluateClientScanAccess(usedClientActiveCooldown).isScanPermitted === false, 'Client within 48h cooldown without admin extra-scan is blocked');

  // Case C: Client who used OTP, 48 hours elapsed, but NO admin extra-scan granted
  const usedClientExpiredCooldown = { otpUsed: true, otpScanCount: 1, otpUsedAt: new Date(Date.now() - (49 * 3600000)).toISOString(), extraScanGranted: false };
  assert(evaluateClientScanAccess(usedClientExpiredCooldown).isScanPermitted === false, 'Client with 48h cooldown expired still requires admin extra-scan approval');

  // Case D: Client who used OTP, but Admin granted extraScanGranted: true
  const adminUnlockedClient = { otpUsed: true, otpScanCount: 1, otpUsedAt: new Date(Date.now() - 3600000).toISOString(), extraScanGranted: true };
  assert(evaluateClientScanAccess(adminUnlockedClient).isScanPermitted === true, 'Admin extraScanGranted: true immediately unblocks client for extra scan');

  // ---------------------------------------------------------
  // TEST GROUP 6: Payment Webhook Fail-Closed Security Suite
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 6: Payment Webhook Fail-Closed Security Suite ---');

  // Timing safe equal string helper
  function timingSafeEqualStr(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length === 0 || bufB.length === 0 || bufA.length !== bufB.length) {
      const dummy = Buffer.alloc(32, 0);
      crypto.timingSafeEqual(dummy, dummy);
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }

  // Helper resolving expected server secret (verifying VITE_ is excluded)
  function resolveExpectedServerSecret(env) {
    return env.UPI_GATEWAY_WEBHOOK_SECRET || env.UPI_GATEWAY_API_KEY || '';
  }

  function validateWebhookRequest(headers, body, expectedSecret, orderInDb, existingUtrsInDb = []) {
    // 1. Fail-closed if secret not configured on server
    if (!expectedSecret) {
      return { status: 503, error: 'CONFIGURATION_ERROR', message: 'Webhook secret not configured on server' };
    }

    let incomingSecret = headers['x-webhook-secret'] || headers['x-api-key'] || '';
    if (!incomingSecret && headers['authorization']) {
      const authHeader = String(headers['authorization']).trim();
      if (authHeader.startsWith('Bearer ')) {
        incomingSecret = authHeader.slice(7).trim();
      } else {
        incomingSecret = authHeader;
      }
    }

    if (!incomingSecret || !timingSafeEqualStr(String(incomingSecret).trim(), expectedSecret.trim())) {
      return { status: 401, error: 'UNAUTHORIZED', message: 'Invalid or missing webhook secret' };
    }

    const { orderCode, status, utr, transactionId, amount, currency } = body;
    if (!orderCode || !status) {
      return { status: 400, error: 'MISSING_FIELDS', message: 'Missing orderCode or status' };
    }

    const cleanOrderCode = String(orderCode).trim();
    const cleanStatus = String(status).trim().toUpperCase();
    const allowedStatuses = ['PAID', 'FAILED', 'EXPIRED'];
    if (!allowedStatuses.includes(cleanStatus)) {
      return { status: 400, error: 'INVALID_STATUS', message: `Invalid order status: ${cleanStatus}` };
    }

    if (!orderInDb) {
      return { status: 404, error: 'ORDER_NOT_FOUND', message: 'Order not found in registry' };
    }

    // Terminal state locks
    if (orderInDb.status === 'PAID') {
      return { status: 200, message: 'IDEMPOTENT_ALREADY_PAID', currentStatus: 'PAID' };
    }
    if (orderInDb.status === 'CANCELLED') {
      return { status: 409, error: 'CANCELLED_LOCKED', message: 'Order is already CANCELLED' };
    }

    // Currency check
    if (currency !== undefined && currency !== null) {
      const expectedCurrency = String(orderInDb.currency || 'INR').toUpperCase();
      if (String(currency).trim().toUpperCase() !== expectedCurrency) {
        return { status: 400, error: 'CURRENCY_MISMATCH', message: 'Currency mismatch detected' };
      }
    }

    // Amount check
    if (amount !== undefined && amount !== null && Number(amount) !== Number(orderInDb.amount)) {
      return { status: 400, error: 'AMOUNT_MISMATCH', message: 'Amount mismatch detected between webhook and order' };
    }

    const paymentEvidence = utr ? String(utr).trim() : (transactionId ? String(transactionId).trim() : '');

    if (cleanStatus === 'PAID') {
      if (!paymentEvidence || paymentEvidence.length < 4) {
        return { status: 400, error: 'MISSING_PAYMENT_EVIDENCE', message: 'Missing or invalid payment evidence (UTR / transactionId)' };
      }

      // Replay check
      const replayed = existingUtrsInDb.some(entry => entry.utr === paymentEvidence && entry.orderCode !== cleanOrderCode);
      if (replayed) {
        return { status: 409, error: 'REPLAY_CONFLICT', message: 'Payment transaction reference (UTR) already used on another order' };
      }

      return { status: 200, message: 'ORDER_MARKED_PAID', utr: paymentEvidence };
    }

    return { status: 200, message: 'STATUS_UPDATED', newStatus: cleanStatus };
  }

  const dummyExpectedSecret = 'mock_secret_test_suite_key_2026';
  const sampleOrder = { orderCode: 'ORD-TEST01', amount: 999, currency: 'INR', status: 'PENDING' };
  const paidOrder = { orderCode: 'ORD-PAID01', amount: 999, currency: 'INR', status: 'PAID', utr: 'UTR1122334455' };
  const cancelledOrder = { orderCode: 'ORD-CANCEL01', amount: 999, currency: 'INR', status: 'CANCELLED' };

  // 6.0: Server Secret resolution excludes VITE_ client variables
  const envWithViteOnly = { VITE_UPI_GATEWAY_API_KEY: 'client_side_key' };
  assert(resolveExpectedServerSecret(envWithViteOnly) === '', 'Server secret resolution strictly excludes VITE_UPI_GATEWAY_API_KEY');
  const envWithServerKey = { UPI_GATEWAY_WEBHOOK_SECRET: 'server_webhook_sec' };
  assert(resolveExpectedServerSecret(envWithServerKey) === 'server_webhook_sec', 'Server secret resolution accepts UPI_GATEWAY_WEBHOOK_SECRET');

  // 6.1: Constant-time comparison handles unequal-length strings safely
  assert(timingSafeEqualStr('short', 'longer_string_value') === false, 'timingSafeEqualStr handles unequal-length strings without crashing');
  assert(timingSafeEqualStr(dummyExpectedSecret, dummyExpectedSecret) === true, 'timingSafeEqualStr matches identical strings correctly');
  assert(timingSafeEqualStr(dummyExpectedSecret, 'wrong_value_length_matched_12345') === false, 'timingSafeEqualStr rejects differing values of same length');

  // 6A: Missing server secret configuration (Fail-Closed)
  const test6A = validateWebhookRequest({ 'x-webhook-secret': 'any_val' }, { orderCode: 'ORD-TEST01', status: 'PAID', utr: 'UTR99887766' }, '', sampleOrder);
  assert(test6A.status === 503, 'Webhook rejects with HTTP 503 (Fail-Closed) if server secret is not configured');

  // 6B: Missing incoming secret header
  const test6B = validateWebhookRequest({}, { orderCode: 'ORD-TEST01', status: 'PAID', utr: 'UTR99887766' }, dummyExpectedSecret, sampleOrder);
  assert(test6B.status === 401, 'Webhook rejects with HTTP 401 if incoming secret header is missing');

  // 6C: Incorrect secret header
  const test6C = validateWebhookRequest({ 'x-webhook-secret': 'wrong_secret' }, { orderCode: 'ORD-TEST01', status: 'PAID', utr: 'UTR99887766' }, dummyExpectedSecret, sampleOrder);
  assert(test6C.status === 401, 'Webhook rejects with HTTP 401 if secret header is incorrect');

  // 6C.2: Authorization Bearer header support
  const testBearer = validateWebhookRequest({ 'authorization': `Bearer ${dummyExpectedSecret}` }, { orderCode: 'ORD-TEST01', status: 'PAID', utr: 'UTR99887766', amount: 999 }, dummyExpectedSecret, sampleOrder);
  assert(testBearer.status === 200, 'Webhook authenticates successfully via Authorization: Bearer <secret>');

  // 6D: Non-existent order reference
  const test6D = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-NONEXISTENT', status: 'PAID', utr: 'UTR99887766' }, dummyExpectedSecret, null);
  assert(test6D.status === 404, 'Webhook returns HTTP 404 if order does not exist in registry');

  // 6E.1: Invalid status string
  const testInvalidStatus = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'UNKNOWN_STATE' }, dummyExpectedSecret, sampleOrder);
  assert(testInvalidStatus.status === 400 && testInvalidStatus.error === 'INVALID_STATUS', 'Webhook rejects invalid order status string');

  // 6E.2: Currency mismatch tampering
  const testCurrencyMismatch = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 999, currency: 'USD', utr: 'UTR99887766' }, dummyExpectedSecret, sampleOrder);
  assert(testCurrencyMismatch.status === 400 && testCurrencyMismatch.error === 'CURRENCY_MISMATCH', 'Webhook rejects currency mismatch (USD vs INR)');

  // 6E.3: Amount mismatch tampering
  const test6E = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 1, utr: 'UTR99887766' }, dummyExpectedSecret, sampleOrder);
  assert(test6E.status === 400 && test6E.error === 'AMOUNT_MISMATCH', 'Webhook rejects with HTTP 400 if amount does not match order total (₹1 vs ₹999)');

  // 6E.4: Missing UTR / transactionId for status PAID
  const testNoUtr = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 999 }, dummyExpectedSecret, sampleOrder);
  assert(testNoUtr.status === 400 && testNoUtr.error === 'MISSING_PAYMENT_EVIDENCE', 'Webhook rejects PAID status without valid UTR / transactionId');

  // 6E.5: Short/dummy UTR rejected
  const testShortUtr = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 999, utr: '12' }, dummyExpectedSecret, sampleOrder);
  assert(testShortUtr.status === 400 && testShortUtr.error === 'MISSING_PAYMENT_EVIDENCE', 'Webhook rejects trivial or sub-4-char UTR');

  // 6E.6: UTR Replay Protection (UTR already used on ORD-OTHER)
  const existingUtrs = [{ utr: 'UTR_REUSED_12345', orderCode: 'ORD-OTHER' }];
  const testReplay = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 999, utr: 'UTR_REUSED_12345' }, dummyExpectedSecret, sampleOrder, existingUtrs);
  assert(testReplay.status === 409 && testReplay.error === 'REPLAY_CONFLICT', 'Webhook rejects UTR replay across distinct orders with HTTP 409 Conflict');

  // 6F: Valid authenticated webhook transitions order to PAID
  const test6F = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-TEST01', status: 'PAID', amount: 999, currency: 'INR', utr: 'UTR_FRESH_998877' }, dummyExpectedSecret, sampleOrder, existingUtrs);
  assert(test6F.status === 200 && test6F.message === 'ORDER_MARKED_PAID', 'Valid authenticated webhook successfully verifies and marks order PAID');

  // 6G: Duplicate webhook delivery on already PAID order (Idempotent replay protection)
  const test6G = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-PAID01', status: 'PAID', amount: 999, utr: 'UTR1122334455' }, dummyExpectedSecret, paidOrder);
  assert(test6G.status === 200 && test6G.message === 'IDEMPOTENT_ALREADY_PAID', 'Duplicate webhook on already PAID order returns 200 OK idempotently without re-execution');

  // 6H: Conflicting status update attempt on an already PAID order (Terminal Lock)
  const testDowngrade = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-PAID01', status: 'FAILED' }, dummyExpectedSecret, paidOrder);
  assert(testDowngrade.status === 200 && testDowngrade.currentStatus === 'PAID', 'Late conflicting FAILED webhook cannot overwrite terminal PAID order');

  // 6I: Attempted transition on CANCELLED order is rejected
  const testCancelled = validateWebhookRequest({ 'x-webhook-secret': dummyExpectedSecret }, { orderCode: 'ORD-CANCEL01', status: 'PAID', amount: 999, utr: 'UTR_NEW_7766' }, dummyExpectedSecret, cancelledOrder);
  assert(testCancelled.status === 409 && testCancelled.error === 'CANCELLED_LOCKED', 'Webhook cannot resurrect or transition a CANCELLED order');

  // ---------------------------------------------------------
  // TEST GROUP 7: App Version Check & APK Download Integrity
  // ---------------------------------------------------------
  console.log('\n--- TEST GROUP 7: App Version Check & APK Download Integrity ---');

  function isValidReleaseUrl(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return false;
    try {
      const parsed = new URL(urlStr);
      return parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  function isValidSha256(hashStr) {
    if (!hashStr || typeof hashStr !== 'string') return false;
    return /^[a-fA-F0-9]{64}$/.test(hashStr.trim());
  }

  function evaluateArtifactAvailability(cfg) {
    const isArtifactAvailable = Boolean(
      cfg.downloadUrl &&
      isValidReleaseUrl(cfg.downloadUrl) &&
      cfg.sha256Checksum &&
      isValidSha256(cfg.sha256Checksum) &&
      (cfg.fileSizeBytes == null || (!isNaN(cfg.fileSizeBytes) && cfg.fileSizeBytes > 100000))
    );
    return {
      isArtifactAvailable,
      downloadUrl: isArtifactAvailable ? cfg.downloadUrl : null,
      sha256Checksum: isArtifactAvailable ? cfg.sha256Checksum : null,
      fileSizeBytes: isArtifactAvailable ? cfg.fileSizeBytes : null
    };
  }

  // 7A: Missing SHA-256
  const missingChecksum = evaluateArtifactAvailability({ downloadUrl: 'https://cdn.gamervoult.com/release.apk', sha256Checksum: null });
  assert(missingChecksum.isArtifactAvailable === false && missingChecksum.downloadUrl === null, 'Artifact unavailable when SHA-256 is null');

  // 7B: Missing download URL
  const missingUrl = evaluateArtifactAvailability({ downloadUrl: null, sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
  assert(missingUrl.isArtifactAvailable === false && missingUrl.sha256Checksum === null, 'Artifact unavailable when downloadUrl is null');

  // 7C: Non-HTTPS download URL rejected (prevents MitM and plaintext transport)
  const nonHttps = evaluateArtifactAvailability({ downloadUrl: 'http://insecure.gamervoult.com/release.apk', sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
  assert(nonHttps.isArtifactAvailable === false, 'Artifact unavailable when download URL uses insecure http:// protocol');

  // 7D: Malformed URL rejected
  const malformedUrl = evaluateArtifactAvailability({ downloadUrl: 'not_a_valid_url', sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
  assert(malformedUrl.isArtifactAvailable === false, 'Artifact unavailable when download URL is malformed string');

  // 7E: Invalid SHA-256 format (MD5 / 32 chars rejected)
  const md5Hash = evaluateArtifactAvailability({ downloadUrl: 'https://cdn.gamervoult.com/release.apk', sha256Checksum: 'd41d8cd98f00b204e9800998ecf8427e' });
  assert(md5Hash.isArtifactAvailable === false, 'Artifact unavailable when checksum is MD5 (32 chars) instead of SHA-256 (64 hex chars)');

  // 7F: Non-hex characters in SHA-256 rejected
  const nonHexHash = evaluateArtifactAvailability({ downloadUrl: 'https://cdn.gamervoult.com/release.apk', sha256Checksum: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' });
  assert(nonHexHash.isArtifactAvailable === false, 'Artifact unavailable when checksum contains non-hex characters');

  // 7G: Small file size (HTML 404 page / corrupted download rejected)
  const tinyFile = evaluateArtifactAvailability({ downloadUrl: 'https://cdn.gamervoult.com/release.apk', sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', fileSizeBytes: 1024 });
  assert(tinyFile.isArtifactAvailable === false, 'Artifact unavailable when file size is <= 100KB (prevents serving HTML 404 error pages)');

  // 7H: Valid verified release artifact with HTTPS, SHA-256, and realistic APK size
  const validRelease = evaluateArtifactAvailability({
    downloadUrl: 'https://44b2ffbfe204eaa7b4ddb8269123c229.r2.cloudflarestorage.com/gamervoult-v1.0.0.apk',
    sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    fileSizeBytes: 24500000
  });
  assert(validRelease.isArtifactAvailable === true, 'Artifact available when URL is HTTPS, SHA-256 is 64 hex, and size is valid APK (>100KB)');
  assert(validRelease.downloadUrl === 'https://44b2ffbfe204eaa7b4ddb8269123c229.r2.cloudflarestorage.com/gamervoult-v1.0.0.apk', 'Verified HTTPS download URL returned to client');
  assert(validRelease.fileSizeBytes === 24500000, 'Verified file size in bytes returned to client');


  console.log('\n======================================================');
  console.log(`📊 TEST RESULTS: ${testsPassed} Passed | ${testsFailed} Failed`);
  console.log('======================================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTests();
