'use strict';
/**
 * @geoclear/verify-receipt - verify GeoClear operational evidence records
 * (compact JWS receipts) and Evidence Bundles.
 *
 * v2.0.0 (security fix, breaking; see CHANGELOG.md):
 * - A key is trusted only from an INDEPENDENT trust source: the JWKS the
 *   caller supplies (`jwksJson`, exclusive) or a JWKS fetched live from
 *   `jwksUrl`. A bundle's trust/jwks-snapshot.json never vouches for itself,
 *   and there is no fallback from one source to another. There is no pinned
 *   snapshot option: a pre-release 2.0.0 draft had one (`trustedJwksSha256`),
 *   and a pin a caller took from the bundle itself let a forged bundle verify.
 *   Passing it is refused (TRUST_PIN_REMOVED). Offline verification against a
 *   GeoClear-signed snapshot is a separate, future feature.
 * - Key metadata is enforced: the key must carry key_purpose,
 *   environment, status and a non-empty valid_endpoints; status must be
 *   "active"; the endpoint must be one the key is valid for.
 * - The receipt's own claims must be present and agree with the key, always:
 *   its env is the key's environment, its endpoint is one the key is valid for
 *   (and, for a single receipt, the path verified). `expectedEnv` defaults to
 *   "production"; null accepts a key of any environment, but never a receipt
 *   whose claims do not bind it to that key's domain.
 * - trust/trust-anchor.txt is checked: its Key ID must be the receipt's kid.
 *   Its declared JWKS SHA-256 is reported, never trusted: the bundle wrote it.
 * - The signature algorithms are fixed: the JWS header must say ES384 and the
 *   key must be EC P-384; a bundle's ML-DSA layer must declare ML-DSA-87 (and a
 *   signed pqc_alg claim, when present, must say the same).
 *
 * Errors carry `.code` (stable, listed in README.md) and `.step`.
 */

const crypto = require('crypto');

const DEFAULT_ISS = 'https://geoclear.io';
const DEFAULT_JWKS_URL = 'https://geoclear.io/.well-known/jwks.json';
const DEFAULT_EXPECTED_ENV = 'production';
const PURPOSE_FOR_ENV = Object.freeze({ production: 'production-signed-operational-evidence' });
const JWKS_FETCH_TIMEOUT_MS = 10_000;
const JWKS_CACHE_TTL_MS = 5 * 60_000;
const MLDSA_ALG = 'ML-DSA-87';

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

class VerifyError extends Error {
  constructor(code, message, step) {
    super(`${code}: ${message}`);
    this.name = 'VerifyError';
    this.code = code;
    if (step !== undefined) this.step = step;
  }
}

function parseJwks(source, label) {
  let jwks = source;
  if (typeof source === 'string') {
    try { jwks = JSON.parse(source); } catch (e) {
      throw new VerifyError('TRUST_SOURCE_INVALID', `${label} is not JSON (${e.message})`, 0);
    }
  }
  if (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys)) {
    throw new VerifyError('TRUST_SOURCE_INVALID', `${label} is not a JWKS (no "keys" array)`, 0);
  }
  return jwks;
}

// The live-JWKS cache is keyed by URL within the fetch function used, so a
// caller-supplied fetchImpl never reads entries another fetch function wrote.
let jwksCaches = new WeakMap();
let defaultJwksCache = new Map();
function cacheFor(fetchImpl) {
  if (!fetchImpl) return defaultJwksCache;
  let c = jwksCaches.get(fetchImpl);
  if (!c) { c = new Map(); jwksCaches.set(fetchImpl, c); }
  return c;
}

/** The JWKS at `url` (https only), fetched with a bounded deadline and cached briefly. */
async function fetchJwks(url, { fetchImpl } = {}) {
  let parsedUrl;
  try { parsedUrl = new URL(String(url)); } catch (_e) {
    throw new VerifyError('TRUST_SOURCE_INVALID', `the JWKS URL ${JSON.stringify(String(url))} is not a URL`, 0);
  }
  if (parsedUrl.protocol !== 'https:') {
    throw new VerifyError('TRUST_SOURCE_NOT_HTTPS', `the JWKS URL must use https, not ${parsedUrl.protocol}`, 0);
  }
  const cache = cacheFor(fetchImpl);
  const hit = cache.get(parsedUrl.href);
  if (hit && Date.now() - hit.at < JWKS_CACHE_TTL_MS) return hit.jwks;
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new VerifyError('TRUST_SOURCE_UNAVAILABLE', 'no fetch() in this runtime; pass jwksJson', 0);
  }
  let text;
  let finalUrl;
  try {
    const res = await doFetch(url, { signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS), headers: { accept: 'application/json' }, redirect: 'follow' });
    finalUrl = res.url;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    text = await res.text();
  } catch (e) {
    throw new VerifyError('TRUST_SOURCE_UNAVAILABLE', `could not fetch the JWKS at ${url} (${e.message})`, 0);
  }
  // A redirect must not leave https: the URL the response finally came from is
  // checked as the requested one was.
  if (finalUrl) {
    let finalParsed = null;
    try { finalParsed = new URL(String(finalUrl)); } catch (_e) { finalParsed = null; }
    if (!finalParsed || finalParsed.protocol !== 'https:') {
      throw new VerifyError('TRUST_SOURCE_NOT_HTTPS', `the JWKS at ${parsedUrl.href} was served from ${JSON.stringify(String(finalUrl))}, which is not https`, 0);
    }
  }
  const jwks = parseJwks(text, url);
  cache.set(parsedUrl.href, { at: Date.now(), jwks });
  return jwks;
}

/** Clears the live-JWKS cache (tests; or after a key rotation). */
function clearJwksCache() { jwksCaches = new WeakMap(); defaultJwksCache = new Map(); }

/**
 * The decoded, canonical form of a request path, or null: a string starting
 * with "/", no query or fragment, decoded exactly once, and no dot or empty
 * segment, backslash, NUL or remaining %-escape after decoding.
 */
function canonicalPath(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('/') || /[?#\s\\\0]/.test(raw)) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch (_e) { return null; }
  if (/[\\\0]/.test(decoded) || /%[0-9a-f]{2}/i.test(decoded) || decoded.includes('//')) return null;
  if (decoded.split('/').some(seg => seg === '.' || seg === '..')) return null;
  return decoded;
}

/** A path is valid for a key when listed exactly, or under a listed "/x/*" prefix; compared canonically. */
function endpointAllowed(validEndpoints, path) {
  if (!Array.isArray(validEndpoints)) return false;
  const canon = canonicalPath(path);
  if (canon === null) return false;
  return validEndpoints.some(p => {
    if (typeof p !== 'string') return false;
    if (p.endsWith('/*')) { const base = p.slice(0, -2); return canon === base || canon.startsWith(`${base}/`); }
    return canon === p;
  });
}

/** The key's type, metadata and status, and the expected trust domain. */
function checkKey(jwk, { expectedEnv, expectedPurpose }) {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-384' || (jwk.alg && jwk.alg !== 'ES384') || !jwk.x || !jwk.y) {
    throw new VerifyError('KEY_TYPE_INVALID', `key ${jwk.kid} is not an ES384 P-384 public key`, 0);
  }
  const missing = ['key_purpose', 'environment', 'status'].filter(f => typeof jwk[f] !== 'string' || !jwk[f]);
  if (!Array.isArray(jwk.valid_endpoints) || jwk.valid_endpoints.length === 0) missing.push('valid_endpoints');
  if (missing.length) {
    throw new VerifyError('KEY_METADATA_MISSING', `key ${jwk.kid} lacks ${missing.join(', ')}; a key without them is not trusted`, 0);
  }
  if (jwk.status !== 'active') {
    throw new VerifyError('KEY_NOT_ACTIVE', `key ${jwk.kid} status is ${jwk.status}`, 0);
  }
  if (expectedEnv !== null && jwk.environment !== expectedEnv) {
    throw new VerifyError('KEY_ENVIRONMENT_MISMATCH', `key ${jwk.kid} belongs to environment ${jwk.environment}, expected ${expectedEnv}`, 0);
  }
  const purpose = expectedPurpose !== undefined ? expectedPurpose : (expectedEnv !== null ? PURPOSE_FOR_ENV[expectedEnv] : undefined);
  if (purpose && jwk.key_purpose !== purpose) {
    throw new VerifyError('KEY_PURPOSE_MISMATCH', `key ${jwk.kid} key_purpose is ${jwk.key_purpose}, expected ${purpose}`, 0);
  }
}

/**
 * The receipt's own (signed) claims against the key. ALWAYS required, whatever
 * expectedEnv is (with expectedEnv: null the key may come from
 * any trust domain, so the claims are what bind the receipt to that key's
 * domain): the env claim must be present and equal the key's environment, and
 * the endpoint claim must be present and be one the key is valid for. With
 * `path` (single receipt) the endpoint claim must also be that path.
 */
function checkClaims(payload, jwk, { path }, step) {
  if (typeof payload.env !== 'string' || !payload.env) {
    throw new VerifyError('CLAIM_ENV_MISSING', 'the receipt states no environment (env claim)', step);
  }
  if (payload.env !== jwk.environment) {
    throw new VerifyError('CLAIM_ENV_MISMATCH', `receipt env ${payload.env} is not key ${jwk.kid}'s environment ${jwk.environment}`, step);
  }
  if (typeof payload.endpoint !== 'string' || !payload.endpoint) {
    throw new VerifyError('CLAIM_ENDPOINT_MISSING', 'the receipt states no endpoint (endpoint claim)', step);
  }
  if (path !== undefined && payload.endpoint !== path) {
    throw new VerifyError('CLAIM_ENDPOINT_MISMATCH', `receipt was issued on ${payload.endpoint}, not ${path}`, step);
  }
  if (!endpointAllowed(jwk.valid_endpoints, payload.endpoint)) {
    throw new VerifyError('ENDPOINT_NOT_VALID_FOR_KEY', `key ${jwk.kid} is not valid for endpoint ${payload.endpoint}`, step);
  }
}

function findKey(jwks, kid) {
  const matches = jwks.keys.filter(k => k && k.kid === kid);
  if (matches.length !== 1) {
    throw new VerifyError('KID_NOT_TRUSTED', matches.length ? `kid ${kid} appears ${matches.length} times in the trusted JWKS` : `kid ${kid} is not in the trusted JWKS`, 0);
  }
  return matches[0];
}

async function verifyJwsWithKey(jws, jwk, issuer, step) {
  const { importJWK, jwtVerify } = require('jose');
  try {
    const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, 'ES384');
    const { payload } = await jwtVerify(jws, key, { issuer, algorithms: ['ES384'] });
    return payload;
  } catch (e) {
    throw new VerifyError(step === 1 ? 'ECDSA_VERIFY_FAILED' : 'SIGNATURE_INVALID', e.message, step);
  }
}

function headerOf(jws) {
  const { decodeProtectedHeader } = require('jose');
  let header;
  try { header = decodeProtectedHeader(jws); } catch (e) {
    throw new VerifyError('RECEIPT_MALFORMED', `not a compact JWS (${e.message})`, 0);
  }
  if (header.alg !== 'ES384') throw new VerifyError('RECEIPT_MALFORMED', `alg ${header.alg}, expected ES384`, 0);
  if (typeof header.kid !== 'string' || !header.kid) throw new VerifyError('RECEIPT_MALFORMED', 'the JWS header names no kid', 0);
  return header;
}

/**
 * Verify one receipt (the X-GeoClear-Receipt header) for the request and
 * response it covers.
 *
 * Trust source, as for verifyBundle: `jwksJson` (string or object; used
 * exclusively when given), or the JWKS fetched from `jwksUrl` (https only),
 * unless `offline: true`, which refuses (TRUST_SOURCE_REQUIRED).
 * `trustedJwksSha256` is refused (TRUST_PIN_REMOVED). `expectedEnv` defaults
 * to "production"; null accepts a key of any environment (the key's metadata,
 * status and endpoints are still enforced). Throws a VerifyError with `.code`;
 * returns the verified payload as signed, without evaluating any of its claims
 * beyond those listed above.
 */
async function verifyGeoClearReceipt({
  receipt, method, path, requestBody, responseBody,
  issuer = DEFAULT_ISS, jwksUrl = DEFAULT_JWKS_URL, jwksJson, offline = false, trustedJwksSha256,
  expectedEnv = DEFAULT_EXPECTED_ENV, expectedPurpose, fetchImpl,
}) {
  if (trustedJwksSha256 !== undefined) {
    throw new VerifyError('TRUST_PIN_REMOVED', 'trustedJwksSha256 is not supported: pass jwksJson (a JWKS obtained from GeoClear) or use the live JWKS', 0);
  }
  if (!receipt) throw new Error('receipt is required');
  if (!method || !path) throw new Error('method and path are required');
  if (!responseBody) throw new Error('responseBody is required');

  const header = headerOf(receipt);
  let jwks;
  if (jwksJson !== undefined) jwks = parseJwks(jwksJson, 'jwksJson');
  else if (offline) throw new VerifyError('TRUST_SOURCE_REQUIRED', 'offline verification needs jwksJson (a JWKS obtained from GeoClear)', 0);
  else jwks = await fetchJwks(jwksUrl, { fetchImpl });
  const jwk = findKey(jwks, header.kid);
  checkKey(jwk, { expectedEnv, expectedPurpose });
  // `path` is the request target as sent: a path, optionally with its query.
  // The endpoint claim is the path alone; req_hash covers path and query.
  const q = String(path).indexOf('?');
  const pathname = q < 0 ? String(path) : String(path).slice(0, q);
  if (canonicalPath(pathname) === null) throw new VerifyError('PATH_NOT_CANONICAL', `path ${JSON.stringify(pathname)} is not a canonical request path`, 0);
  if (!endpointAllowed(jwk.valid_endpoints, pathname)) throw new VerifyError('ENDPOINT_NOT_VALID_FOR_KEY', `key ${jwk.kid} is not valid for ${pathname}`, 0);

  const payload = await verifyJwsWithKey(receipt, jwk, issuer, 1);
  checkClaims(payload, jwk, { path: pathname }, 1);

  const reqRepr = `${method} ${path}\n${requestBody ? canonicalize(requestBody) : ''}`;
  const reqHash = 'sha256:' + sha256Hex(Buffer.from(reqRepr, 'utf8'));
  const respHash = 'sha256:' + sha256Hex(canonicalize(responseBody));

  if (payload.req_hash !== reqHash) {
    throw new VerifyError('REQUEST_HASH_MISMATCH', `receipt=${payload.req_hash} expected=${reqHash}`, 1);
  }
  if (payload.resp_hash !== respHash) {
    throw new VerifyError('RESPONSE_HASH_MISMATCH', `receipt=${payload.resp_hash} expected=${respHash}`, 1);
  }
  return payload;
}

// ─── Evidence Bundle verification, hybrid ECDSA + ML-DSA-87 (trust model v2.0.0) ─
//
// The bundle's signature/ files: mldsa.sig (raw 4627-byte ML-DSA-87
// signature), mldsa-pubkey.json (public key descriptor) and
// mldsa-signed-input.bytes (the JWS signing input both signatures cover).
//
// Verification chain:
//   0. Trust: resolve the trusted JWKS (supplied or live), find the kid there,
//      enforce its key metadata, and check the bundle's snapshot and trust
//      anchor against it.
//   1. Verify the ECDSA P-384 JWS with the TRUSTED key; check its claims.
//   2. Recompute sha384(decoded mldsa-pubkey bytes).
//   3. Confirm match with the JWS payload pqc_pubkey_fingerprint claim
//      (the signed ECDSA receipt names the ML-DSA public key it vouches for).
//   4. Require the signed-input bytes to be the receipt's JWS signing input,
//      then verify the ML-DSA-87 signature over them. The ML-DSA key is trusted
//      only through the fingerprint the ECDSA-signed receipt carries.
//
// Any single failure is a tamper or trust signal with a specific error code.

const AdmZip = require('adm-zip');

function sha384Hex(buf) {
  return crypto.createHash('sha384').update(buf).digest('hex');
}

function b64ToBuffer(b64) {
  let s = String(b64).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function parseBundle(zipBytes) {
  const zip = new AdmZip(Buffer.isBuffer(zipBytes) ? zipBytes : Buffer.from(zipBytes));
  const read = name => {
    const e = zip.getEntry(name);
    return e ? e.getData() : null;
  };
  const readStr = name => {
    const b = read(name);
    return b ? b.toString('utf8') : null;
  };

  const receiptJws = readStr('receipt/receipt.jws');
  if (!receiptJws) throw new Error('Bundle missing receipt/receipt.jws — not a GeoClear Evidence Bundle');
  const trustJwksBytes = read('trust/jwks-snapshot.json');
  const trustJwks = trustJwksBytes ? trustJwksBytes.toString('utf8') : '';
  const trustAnchor = readStr('trust/trust-anchor.txt') || '';
  // audit/verification-report.json is informational and never used to verify;
  // a malformed one is reported as null rather than failing the bundle.
  const verificationReport = (() => {
    const s = readStr('audit/verification-report.json');
    if (!s) return null;
    try { return JSON.parse(s); } catch (_e) { return null; }
  })();

  const mldsaSig = read('signature/mldsa.sig');
  const mldsaPubkeyJsonStr = readStr('signature/mldsa-pubkey.json');
  const mldsaSignedInput = read('signature/mldsa-signed-input.bytes');
  const hasPqcOverlay = !!(mldsaSig && mldsaPubkeyJsonStr && mldsaSignedInput);

  let mldsaPubkeyBytes = null;
  let mldsaPubkeyDescriptor = null;
  if (hasPqcOverlay) {
    mldsaPubkeyDescriptor = JSON.parse(mldsaPubkeyJsonStr);
    if (!mldsaPubkeyDescriptor.pubkey_b64) {
      throw new Error('signature/mldsa-pubkey.json missing pubkey_b64 field');
    }
    mldsaPubkeyBytes = b64ToBuffer(mldsaPubkeyDescriptor.pubkey_b64);
  }

  return {
    receipt_jws: receiptJws.replace(/\n+$/, ''),
    trust_jwks_json: trustJwks,
    trust_jwks_sha256: trustJwksBytes ? sha256Hex(trustJwksBytes) : null,
    trust_anchor_txt: trustAnchor,
    verification_report: verificationReport,
    has_pqc_overlay: hasPqcOverlay,
    mldsa_signature_bytes: mldsaSig || undefined,
    mldsa_pubkey_bytes: mldsaPubkeyBytes || undefined,
    mldsa_pubkey_descriptor: mldsaPubkeyDescriptor || undefined,
    mldsa_signed_input: mldsaSignedInput || undefined,
  };
}

/** What trust/trust-anchor.txt declares: { jwks_sha256, kid } (null when absent). */
function parseTrustAnchor(text) {
  if (!text) return null;
  const sha = /^JWKS sha256:\s*([0-9a-fA-F]{64})\s*$/m.exec(text);
  const kid = /^Key ID:\s*(\S+)\s*$/m.exec(text);
  return { jwks_sha256: sha ? sha[1].toLowerCase() : null, kid: kid ? kid[1] : null };
}

/**
 * Verify an Evidence Bundle (an ECDSA P-384 receipt, with an ML-DSA-87 layer
 * when the bundle carries one).
 *
 * Trust source (exactly one; no fallback between them):
 *   - jwksJson: a JWKS the caller trusts (string or object), obtained from
 *     GeoClear independently of the bundle; this is how to verify offline;
 *   - otherwise the JWKS fetched live from jwksUrl, unless offline: true, which
 *     refuses (TRUST_SOURCE_REQUIRED): a bundle cannot vouch for itself.
 * trustedJwksSha256 is not an option and is refused (TRUST_PIN_REMOVED).
 * expectedEnv defaults to "production"; null accepts a key of any environment.
 * The receipt's env and endpoint claims are always required and must match the
 * key (step 5, after the ML-DSA layer).
 */
async function verifyBundle({
  zip, jwksJson, trustedJwksSha256, jwksUrl = DEFAULT_JWKS_URL, offline = false,
  issuer = DEFAULT_ISS, expectedEnv = DEFAULT_EXPECTED_ENV, expectedPurpose, fetchImpl,
}) {
  // Refused, never ignored: a caller relying on a pin must not silently get a
  // different trust source instead.
  if (trustedJwksSha256 !== undefined) {
    throw new VerifyError('TRUST_PIN_REMOVED', 'trustedJwksSha256 is not supported: a pinned bundle snapshot is not an independent trust source. Pass jwksJson (a JWKS obtained from GeoClear, not from the bundle) or use the live JWKS', 0);
  }
  const t0 = Date.now();
  const parsed = parseBundle(zip);
  const jwsHeader = headerOf(parsed.receipt_jws);
  const anchor = parseTrustAnchor(parsed.trust_anchor_txt);

  // Step 0: the trusted JWKS.
  let trusted;
  let source;
  if (jwksJson !== undefined) {
    trusted = parseJwks(jwksJson, 'jwksJson');
    source = 'supplied';
  } else if (offline) {
    throw new VerifyError('TRUST_SOURCE_REQUIRED', 'offline verification needs jwksJson (a JWKS obtained from GeoClear, not from the bundle); the bundle\'s own snapshot does not vouch for itself', 0);
  } else {
    trusted = await fetchJwks(jwksUrl, { fetchImpl });
    source = 'live';
  }
  if (anchor && anchor.kid && anchor.kid !== jwsHeader.kid) {
    throw new VerifyError('BUNDLE_TRUST_ANCHOR_MISMATCH', `trust/trust-anchor.txt names key ${anchor.kid}, the receipt is signed under ${jwsHeader.kid}`, 0);
  }
  const jwk = findKey(trusted, jwsHeader.kid);
  checkKey(jwk, { expectedEnv, expectedPurpose });
  if (parsed.trust_jwks_json) {
    let snapshot = null;
    try { snapshot = JSON.parse(parsed.trust_jwks_json); } catch (_e) { snapshot = null; }
    const own = snapshot && Array.isArray(snapshot.keys) ? snapshot.keys.filter(k => k && k.kid === jwsHeader.kid) : [];
    if (own.some(k => k.x !== jwk.x || k.y !== jwk.y || k.crv !== jwk.crv)) {
      throw new VerifyError('BUNDLE_SNAPSHOT_KEY_MISMATCH', `the bundle's snapshot holds a different key under ${jwsHeader.kid} than the trusted JWKS`, 0);
    }
  }

  // Step 1: the ECDSA P-384 JWS, with the trusted key. Its claims are checked
  // in step 5, after the ML-DSA layer (steps 2-4) when there is one.
  const jwsPayload = await verifyJwsWithKey(parsed.receipt_jws, jwk, issuer, 1);

  const trust = {
    source,
    kid: jwk.kid,
    key: { environment: jwk.environment, key_purpose: jwk.key_purpose, status: jwk.status, valid_endpoints: jwk.valid_endpoints },
    claims: { env: jwsPayload.env === undefined ? null : jwsPayload.env, endpoint: jwsPayload.endpoint === undefined ? null : jwsPayload.endpoint },
    trust_anchor: anchor ? { declared_jwks_sha256: anchor.jwks_sha256, snapshot_sha256: parsed.trust_jwks_sha256, matches_snapshot: anchor.jwks_sha256 !== null && anchor.jwks_sha256 === parsed.trust_jwks_sha256 } : null,
  };

  // Non-hybrid bundle: no ML-DSA layer; step 5 (claims) only.
  if (!parsed.has_pqc_overlay) {
    checkClaims(jwsPayload, jwk, {}, 5);
    return {
      valid: true,
      ms: Date.now() - t0,
      mode: 'ecdsa-only',
      jws_header: jwsHeader,
      jws_payload: jwsPayload,
      pqc_overlay: null,
      trust,
    };
  }

  // The ML-DSA layer is verified with ML-DSA-87 only. The descriptor is bundle
  // content, so an algorithm it names is refused rather than reported as if it
  // had been verified; a signed pqc_alg claim, when present, must agree.
  if (parsed.mldsa_pubkey_descriptor.alg !== MLDSA_ALG) {
    const err = new Error(`ML_DSA_ALG_UNSUPPORTED: signature/mldsa-pubkey.json declares alg ${JSON.stringify(parsed.mldsa_pubkey_descriptor.alg)}; only ${MLDSA_ALG} is verified`);
    err.code = 'ML_DSA_ALG_UNSUPPORTED';
    err.step = 2;
    throw err;
  }
  if (jwsPayload.pqc_alg !== undefined && jwsPayload.pqc_alg !== MLDSA_ALG) {
    const err = new Error(`ML_DSA_ALG_UNSUPPORTED: the signed pqc_alg claim is ${JSON.stringify(jwsPayload.pqc_alg)}; only ${MLDSA_ALG} is verified`);
    err.code = 'ML_DSA_ALG_UNSUPPORTED';
    err.step = 2;
    throw err;
  }

  // Step 2: Recompute sha384(mldsa pubkey bytes).
  const recomputedFingerprintHex = sha384Hex(parsed.mldsa_pubkey_bytes);

  // Step 3: Confirm match with JWS payload pqc_pubkey_fingerprint claim.
  const claim = jwsPayload.pqc_pubkey_fingerprint;
  if (!claim) {
    const err = new Error('ECDSA_CHAIN_ANCHOR_MISSING: JWS payload has no pqc_pubkey_fingerprint claim; ECDSA chain does not anchor ML-DSA layer');
    err.code = 'ECDSA_CHAIN_ANCHOR_MISSING';
    err.step = 3;
    throw err;
  }
  const claimedHex = String(claim).replace(/^sha384:/, '');
  if (claimedHex.toLowerCase() !== recomputedFingerprintHex.toLowerCase()) {
    const err = new Error(
      `ECDSA_CHAIN_FINGERPRINT_MISMATCH: ECDSA chain does not anchor ML-DSA public key. ` +
      `Expected (from JWS payload claim): ${claimedHex.slice(0, 32)}... ` +
      `Got (recomputed from signature/mldsa-pubkey.json): ${recomputedFingerprintHex.slice(0, 32)}... ` +
      `Possible downgrade/swap attack on the ML-DSA pubkey.`
    );
    err.code = 'ECDSA_CHAIN_FINGERPRINT_MISMATCH';
    err.step = 3;
    err.claimed = claimedHex;
    err.recomputed = recomputedFingerprintHex;
    throw err;
  }

  // Step 4: the ML-DSA-87 signature must be over the receipt's own JWS signing
  // input (BASE64URL(header).BASE64URL(payload)), the bytes the ECDSA signature
  // covers. A signature over any other bytes is refused before it is checked.
  const receiptSigningInput = Buffer.from(parsed.receipt_jws.split('.').slice(0, 2).join('.'), 'utf8');
  if (!Buffer.from(parsed.mldsa_signed_input).equals(receiptSigningInput)) {
    throw new VerifyError('ML_DSA_SIGNED_INPUT_MISMATCH', 'signature/mldsa-signed-input.bytes is not the receipt\'s JWS signing input; the ML-DSA-87 signature does not cover the signed receipt', 4);
  }
  let mldsaOk = false;
  try {
    // @noble/post-quantum v0.6.1 is ESM-only; use dynamic import() so this
    // CJS module can still load it. verifyBundle is async so await works here.
    // API: ml_dsa87.verify(signature, message, publicKey); the @noble convention
    // is signature-first (matches @noble/curves verify shape).
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    mldsaOk = ml_dsa87.verify(
      parsed.mldsa_signature_bytes,
      parsed.mldsa_signed_input,
      parsed.mldsa_pubkey_bytes
    );
  } catch (e) {
    const err = new Error(`ML_DSA_VERIFY_THREW: ${e.message}`);
    err.code = 'ML_DSA_VERIFY_THREW';
    err.step = 4;
    throw err;
  }
  if (!mldsaOk) {
    const err = new Error(
      'ML_DSA_SIGNATURE_INVALID: ML-DSA-87 signature does not verify against the public key + signed-input bytes in the bundle. Possible tamper on signature/mldsa.sig or signature/mldsa-signed-input.bytes.'
    );
    err.code = 'ML_DSA_SIGNATURE_INVALID';
    err.step = 4;
    throw err;
  }

  // Step 5: the receipt's claims against the trusted key.
  checkClaims(jwsPayload, jwk, {}, 5);

  return {
    valid: true,
    ms: Date.now() - t0,
    mode: 'hybrid-ecdsa-p384-mldsa-87',
    jws_header: jwsHeader,
    jws_payload: jwsPayload,
    trust,
    pqc_overlay: {
      alg: MLDSA_ALG,
      standard: parsed.mldsa_pubkey_descriptor.standard ?? null,
      security_level: parsed.mldsa_pubkey_descriptor.cnsa_2_security_level ?? null,
      pubkey_fingerprint_sha384: recomputedFingerprintHex,
      key_lifecycle: parsed.mldsa_pubkey_descriptor.key_lifecycle ?? null,
      signature_bytes: parsed.mldsa_signature_bytes.length,
      pubkey_bytes: parsed.mldsa_pubkey_bytes.length,
    },
  };
}

// ─── policy_bundle shape check (v1.4.0; scope narrowed in v2.0.0) ──────────
//
// validatePolicyBundle checks the SHAPE of the optional, informational
// `policy_bundle` claim a receipt payload may carry: each field that is
// present has the expected type and size. That is all it does. It never
// yields, verifies or interprets a decision, an authorization, a denial or a
// policy result: verifier_result.verdict, for example, is checked to be a
// non-empty string and nothing else. verifyGeoClearReceipt and verifyBundle
// never call it, and its result never changes theirs.
//
// v2.0.0 removed replayPolicyBundle (1.4.0), which recomputed a commitment
// over the claim's content and returned a verdict alongside the issuer's own
// result. This package verifies signatures, integrity and trust only.
//
// Contract:
//   - `bundle === undefined` or `bundle === null` → null (no claim).
//   - `bundle === {}` → null. A bundle may carry any subset of the fields.
//   - Each present field is checked; the first violation is returned as
//     { error_code, error_field, message }.
//
// Error codes (stable since v1.4.0): POLICY_BUNDLE_INVALID,
// ORIGINAL_POLICY_TEXT_INVALID, STRUCTURED_INTERPRETATION_INVALID,
// POLICY_COMMITMENT_INVALID, RUNTIME_OUTCOME_INVALID, CLAIM_SOURCE_MAP_INVALID,
// CLAIM_SOURCE_INVALID, VERIFIER_RESULT_INVALID, OFFLINE_REPLAY_RESULT_INVALID.

/** The claim_source values the shape check accepts. Frozen. */
const CLAIM_SOURCES = Object.freeze([
  'customer_declared',
  'source_attested',
  'geoclear_verified',
  'demo_synthetic',
  'llm_compiled',
]);

/** Size caps. */
const MAX_ORIGINAL_POLICY_TEXT_LEN = 65_536;
const MAX_CLAIM_SOURCE_MAP_ENTRIES = 256;
const MAX_CLAIM_KEY_LEN = 256;
const MAX_VERIFIER_RESULT_DETAILS_LEN = 4_096;
const MAX_OFFLINE_REPLAY_RESULT_LEN = 8_192;
const MAX_ENUM_STRING_LEN = 128;

const SHA384_TAG_REGEX = /^sha384:[0-9a-f]{96}$/;

function _isTaggedSha384(v) {
  return typeof v === 'string' && SHA384_TAG_REGEX.test(v);
}

function _isClaimSource(v) {
  return typeof v === 'string' && CLAIM_SOURCES.includes(v);
}

// ─── v5.1 sub-validators ─────────────────────────────────────────────────────

function _validateOriginalPolicyText(v) {
  if (typeof v !== 'string') {
    return {
      error_code: 'ORIGINAL_POLICY_TEXT_INVALID',
      error_field: 'policy_bundle.original_policy_text',
      message: 'original_policy_text must be a string',
    };
  }
  if (v.length === 0 || v.length > MAX_ORIGINAL_POLICY_TEXT_LEN) {
    return {
      error_code: 'ORIGINAL_POLICY_TEXT_INVALID',
      error_field: 'policy_bundle.original_policy_text',
      message: `original_policy_text length must be between 1 and ${MAX_ORIGINAL_POLICY_TEXT_LEN} chars`,
    };
  }
  return null;
}

function _validateStructuredInterpretation(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'STRUCTURED_INTERPRETATION_INVALID',
      error_field: 'policy_bundle.structured_interpretation',
      message: 'structured_interpretation must be a non-array object',
    };
  }
  return null;
}

function _validatePolicyCommitment(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'POLICY_COMMITMENT_INVALID',
      error_field: 'policy_bundle.policy_commitment',
      message: 'policy_commitment must be a non-array object',
    };
  }
  if (!_isTaggedSha384(v.commitment_hash)) {
    return {
      error_code: 'POLICY_COMMITMENT_INVALID',
      error_field: 'policy_bundle.policy_commitment.commitment_hash',
      message: 'policy_commitment.commitment_hash must be sha384:<96-hex>',
    };
  }
  return null;
}

function _validateRuntimeOutcome(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'RUNTIME_OUTCOME_INVALID',
      error_field: 'policy_bundle.runtime_outcome',
      message: 'runtime_outcome must be a non-array object',
    };
  }
  if (!_isTaggedSha384(v.decision_packet_hash)) {
    return {
      error_code: 'RUNTIME_OUTCOME_INVALID',
      error_field: 'policy_bundle.runtime_outcome.decision_packet_hash',
      message: 'runtime_outcome.decision_packet_hash must be sha384:<96-hex>',
    };
  }
  return null;
}

function _validateClaimSourceMap(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'CLAIM_SOURCE_MAP_INVALID',
      error_field: 'policy_bundle.claim_source_map',
      message: 'claim_source_map must be a non-array object (string -> claim_source)',
    };
  }
  const keys = Object.keys(v);
  if (keys.length > MAX_CLAIM_SOURCE_MAP_ENTRIES) {
    return {
      error_code: 'CLAIM_SOURCE_MAP_INVALID',
      error_field: 'policy_bundle.claim_source_map',
      message: `claim_source_map may contain at most ${MAX_CLAIM_SOURCE_MAP_ENTRIES} entries`,
    };
  }
  for (const k of keys) {
    if (typeof k !== 'string' || k.length === 0 || k.length > MAX_CLAIM_KEY_LEN) {
      return {
        error_code: 'CLAIM_SOURCE_MAP_INVALID',
        error_field: `policy_bundle.claim_source_map.${k}`,
        message: 'claim_source_map keys must be non-empty strings <=256 chars',
      };
    }
    if (!_isClaimSource(v[k])) {
      return {
        error_code: 'CLAIM_SOURCE_INVALID',
        error_field: `policy_bundle.claim_source_map.${k}`,
        message: `claim_source_map[${k}] must be one of: ${CLAIM_SOURCES.join(', ')}`,
      };
    }
  }
  return null;
}

function _validateVerifierResult(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'VERIFIER_RESULT_INVALID',
      error_field: 'policy_bundle.verifier_result',
      message: 'verifier_result must be a non-array object',
    };
  }
  if (typeof v.verdict !== 'string' || v.verdict.length === 0 || v.verdict.length > MAX_ENUM_STRING_LEN) {
    return {
      error_code: 'VERIFIER_RESULT_INVALID',
      error_field: 'policy_bundle.verifier_result.verdict',
      message: 'verifier_result.verdict must be a non-empty string',
    };
  }
  if (v.details !== undefined) {
    if (typeof v.details !== 'string' || v.details.length > MAX_VERIFIER_RESULT_DETAILS_LEN) {
      return {
        error_code: 'VERIFIER_RESULT_INVALID',
        error_field: 'policy_bundle.verifier_result.details',
        message: `verifier_result.details must be a string <=${MAX_VERIFIER_RESULT_DETAILS_LEN} chars when present`,
      };
    }
  }
  return null;
}

function _validateOfflineReplayResult(v) {
  if (v == null || typeof v !== 'object' || Array.isArray(v)) {
    return {
      error_code: 'OFFLINE_REPLAY_RESULT_INVALID',
      error_field: 'policy_bundle.offline_replay_result',
      message: 'offline_replay_result must be a non-array object',
    };
  }
  try {
    const bytes = canonicalize(v);
    if (bytes.length > MAX_OFFLINE_REPLAY_RESULT_LEN) {
      return {
        error_code: 'OFFLINE_REPLAY_RESULT_INVALID',
        error_field: 'policy_bundle.offline_replay_result',
        message: `offline_replay_result canonical size must be <=${MAX_OFFLINE_REPLAY_RESULT_LEN} bytes`,
      };
    }
  } catch (_e) {
    return {
      error_code: 'OFFLINE_REPLAY_RESULT_INVALID',
      error_field: 'policy_bundle.offline_replay_result',
      message: 'offline_replay_result must be JCS-canonicalizable',
    };
  }
  return null;
}

/**
 * Check the shape of the optional, informational `policy_bundle` claim.
 * Shape only: it never yields, verifies or interprets a decision.
 *
 * @param {object|null|undefined} bundle
 * @returns {null | {error_code, error_field, message}}
 */
function validatePolicyBundle(bundle) {
  if (bundle === undefined || bundle === null) {
    return null; // no claim
  }
  if (typeof bundle !== 'object' || Array.isArray(bundle)) {
    return {
      error_code: 'POLICY_BUNDLE_INVALID',
      error_field: 'policy_bundle',
      message: 'policy_bundle must be a non-array object when present',
    };
  }
  if (bundle.original_policy_text !== undefined) {
    const err = _validateOriginalPolicyText(bundle.original_policy_text);
    if (err) return err;
  }
  if (bundle.structured_interpretation !== undefined) {
    const err = _validateStructuredInterpretation(bundle.structured_interpretation);
    if (err) return err;
  }
  if (bundle.policy_commitment !== undefined) {
    const err = _validatePolicyCommitment(bundle.policy_commitment);
    if (err) return err;
  }
  if (bundle.runtime_outcome !== undefined) {
    const err = _validateRuntimeOutcome(bundle.runtime_outcome);
    if (err) return err;
  }
  if (bundle.claim_source_map !== undefined) {
    const err = _validateClaimSourceMap(bundle.claim_source_map);
    if (err) return err;
  }
  if (bundle.verifier_result !== undefined) {
    const err = _validateVerifierResult(bundle.verifier_result);
    if (err) return err;
  }
  if (bundle.offline_replay_result !== undefined) {
    const err = _validateOfflineReplayResult(bundle.offline_replay_result);
    if (err) return err;
  }
  return null;
}

module.exports = {
  // v1.0.0 API, trust model changed in v2.0.0 (see CHANGELOG.md)
  verifyGeoClearReceipt,
  canonicalize,
  sha256Hex,
  // v1.2: Evidence Bundle verification; trust model v2.0.0
  verifyBundle,
  parseBundle,
  sha384Hex,
  b64ToBuffer,
  // v2.0.0: trust model helpers
  VerifyError,
  parseTrustAnchor,
  canonicalPath,
  endpointAllowed,
  clearJwksCache,
  DEFAULT_JWKS_URL,
  DEFAULT_EXPECTED_ENV,
  // v1.4.0: policy_bundle shape check only (replayPolicyBundle removed in v2.0.0)
  validatePolicyBundle,
  CLAIM_SOURCES,
};
