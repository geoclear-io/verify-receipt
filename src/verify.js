'use strict';
/**
 * @geoclear/verify-receipt
 *
 * Verify a GeoClear signed decision receipt offline. Proves what GeoClear
 * returned at what moment, without calling GeoClear.
 *
 * v1.1.0 — Adds support for the 4 augmented JWS claims emitted by the
 * Maven-Mirror sovereign decision environment (Q-1219 / EPIC-2026-0036):
 *
 *   - signing_account_id    : AWS account that owns the KMS signing key
 *   - signing_region        : AWS region of the signing key (e.g. us-east-1)
 *   - signing_instance_id   : EC2 instance ID of the Nitro Enclave's parent
 *   - pcr0                  : SHA-384 hex of the running .eif binary
 *
 * These claims appear in receipts produced by the fact-witness enclave
 * pipeline. They are informational on the standard response-signing path
 * (today) and become assertable cryptographic gates via the new strict-
 * verification parameters (expectedAccountId / expectedPcr0 / etc.).
 */

const crypto = require('crypto');
const { jwtVerify, createRemoteJWKSet, createLocalJWKSet, importJWK } = require('jose');

const DEFAULT_ISS = 'https://geoclear.io';
const DEFAULT_JWKS_URL = 'https://geoclear.io/.well-known/jwks.json';

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

let jwksCache = null;
function getJwks(jwksUrl = DEFAULT_JWKS_URL) {
  if (jwksCache && jwksCache._url === jwksUrl) return jwksCache;
  jwksCache = createRemoteJWKSet(new URL(jwksUrl));
  jwksCache._url = jwksUrl;
  return jwksCache;
}

/**
 * Apply the v1.1.0 strict gates. Each gate is a fatal hard-stop when
 * the provided "expected" value does not exactly match the corresponding
 * claim in the JWS payload. When the expected value is undefined or null,
 * the gate is skipped (informational claims still flow through in the
 * returned payload).
 *
 * @throws {Error} if any provided expected value mismatches the claim.
 */
function applyStrictGates(payload, gates) {
  const checks = [
    ['expectedAccountId',   'signing_account_id'],
    ['expectedRegion',      'signing_region'],
    ['expectedInstanceId',  'signing_instance_id'],
    ['expectedPcr0',        'pcr0'],
  ];
  for (const [paramKey, claimKey] of checks) {
    const expected = gates[paramKey];
    if (expected === undefined || expected === null) continue;
    const actual = payload[claimKey];
    if (typeof actual !== 'string' || actual.length === 0) {
      throw new Error(
        `strict ${paramKey}: receipt is missing required claim "${claimKey}"`
      );
    }
    if (actual !== expected) {
      throw new Error(
        `strict ${paramKey}: expected "${expected}" but receipt claim "${claimKey}" was "${actual}"`
      );
    }
  }
}

/**
 * Verify a GeoClear response-signing receipt (standard API path).
 *
 * v1.0.0 API preserved for back-compat. The optional v1.1.0 gates
 * (expectedAccountId / expectedRegion / expectedInstanceId / expectedPcr0)
 * fire only on receipts that carry the augmented claims; on a receipt
 * without them, providing a gate is a hard error (missing-claim).
 */
async function verifyGeoClearReceipt({
  receipt, method, path, requestBody, responseBody,
  issuer = DEFAULT_ISS, jwksUrl = DEFAULT_JWKS_URL,
  expectedAccountId, expectedRegion, expectedInstanceId, expectedPcr0,
}) {
  if (!receipt) throw new Error('receipt is required');
  if (!method || !path) throw new Error('method and path are required');
  if (!responseBody) throw new Error('responseBody is required');

  const { payload } = await jwtVerify(receipt, getJwks(jwksUrl), {
    issuer, algorithms: ['ES384'],
  });

  const reqRepr = `${method} ${path}\n${requestBody ? canonicalize(requestBody) : ''}`;
  const reqHash = 'sha256:' + sha256Hex(Buffer.from(reqRepr, 'utf8'));
  const respHash = 'sha256:' + sha256Hex(canonicalize(responseBody));

  if (payload.req_hash !== reqHash) {
    throw new Error(`request hash mismatch: receipt=${payload.req_hash} expected=${reqHash}`);
  }
  if (payload.resp_hash !== respHash) {
    throw new Error(`response hash mismatch: receipt=${payload.resp_hash} expected=${respHash}`);
  }

  applyStrictGates(payload, { expectedAccountId, expectedRegion, expectedInstanceId, expectedPcr0 });
  return payload;
}

/**
 * Verify a GeoClear fact-witness enclave receipt (Q-1219 sovereign-
 * decision-environment path).
 *
 * The fact-witness JWS shape differs from the response-signing shape:
 * there is no req_hash / method / path; the receipt records a single
 * canonical payload via resp_hash + payload_size. The 4 augmented
 * runtime-identity claims (signing_account_id / signing_region /
 * signing_instance_id / pcr0) bind the signature to the physical
 * signing host.
 *
 * Inputs (object):
 *   - receipt: required. The compact JWS string.
 *   - canonicalPayload: required. EITHER the object whose JCS-canonical
 *     SHA-256 should match the receipt's resp_hash claim, OR the
 *     canonical bytes themselves (Buffer / Uint8Array / string).
 *   - issuer: optional, default 'https://geoclear.io'.
 *   - jwks: optional. A JWKS object {keys:[...]} to use locally (no
 *     network). When set, jwksUrl is ignored.
 *   - jwksUrl: optional, default 'https://geoclear.io/.well-known/jwks.json'.
 *   - publicKeyJwk: optional. A single JWK to use directly (no network).
 *     When set, jwks and jwksUrl are ignored.
 *   - expectedAccountId: optional. Strict gate (v1.1.0).
 *   - expectedRegion: optional. Strict gate (v1.1.0).
 *   - expectedInstanceId: optional. Strict gate (v1.1.0).
 *   - expectedPcr0: optional. Strict gate (v1.1.0).
 *
 * Returns the verified JWS payload.
 *
 * Failures throw — there is no "warnings" surface. Each gate is a
 * cryptographic hard-stop.
 */
async function verifyEnclaveReceipt({
  receipt, canonicalPayload,
  issuer = DEFAULT_ISS, jwks, jwksUrl = DEFAULT_JWKS_URL, publicKeyJwk,
  expectedAccountId, expectedRegion, expectedInstanceId, expectedPcr0,
}) {
  if (!receipt) throw new Error('receipt is required');
  if (canonicalPayload === undefined || canonicalPayload === null) {
    throw new Error('canonicalPayload is required (object, Buffer, Uint8Array, or string)');
  }

  let keySource;
  if (publicKeyJwk) {
    keySource = await importJWK(publicKeyJwk, 'ES384');
  } else if (jwks) {
    keySource = createLocalJWKSet(jwks);
  } else {
    keySource = getJwks(jwksUrl);
  }

  const { payload } = await jwtVerify(receipt, keySource, {
    issuer, algorithms: ['ES384'],
  });

  // Recompute resp_hash from caller's canonical-payload input
  let bytes;
  if (Buffer.isBuffer(canonicalPayload)) {
    bytes = canonicalPayload;
  } else if (canonicalPayload instanceof Uint8Array) {
    bytes = Buffer.from(canonicalPayload);
  } else if (typeof canonicalPayload === 'string') {
    bytes = Buffer.from(canonicalPayload, 'utf8');
  } else {
    // Plain object — JCS-canonicalize ourselves
    bytes = Buffer.from(canonicalize(canonicalPayload), 'utf8');
  }
  const recomputed = 'sha256:' + sha256Hex(bytes);
  if (payload.resp_hash !== recomputed) {
    throw new Error(
      `response hash mismatch: receipt resp_hash=${payload.resp_hash} ` +
      `but caller's canonical-payload SHA-256=${recomputed}`
    );
  }

  // Optional payload_size sanity check
  if (typeof payload.payload_size === 'number' && payload.payload_size !== bytes.length) {
    throw new Error(
      `payload_size mismatch: receipt=${payload.payload_size} bytes ` +
      `but caller's canonical-payload=${bytes.length} bytes`
    );
  }

  applyStrictGates(payload, { expectedAccountId, expectedRegion, expectedInstanceId, expectedPcr0 });
  return payload;
}

module.exports = {
  verifyGeoClearReceipt,
  verifyEnclaveReceipt,
  canonicalize,
  sha256Hex,
};
