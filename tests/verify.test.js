// v1.0.0 + v1.1.0 — local roundtrip tests: sign a synthetic receipt with
// a local P-384 key, construct a local JWKS, verify. Does NOT hit
// geoclear.io. v1.1.0 adds tests for the strict-gate parameters.

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

import { SignJWT, importJWK, jwtVerify, createLocalJWKSet } from 'jose';
const {
  verifyGeoClearReceipt,
  verifyEnclaveReceipt,
  canonicalize,
  sha256Hex,
} = require('../src/verify.js');

describe('@geoclear/verify-receipt — local roundtrip', () => {
  let publicJwk, privateKey, localJwks;
  const issuer = 'https://geoclear.io';

  beforeAll(() => {
    const { publicKey, privateKey: priv } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
    privateKey = priv;
    const jwk = publicKey.export({ format: 'jwk' });
    publicJwk = { ...jwk, use: 'sig', alg: 'ES384', kid: 'test-key-2026' };
    localJwks = { keys: [publicJwk] };
  });

  async function sign(payload) {
    const pkJwk = privateKey.export({ format: 'jwk' });
    const keyLike = await importJWK({ ...pkJwk, alg: 'ES384' }, 'ES384');
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES384', kid: 'test-key-2026', typ: 'JWT' })
      .sign(keyLike);
  }

  it('verifies a valid receipt round-trip (hash match)', async () => {
    const responseBody = { ok: true, count: 1, data: [{ address_id: 'X' }] };
    const method = 'GET';
    const path = '/v1/demo?x=y';
    const req_hash = 'sha256:' + sha256Hex(`${method} ${path}\n`);
    const resp_hash = 'sha256:' + sha256Hex(canonicalize(responseBody));

    const payload = {
      iss: issuer, iat: Math.floor(Date.now() / 1000), sub: 'req-test-1',
      api_version: 'v1', endpoint: '/v1/demo',
      req_hash, resp_hash, status: 200,
    };
    const jws = await sign(payload);

    const { payload: verified } = await jwtVerify(jws, createLocalJWKSet(localJwks), {
      issuer, algorithms: ['ES384'],
    });
    expect(verified.req_hash).toBe(req_hash);
    expect(verified.resp_hash).toBe(resp_hash);
  });

  it('detects a tampered response body (hash mismatch)', async () => {
    const responseBody = { ok: true, data: 'original' };
    const resp_hash = 'sha256:' + sha256Hex(canonicalize(responseBody));
    const payload = {
      iss: issuer, iat: Math.floor(Date.now() / 1000), sub: 'r',
      api_version: 'v1', endpoint: '/v1/x',
      req_hash: 'sha256:reqhash', resp_hash, status: 200,
    };
    const jws = await sign(payload);
    const { payload: verified } = await jwtVerify(jws, createLocalJWKSet(localJwks), {
      issuer, algorithms: ['ES384'],
    });

    const tampered = { ok: true, data: 'tampered' };
    const tamperedHash = 'sha256:' + sha256Hex(canonicalize(tampered));
    expect(verified.resp_hash).not.toBe(tamperedHash);
  });

  it('canonicalize helper respects RFC 8785 key order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

// ===========================================================================
// v1.1.0 — Enclave receipt + strict-gate tests
// ===========================================================================
describe('@geoclear/verify-receipt — v1.1.0 enclave receipt + strict gates', () => {
  let publicJwk, privateKey, localJwks;
  const issuer = 'https://geoclear.io';
  const ACCT = '769533384420';
  const REGION = 'us-east-1';
  const INSTANCE = 'i-095d3b347ed8703e5';
  const PCR0 = '98fc045975c7b9a58cf2fcd89ae7804d8e06d8b31c5c80585ed87a78f76b2f7fb4374183b5ce353d387a6216b8ca9f4d';

  beforeAll(async () => {
    const { publicKey, privateKey: priv } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
    privateKey = priv;
    const jwk = publicKey.export({ format: 'jwk' });
    publicJwk = { ...jwk, use: 'sig', alg: 'ES384', kid: 'geoclear-response-signing-attested-2026' };
    localJwks = { keys: [publicJwk] };
  });

  async function signEnclave(canonicalPayload, augmented = {}) {
    const pkJwk = privateKey.export({ format: 'jwk' });
    const keyLike = await importJWK({ ...pkJwk, alg: 'ES384' }, 'ES384');
    const bytes = Buffer.from(canonicalize(canonicalPayload), 'utf8');
    const resp_hash = 'sha256:' + sha256Hex(bytes);
    const payload = {
      iss: issuer,
      iat: Math.floor(Date.now() / 1000),
      sub: 'enclave-test-1',
      resp_hash,
      payload_size: bytes.length,
      ...augmented,
    };
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES384', kid: 'geoclear-response-signing-attested-2026', typ: 'JWT' })
      .sign(keyLike);
  }

  const payload = {
    decision_id: 'MSS-TGT-0991',
    leaf_4_laanc: { issuing_uas_service_supplier: 'Aloft-Enterprise' },
  };

  it('verifies a fact-witness enclave receipt against a local JWKS', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
    });
    expect(verified.signing_account_id).toBe(ACCT);
    expect(verified.signing_region).toBe(REGION);
    expect(verified.signing_instance_id).toBe(INSTANCE);
    expect(verified.pcr0).toBe(PCR0);
  });

  it('accepts canonicalPayload as a pre-computed Buffer', async () => {
    const bytes = Buffer.from(canonicalize(payload), 'utf8');
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: bytes, jwks: localJwks,
    });
    expect(verified.resp_hash).toBe('sha256:' + sha256Hex(bytes));
  });

  it('detects tampered canonical payload', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const tampered = { ...payload, decision_id: 'MSS-TGT-9999' };
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: tampered, jwks: localJwks,
    })).rejects.toThrow(/response hash mismatch/);
  });

  it('strict gate: expectedAccountId mismatch throws fatal', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedAccountId: '111111111111',
    })).rejects.toThrow(/strict expectedAccountId/);
  });

  it('strict gate: expectedAccountId match passes', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedAccountId: ACCT,
    });
    expect(verified.signing_account_id).toBe(ACCT);
  });

  it('strict gate: expectedPcr0 mismatch throws fatal', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedPcr0: '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    })).rejects.toThrow(/strict expectedPcr0/);
  });

  it('strict gate: expectedPcr0 match passes', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedPcr0: PCR0,
    });
    expect(verified.pcr0).toBe(PCR0);
  });

  it('strict gate: all four gates together — match passes', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedAccountId: ACCT,
      expectedRegion: REGION,
      expectedInstanceId: INSTANCE,
      expectedPcr0: PCR0,
    });
    expect(verified.sub).toBe('enclave-test-1');
  });

  it('strict gate: any single mismatch out of four throws fatal', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedAccountId: ACCT,
      expectedRegion: REGION,
      expectedInstanceId: 'i-WRONG',  // <-- single wrong field
      expectedPcr0: PCR0,
    })).rejects.toThrow(/strict expectedInstanceId/);
  });

  it('strict gate: missing claim when gate is provided throws fatal', async () => {
    // Receipt with NO augmented claims — caller provides expectedAccountId
    const jws = await signEnclave(payload, {});
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, jwks: localJwks,
      expectedAccountId: ACCT,
    })).rejects.toThrow(/missing required claim/);
  });

  it('payload_size sanity check fires when payload differs in size', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, pcr0: PCR0,
    });
    // Caller passes the wrong canonical bytes with intentionally different length
    const wrongBytes = Buffer.from(canonicalize(payload) + ' ', 'utf8');
    await expect(verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: wrongBytes, jwks: localJwks,
    })).rejects.toThrow();  // resp_hash mismatch fires first; size check is defense-in-depth
  });

  it('verifyEnclaveReceipt accepts a single publicKeyJwk (no JWKS needed)', async () => {
    const jws = await signEnclave(payload, {
      signing_account_id: ACCT, signing_region: REGION,
      signing_instance_id: INSTANCE, pcr0: PCR0,
    });
    const verified = await verifyEnclaveReceipt({
      receipt: jws, canonicalPayload: payload, publicKeyJwk: publicJwk,
      expectedAccountId: ACCT, expectedPcr0: PCR0,
    });
    expect(verified.signing_account_id).toBe(ACCT);
  });
});
