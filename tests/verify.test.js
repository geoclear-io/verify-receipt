// Q-395/Q-397 — local roundtrip test: sign a synthetic receipt with a local
// P-384 key, construct a local JWKS, verify. Does NOT hit geoclear.io.

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

import { SignJWT, importJWK, jwtVerify, createLocalJWKSet } from 'jose';
const { canonicalize, sha256Hex } = require('../src/verify.js');

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
