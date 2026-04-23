'use strict';
/**
 * Q-382 — Node.js receipt verifier (local prototype).
 *
 * Public package `@geoclear/verify-receipt` will wrap this after user approves
 * publication to shaileshjgd/* GitHub + npm (CLAUDE.md GitHub separation rule).
 *
 * No dependencies on GeoClear internals. Only depends on `jose` (npm).
 */

const crypto = require('crypto');
const { jwtVerify, createRemoteJWKSet } = require('jose');

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

async function verifyGeoClearReceipt({
  receipt, method, path, requestBody, responseBody,
  issuer = DEFAULT_ISS, jwksUrl = DEFAULT_JWKS_URL,
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
  return payload;
}

module.exports = { verifyGeoClearReceipt, canonicalize, sha256Hex };
