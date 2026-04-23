# @geoclear/verify-receipt

> Verify a GeoClear signed receipt in **any language, offline, without
> calling GeoClear servers.** Proves to a regulator years from now exactly
> what GeoClear returned at exactly what moment.

**Status (2026-04-23):** local prototype — not yet published. Public release
pending internal security review + legal review of the "attestation" claim.
Issue tracking: Q-382 Phase 2.8.

## What a signed receipt is

Every GeoClear API response (JSON) comes with an `X-GeoClear-Receipt` header.
That header value is a JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515))
with this payload:

```json
{
  "iss": "https://geoclear.io",
  "iat": 1745370001,
  "sub": "req_...",
  "api_version": "v1",
  "endpoint": "/v1/risk",
  "req_hash": "sha256:...",
  "resp_hash": "sha256:...",
  "status": 200
}
```

Signed with ECDSA on curve P-384 (`alg: ES384`), key held in AWS KMS, public
key distributed at `https://geoclear.io/.well-known/jwks.json`.

## What it attests to

> A signed receipt proves, cryptographically, **what GeoClear returned** at
> **what moment**. It does **not** attest to the ground-truth correctness of
> the underlying flood map, census tract, or climate model. If FEMA updates a
> flood-zone boundary six months from now, your old receipt is still valid —
> it accurately records what GeoClear returned on the day you asked.

This distinction is non-negotiable. We're in the attestation-of-our-
statements business, not the insurance-of-ground-truth business.

## Node.js

```js
// Requires: npm i jose
const { jwtVerify, createRemoteJWKSet } = require('jose');
const crypto = require('crypto');

const JWKS = createRemoteJWKSet(new URL('https://geoclear.io/.well-known/jwks.json'));

function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function verifyGeoClearReceipt({ receipt, requestMethod, requestPath, requestBody, responseBody }) {
  const { payload } = await jwtVerify(receipt, JWKS, {
    issuer: 'https://geoclear.io',
    algorithms: ['ES384'],
  });

  const reqRepr = `${requestMethod} ${requestPath}\n${requestBody ? canonicalize(requestBody) : ''}`;
  const reqHash = 'sha256:' + sha256(reqRepr);
  const respHash = 'sha256:' + sha256(canonicalize(responseBody));

  if (payload.req_hash !== reqHash)   throw new Error('request was tampered or differs from what GeoClear received');
  if (payload.resp_hash !== respHash) throw new Error('response was tampered');
  return payload;  // includes iat (timestamp), sub (request ID), status
}

module.exports = { verifyGeoClearReceipt };
```

## Python

```python
# Requires: pip install pyjwt cryptography requests
import hashlib, json, requests, jwt
from jwt.algorithms import ECAlgorithm

def canonicalize(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'))

def sha256(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()

def verify_geoclear_receipt(receipt, request_method, request_path, request_body, response_body):
    jwks = requests.get('https://geoclear.io/.well-known/jwks.json').json()
    header = jwt.get_unverified_header(receipt)
    key_jwk = next(k for k in jwks['keys'] if k['kid'] == header['kid'])
    key = ECAlgorithm.from_jwk(json.dumps(key_jwk))

    claims = jwt.decode(receipt, key=key, algorithms=['ES384'], issuer='https://geoclear.io')

    req_repr = f"{request_method} {request_path}\n{canonicalize(request_body) if request_body else ''}"
    req_hash = 'sha256:' + sha256(req_repr)
    resp_hash = 'sha256:' + sha256(canonicalize(response_body))

    assert claims['req_hash']  == req_hash,  'request was tampered or differs from what GeoClear received'
    assert claims['resp_hash'] == resp_hash, 'response was tampered'
    return claims
```

## Browser (vanilla JS, no dependencies besides `jose`)

```html
<script type="module">
import { jwtVerify, createRemoteJWKSet } from 'https://esm.sh/jose@5';

const JWKS = createRemoteJWKSet(new URL('https://geoclear.io/.well-known/jwks.json'));

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}

async function verify(receipt, method, path, reqBody, respBody) {
  const { payload } = await jwtVerify(receipt, JWKS, {
    issuer: 'https://geoclear.io', algorithms: ['ES384'],
  });
  const reqRepr = `${method} ${path}\n${reqBody ? canonicalize(reqBody) : ''}`;
  const reqHash = 'sha256:' + await sha256Hex(reqRepr);
  const respHash = 'sha256:' + await sha256Hex(canonicalize(respBody));
  if (payload.req_hash !== reqHash)   throw new Error('request tampered');
  if (payload.resp_hash !== respHash) throw new Error('response tampered');
  return payload;
}
</script>
```

## Future language support

- **Go:** planned (`go get github.com/shaileshjgd/geoclear-verify-receipt`)
- **Rust:** planned (`cargo add geoclear-verify-receipt`)
- **Ruby:** nice-to-have
- **Java:** nice-to-have

PRs welcome once the public package repo is open.

## License

MIT (planned). Current prototype: internal use only until the security +
legal review gate clears.
