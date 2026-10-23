# @geoclear/verify-receipt

> Verify a GeoClear signed receipt or Evidence Bundle. With a JWKS you saved
> (`jwksJson`, or `--jwks` on the CLI) it runs fully offline; by default it
> fetches GeoClear's published JWKS over https. A valid receipt is evidence of
> what GeoClear returned, and when.

Install with `npm install @geoclear/verify-receipt`. MIT licensed.

## What this package verifies, and what it does not

It verifies **signatures, integrity and trust**:

- the receipt's signature, with a key from a trust source you choose (below);
- that key's published metadata, and the receipt's `env` and `endpoint` claims
  against it;
- for a single receipt (`verifyGeoClearReceipt`), its request and response
  hashes against the request and response you supply;
- for an Evidence Bundle that includes an ML-DSA-87 signature layer
  (`verifyBundle`): that the signed receipt names the layer's public key, that
  the ML-DSA-87 signature is over exactly the receipt's JWS signing input, and
  that it verifies. The ML-DSA-87 key is trusted only because the ECDSA-signed
  receipt names its fingerprint, so the layer adds no protection if the ECDSA
  signature alone could be forged. `verifyBundle` does not compare
  `payload/canonical-payload.bytes` with the receipt's `resp_hash`; to check a
  response body, pass it to `verifyGeoClearReceipt`.

It does **not** evaluate, verify or act on decisions. Both functions return
the signed payload as it was signed, including any claims it carries about a
decision, an authorization, a denial or a policy result, without reading those
claims: they accept or refuse the receipt the same way whatever the claims say,
and the CLI prints the same lines and exits with the same code. A valid receipt
is evidence of what GeoClear signed. What you do with it is your decision.

**`validatePolicyBundle(bundle)`** checks only the **shape** of the optional,
informational `policy_bundle` claim: that each field it carries has the
expected type and size. It never yields, verifies or interprets a decision.
`verifyGeoClearReceipt` and `verifyBundle` do not call it, and its result never
changes theirs. (`replayPolicyBundle`, added in 1.4.0, was removed in 2.0.0.)

## v2.0.0: trust model (security fix, breaking)

Version 1.x let an Evidence Bundle vouch for itself (`verifyBundle({ zip })`
trusted the key in the bundle's own JWKS snapshot), never checked
`trust/trust-anchor.txt`, and ignored the key metadata the published JWKS
carries. In 2.0.0:

- **Trusted keys come from an independent source only.** That means a JWKS you
  supply (`jwksJson`) or the live JWKS (`jwksUrl`, https only, redirects
  included: `TRUST_SOURCE_NOT_HTTPS`). There is no fallback between them, and a bundle's
  own `trust/jwks-snapshot.json` is never a source. With `offline: true`, both
  functions need `jwksJson` (`TRUST_SOURCE_REQUIRED`): a JWKS you obtained from
  GeoClear, not from the bundle.
- **Key metadata is enforced.** The key must carry `key_purpose`,
  `environment`, `status: active` and the `valid_endpoints` the receipt's
  endpoint is in.
- **`expectedEnv` defaults to `production`.** Pass `expectedEnv: null` to
  accept a key of any environment. Either way, the receipt's `env` and
  `endpoint` claims must be present and agree with the key, so a receipt
  without them (issued before the `env` claim existed) cannot be verified by
  2.0.0.
- **There is no pinned-snapshot option.** A pre-release draft of 2.0.0 let a
  bundle's own snapshot be trusted when the caller passed its SHA-256
  (`trustedJwksSha256`). A caller who took that hash from the bundle accepted a
  forged bundle, so the option was removed before release. Passing it is refused
  by both functions (`TRUST_PIN_REMOVED`; the CLI's `--trusted-jwks-sha256` exits 5). Offline
  verification against a snapshot GeoClear has signed is planned as a separate
  feature.
- **The signature algorithms are fixed.** The receipt's JWS header must say
  `ES384` and the key must be EC P-384 (`RECEIPT_MALFORMED`,
  `KEY_TYPE_INVALID`). A bundle's ML-DSA layer must declare `ML-DSA-87`, and a
  signed `pqc_alg` claim, when present, must agree (`ML_DSA_ALG_UNSUPPORTED`).
  Its signature must be over the receipt's JWS signing input
  (`ML_DSA_SIGNED_INPUT_MISMATCH`).
- **`trust.trust_anchor` is reported, never trusted.** The hash a bundle's
  `trust/trust-anchor.txt` declares, and whether it matches the bundle's
  snapshot, are bundle content: they describe the bundle and decide nothing.

```js
const { verifyGeoClearReceipt, verifyBundle } = require('@geoclear/verify-receipt');

// A response header, checked against the live JWKS (production by default):
await verifyGeoClearReceipt({ receipt, method: 'GET', path: '/api/health', responseBody });

// A bundle, offline, with the JWKS you saved when you received it:
await verifyBundle({ zip, jwksJson: savedJwks, offline: true });
```

Error codes and the migration notes are in [CHANGELOG.md](CHANGELOG.md). The
inline Node.js, Python and browser examples below check the signature and
hashes only. They do not apply the key-metadata and claim checks above, so use
the package, or add those checks, before relying on a receipt as production
evidence.

## What a signed receipt is

Signed GeoClear API responses (JSON) carry an `X-GeoClear-Receipt` header;
not every route is signed. The header value is a JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515))
with this payload:

```json
{
  "iss": "https://geoclear.io",
  "iat": 1745370001,
  "sub": "req_...",
  "api_version": "v1",
  "env": "production",
  "endpoint": "/api/health",
  "req_hash": "sha256:...",
  "resp_hash": "sha256:...",
  "status": 200
}
```

It is signed with ECDSA on curve P-384 (`ES384`). The public keys are published
at `https://geoclear.io/.well-known/jwks.json`.

## What it attests to

A valid receipt is evidence of **what GeoClear returned** and **when**. It is
not evidence that the data in the response is correct, and it stays valid if
that data later changes: it records what GeoClear returned at the time.

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

- **Go:** planned
- **Rust:** planned
- **Ruby:** nice-to-have
- **Java:** nice-to-have

File an issue first to discuss substantive changes.

## License

MIT (see [LICENSE](LICENSE)). Published as `@geoclear/verify-receipt` on npm.
See https://www.npmjs.com/package/@geoclear/verify-receipt.

---

## Evidence Bundles

`verifyBundle()` verifies an **Evidence Bundle**: a ZIP that carries the
receipt JWS and may include an ML-DSA-87 signature layer as sibling files. When
it does, the signed JWS payload's `pqc_pubkey_fingerprint` claim names the
layer's public key, and `verifyBundle` checks that the ML-DSA-87 signature is
over exactly the receipt's JWS signing input, the bytes the ECDSA signature
covers. The ML-DSA-87 key is trusted only through that ECDSA-signed
fingerprint: the layer adds no protection if the ECDSA signature alone could be
forged.

### CLI usage

```
npm install -g @geoclear/verify-receipt

# With a JWKS you obtained from GeoClear (works offline):
geoclear-verify-receipt ./evidence-bundle.zip --jwks ./geoclear-jwks.json

# Against the live JWKS:
geoclear-verify-receipt ./evidence-bundle.zip

# A single receipt header (add --request-body req.json for a request with a body):
geoclear-verify-receipt --jws "$(cat receipt.jws)" --method GET --path /api/health \
                        --response-body resp.json --jwks ./geoclear-jwks.json
```

Other options: `--jwks-url <url>` (https only), `--offline` (refuse rather than
fetch when no `--jwks` is given), `--expected-env <env>|any`. Unknown options,
a missing option value, a second bundle and two trust sources are usage errors
(exit 5). Values printed from a bundle, a JWKS or an error message show control
characters, bidirectional-text controls, zero-width characters, line and
paragraph separators and the byte order mark as `\xNN` / `\uNNNN` escapes.

The CLI prints one line per check that passed, then `Bundle VALID.`, the mode,
the issuer and the issue time. It prints no claim that describes a decision.

### Exit codes and tamper detection

| Exit | Meaning | Error code |
|---|---|---|
| 0 | bundle or receipt valid | |
| 1 | the receipt's signature does not verify with the trusted key (the receipt was modified, or signed by another key); for a single receipt, also a request or response that differs from what it covers | `ECDSA_VERIFY_FAILED`, `REQUEST_HASH_MISMATCH`, `RESPONSE_HASH_MISMATCH` |
| 2 | the ML-DSA-87 public key in the bundle is not the one the signed receipt names (key swap) | `ECDSA_CHAIN_FINGERPRINT_MISMATCH`, `ECDSA_CHAIN_ANCHOR_MISSING` |
| 3 | the ML-DSA-87 signature does not verify, is not over the receipt's signed bytes, or the bundle names another ML-DSA algorithm | `ML_DSA_SIGNATURE_INVALID`, `ML_DSA_SIGNED_INPUT_MISMATCH`, `ML_DSA_VERIFY_THREW`, `ML_DSA_ALG_UNSUPPORTED` |
| 4 | the bundle, or a `--request-body` / `--response-body` file, is missing or cannot be read | |
| 5 | CLI usage error | |
| 6 | trust refused: no independent trust source (`--offline` without `--jwks`), key not trusted, key metadata missing, a malformed receipt header, or the receipt's claims disagree with the key | `TRUST_SOURCE_REQUIRED`, `KID_NOT_TRUSTED`, `KEY_*`, `RECEIPT_MALFORMED`, `CLAIM_*`, `ENDPOINT_*`, `BUNDLE_*` |
| 7 | trust source unreadable: the `--jwks` file is missing, unreadable or not a JWKS, or the live JWKS cannot be fetched or is not https | `TRUST_SOURCE_UNREADABLE`, `TRUST_SOURCE_INVALID`, `TRUST_SOURCE_UNAVAILABLE`, `TRUST_SOURCE_NOT_HTTPS` |

Three ways to see tamper detection on a bundle you hold:

- **Modified receipt.** Change one character of the signature segment of
  `receipt/receipt.jws`, re-zip, run: exit 1.
- **Swapped ML-DSA-87 key.** Replace `signature/mldsa-pubkey.json` with another
  bundle's: the receipt still verifies, the anchor does not: exit 2.
- **Modified ML-DSA-87 signature.** Flip a byte in `signature/mldsa.sig`: the
  receipt and the anchor still verify, the ML-DSA-87 signature does not: exit 3.
- **ML-DSA-87 signature over other bytes.** Replace
  `signature/mldsa-signed-input.bytes` (and a matching signature) with other
  bytes: exit 3 (`ML_DSA_SIGNED_INPUT_MISMATCH`).

### Bundle layout

```
evidence-bundle.zip
├── README.md
├── receipt/
│   └── receipt.jws              ← the signed receipt (JWS)
├── payload/
│   ├── canonical-payload.bytes  ← response body, canonicalized
│   ├── canonical-payload.json
│   └── canonical-payload.sha256
├── signature/                   ← only with an ML-DSA-87 layer
│   ├── mldsa.sig                ← raw 4627-byte ML-DSA-87 signature
│   ├── mldsa-pubkey.json        ← public key descriptor (2592-byte key, base64)
│   └── mldsa-signed-input.bytes ← must be the receipt's JWS signing input
├── trust/
│   ├── jwks-snapshot.json       ← bundle content; never a trust source
│   ├── key-fingerprint.txt
│   └── trust-anchor.txt         ← reported; its key id must be the receipt's
├── verify/
│   └── offline-verifier.html
└── audit/
    └── verification-report.json ← informational; not used to verify (a malformed one is ignored)
```

A bundle without the `signature/` files is verified in `ecdsa-only` mode.

### Programmatic API

```js
const { verifyBundle } = require('@geoclear/verify-receipt');
const fs = require('node:fs');

const zip = fs.readFileSync('./evidence-bundle.zip');
const result = await verifyBundle({ zip, jwksJson: savedJwks });   // a trust source is required (see v2.0.0 above)

if (result.mode === 'hybrid-ecdsa-p384-mldsa-87') {
  console.log('ML-DSA-87 layer verified:', result.pqc_overlay);
}
```

On failure, `verifyBundle()` throws an Error with a specific `.code` and
`.step` (`ECDSA_VERIFY_FAILED`, `ECDSA_CHAIN_FINGERPRINT_MISMATCH`,
`ML_DSA_SIGNATURE_INVALID`, `ML_DSA_SIGNED_INPUT_MISMATCH`, `ML_DSA_VERIFY_THREW`, and the trust codes in
[CHANGELOG.md](CHANGELOG.md)) so callers can tell the failure modes apart.
