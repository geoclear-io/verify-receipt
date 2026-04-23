# @geoclear/verify-receipt — changelog

## [1.0.0] — 2026-04-23

Initial release. Verify a GeoClear signed decision receipt (JWS over ECDSA P-384) offline.

- `verifyGeoClearReceipt({ receipt, method, path, requestBody, responseBody })` — primary API
- Automatic JWKS fetch + caching from `https://geoclear.io/.well-known/jwks.json`
- Verifies JWS signature + canonical (RFC 8785) `req_hash` + `resp_hash`
- `canonicalize` + `sha256Hex` helpers exposed for custom verification flows

Public key as of this release: `kid: "geoclear-response-signing-2026"` · algorithm `ES384` · curve `P-384`.

Key rotation: annual, 30-day overlap window; all live keys remain published at
`/.well-known/jwks.json`. No client change needed across rotations.
