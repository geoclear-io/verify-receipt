# @geoclear/verify-receipt — changelog

## [1.1.1] — 2026-05-12

Metadata-only release. Repository moved from `shaileshjgd/geoclear-verify-receipt` to `geoclear-io/verify-receipt` (org-namespaced under the canonical GeoClear public-protocol-artifact org). GitHub auto-redirects from the old URL; no code changes; no API changes. Existing v1.1.0 callers are unaffected — upgrading to v1.1.1 is optional and metadata-only.

## [1.1.0] — 2026-05-11

Adds support for fact-witness Nitro Enclave receipts and hardware-attested
identity gates.

### New

- **`verifyEnclaveReceipt({ receipt, canonicalPayload, jwks?, jwksUrl?, publicKeyJwk?, ...gates })`** — verify a sovereign-decision-environment receipt produced by the fact-witness enclave pipeline. The shape carries `resp_hash` over a JCS-canonical payload plus four runtime-identity claims:
  - `signing_account_id` — AWS account that owns the KMS signing key
  - `signing_region` — AWS region of the signing key
  - `signing_instance_id` — EC2 instance ID of the enclave's parent host
  - `pcr0` — SHA-384 hex of the running `.eif` binary

- **Strict optional gates (apply to BOTH `verifyGeoClearReceipt` and `verifyEnclaveReceipt`):**
  - `expectedAccountId` — compared to claim `signing_account_id`
  - `expectedRegion` — compared to claim `signing_region`
  - `expectedInstanceId` — compared to claim `signing_instance_id`
  - `expectedPcr0` — compared to claim `pcr0`

  When a gate is provided, the library performs an **exact-match** comparison and throws a fatal `Error` on mismatch or missing claim. When omitted, the gate is skipped and the claim flows through informationally.

- **Offline operation** — `verifyEnclaveReceipt` accepts `jwks: { keys: [...] }` (local JWKS object) or `publicKeyJwk: { ... }` (single JWK) so the verifier never needs network access. Useful for air-gapped audit reviews.

- **`payload_size` defense-in-depth** — if the receipt carries a `payload_size` claim, the library asserts it matches the caller's canonical-payload byte length.

### Backwards compatible

The v1.0.0 `verifyGeoClearReceipt` API is unchanged. Existing callers continue to work; the four optional gate parameters are additive.

### Public key context

The fact-witness enclave path uses `kid: "geoclear-response-signing-attested-2026"` for the Maven-Mirror sovereign-decision-environment. The response-signing middleware continues to use `kid: "geoclear-response-signing-2026"`. Both keys are published at `/.well-known/jwks.json`.

---

## [1.0.0] — 2026-04-23

Initial release. Verify a GeoClear signed decision receipt (JWS over ECDSA P-384) offline.

- `verifyGeoClearReceipt({ receipt, method, path, requestBody, responseBody })` — primary API
- Automatic JWKS fetch + caching from `https://geoclear.io/.well-known/jwks.json`
- Verifies JWS signature + canonical (RFC 8785) `req_hash` + `resp_hash`
- `canonicalize` + `sha256Hex` helpers exposed for custom verification flows

Public key as of this release: `kid: "geoclear-response-signing-2026"` · algorithm `ES384` · curve `P-384`.

Key rotation: annual, 30-day overlap window; all live keys remain published at
`/.well-known/jwks.json`. No client change needed across rotations.
