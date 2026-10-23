# Changelog

## 2.0.0 - security fix, breaking

A bundle could vouch for itself. In 1.x, `verifyBundle({ zip })` verified a
bundle's receipt with the key in the bundle's own `trust/jwks-snapshot.json`.
A bundle signed with any key, carrying that key in its snapshot under the
production key id, returned `valid: true`, and the CLI printed `Bundle VALID`.
`trust/trust-anchor.txt` was read and never checked. Neither verify function
checked the key metadata the published JWKS carries (`key_purpose`,
`environment`, `status`, `valid_endpoints`), so a receipt signed by a demo key
passed as production evidence.

**Do not use 1.x to verify GeoClear evidence.** 1.2.0, 1.2.1 and 1.4.0 accept
a forged bundle as valid, and every 1.x version accepts a receipt signed by any
key in the published JWKS, demo keys included, as production evidence. All 1.x
versions are being deprecated on npm with this release.

### Scope: signatures and integrity, never decisions

This package verifies signatures, integrity and trust. It does not evaluate,
verify or act on decisions, authorizations, denials or policy results. Both
verify functions return the signed payload as signed, including any such
claims, without reading them: whatever the claims say, they accept or refuse
the receipt the same way, and the CLI prints the same lines and exits with the
same code (the tests in the source repository compare allow with deny; they
are not shipped in this package).

- **Removed: the CLI's decision rendering.** 1.4.0 printed a block
  for a receipt that described a decision: a proceed line for an authorization, a
  hold line for a denial, the policy result, the decision packet hash and the
  attribute commitments. 2.0.0 prints none of it.
- **Removed: `replayPolicyBundle(bundle)`.** 1.4.0 recomputed a commitment
  over the `policy_bundle` claim's content and returned a verdict together with
  the issuer's own result. It is not exported by 2.0.0; calling it is a
  `TypeError`.
- **Kept: `validatePolicyBundle(bundle)`, a shape check only.** It checks that
  each field of the optional, informational `policy_bundle` claim has the
  expected type and size. It never yields, verifies or interprets a decision,
  the verify functions do not call it, and it never changes their result.

### Changed (breaking)

- **A key is trusted only from an independent source.** There is exactly one
  source per call, with no fallback between them:
  - `jwksJson`: a JWKS you trust, as a string or an object;
  - `jwksUrl`: a JWKS fetched live over https, default
    `https://geoclear.io/.well-known/jwks.json`. Any other scheme, and a
    redirect that ends at a non-https URL, is refused
    (`TRUST_SOURCE_NOT_HTTPS`). The live JWKS is cached for five minutes, per
    URL and per `fetchImpl`.

  A bundle's own `trust/jwks-snapshot.json` is never a trust source. With
  `offline: true` and no `jwksJson`, `verifyBundle` and `verifyGeoClearReceipt`
  refuse (`TRUST_SOURCE_REQUIRED`). A supplied JWKS without the receipt's kid
  is refused (`KID_NOT_TRUSTED`). It never falls back to fetching remotely or
  to the snapshot. An empty or malformed `jwksJson` is refused
  (`TRUST_SOURCE_INVALID`), not treated as absent.
- **Key metadata is enforced.**
  - The key must carry `key_purpose`, `environment`, `status` and a non-empty
    `valid_endpoints` (`KEY_METADATA_MISSING`).
  - `status` must be `active` (`KEY_NOT_ACTIVE`).
  - It must be an ES384 P-384 key (`KEY_TYPE_INVALID`).
- **The signature algorithms are fixed.** The JWS header must say `ES384`;
  `none`, `HS256` and any other algorithm are refused before a key is used
  (`RECEIPT_MALFORMED`). A bundle's ML-DSA descriptor must declare `ML-DSA-87`,
  and a signed `pqc_alg` claim, when present, must agree
  (`ML_DSA_ALG_UNSUPPORTED`, step 2); the result reports the algorithm that was
  verified, never the one the bundle names.
- **The ML-DSA-87 signature must be over the receipt's own signed bytes.**
  `signature/mldsa-signed-input.bytes` must equal the receipt's JWS signing
  input (`BASE64URL(header).BASE64URL(payload)`), or the bundle is refused
  before the signature is checked (`ML_DSA_SIGNED_INPUT_MISMATCH`, step 4).
  1.x (and earlier 2.0.0 drafts) verified the ML-DSA-87 signature over
  whatever bytes the bundle supplied. The ML-DSA-87 key is trusted only through the fingerprint
  the ECDSA-signed receipt carries, so the layer adds no protection if the
  ECDSA signature alone could be forged.
- **`audit/verification-report.json` is informational.** It is never used to
  verify, and a malformed one no longer fails an otherwise valid bundle
  (`parseBundle` reports it as `null`).
- **The expected environment defaults to `production`.** The key's
  environment must match (`KEY_ENVIRONMENT_MISMATCH`). For production its
  `key_purpose` must be the production evidence purpose the published JWKS
  states for the production key (`KEY_PURPOSE_MISMATCH`; the error names the
  expected value). Pass `expectedEnv: null` to accept a key of any
  environment; the claims below still bind the receipt to that key's domain.
- **The receipt's own claims are always required and must agree with the key,**
  whatever `expectedEnv` is:
  - `env` must be present (`CLAIM_ENV_MISSING`) and equal the key's
    environment (`CLAIM_ENV_MISMATCH`);
  - `endpoint` must be present (`CLAIM_ENDPOINT_MISSING`) and be one the key's
    `valid_endpoints` covers (`ENDPOINT_NOT_VALID_FOR_KEY`);
  - for `verifyGeoClearReceipt`, `endpoint` must also equal the path part of
    `path` (`CLAIM_ENDPOINT_MISMATCH`), which must be canonical
    (`PATH_NOT_CANONICAL`). `path` may carry the request's query; `req_hash`
    covers path and query, as the signer computes it.
  - In a bundle the claims are checked last (step 5), after the ML-DSA layer.
- **The bundle is checked against the trusted key.**
  - A snapshot that holds a different key under the kid is refused
    (`BUNDLE_SNAPSHOT_KEY_MISMATCH`).
  - A trust anchor naming another key is refused
    (`BUNDLE_TRUST_ANCHOR_MISMATCH`). The JWKS hash it declares is reported in
    `trust.trust_anchor` and decides nothing.
- **Errors** are `VerifyError` instances with a stable `.code` and a `.step`:
  0 for trust, 1 for the ECDSA receipt and its claims, 2 to 4 for the ML-DSA
  layer, 5 for a bundle receipt's claims. Hash mismatches are now `REQUEST_HASH_MISMATCH` and
  `RESPONSE_HASH_MISMATCH`.
- **`verifyBundle` result** gains `trust`: the source, the kid, the key's
  metadata, the claims, and what the trust anchor declared.
- **`pqc_overlay.standard`, `pqc_overlay.key_lifecycle` and
  `pqc_overlay.security_level` (breaking shape change)** are the values the
  bundle's ML-DSA public key descriptor states, or `null` when it states none.
  1.x filled in defaults the bundle did not carry (`security_level` was 5).
  Either way they describe the bundle and are not verified; `alg` is the
  algorithm that was verified.
- **CLI:**
  - new options `--jwks-url`, `--offline` and `--expected-env <env>|any`;
  - `--jwks` is now exclusive, and one trust source at a time: `--jwks` with
    `--jwks-url`, or `--offline` with `--jwks-url`, is a usage error;
  - exit code 6 is a trust refusal; exit code 7 is a trust source that cannot
    be read (a missing, unreadable or malformed `--jwks` file, or a live JWKS
    that cannot be fetched or is not https), in both modes;
  - unknown options, an option without its value, and a second bundle argument
    are usage errors (exit 5); `--issuer` is removed;
  - values printed from a bundle, a receipt, a JWKS, a file name or an error
    message show as escapes: control characters (C0 including ESC, DEL, C1),
    the bidirectional-text controls (U+061C, U+200E, U+200F, U+202A-U+202E,
    U+2066-U+2069), zero-width characters (U+200B-U+200D, U+2060), the line and
    paragraph separators (U+2028, U+2029) and the byte order mark (U+FEFF), so
    they cannot move the cursor, reorder or hide text, or rewrite the terminal;
  - no decision rendering (above);
  - every output line states a check this version makes, in the order it
    makes them: the receipt signature with the trusted key, the receipt's
    naming of the bundle's ML-DSA-87 public key, the ML-DSA-87 signature, and
    the receipt's claims against the key. 1.x lines that made claims about key
    custody and algorithm profiles, which the verifier cannot check, are gone, and so
    is the line that printed the descriptor's standard and key lifecycle as if
    they had been verified;
  - a bundle, or a `--request-body` / `--response-body` file, that cannot be
    read exits 4 (1.x exited 1 or crashed);
  - with a single receipt, `--offline` without `--jwks` now refuses (exit 6)
    instead of fetching the live JWKS.
- **Package contents:** `LICENSE` (MIT, GeoClear, Inc.) ships again; 1.2.0 to
  1.4.0 had none. The test file no longer ships.
- **Node.js 20.19 or later** (`engines`). 1.x declared Node 18, but the ML-DSA
  dependency (`@noble/post-quantum` 0.6) requires Node 20.19.

### Migration

- If you called `verifyBundle({ zip })` and relied on the bundle's snapshot:
  - pass `jwksJson` with a JWKS you obtained independently (the published
    one, saved when you received the bundle);
  - or let it fetch the live JWKS.

  Offline, `jwksJson` is required.
- If you verify receipts from a non-production environment, or demo receipts,
  pass `expectedEnv` with that environment, or `null`.
- **Receipts without the `env` claim cannot be verified by 2.0.0**, under any
  option. That covers every receipt issued before the claim existed. The
  inline examples in the README check such a receipt's signature and hashes,
  without the key-metadata and claim checks 2.0.0 adds; the 1.x versions are
  deprecated and should not be used for it.
- **V-Dispatch seals** are signed with the demo-environment key
  `geoclear-vdispatch-2026`. A seal that states `env: "demo"` verifies with
  `expectedEnv: 'demo'` (or `null`) and never as production; a seal whose `env`
  claim is not the key's environment is refused (`CLAIM_ENV_MISMATCH`, or
  `KEY_ENVIRONMENT_MISMATCH` by default).
- **No pinned snapshots.** A pre-release draft of this version accepted
  `trustedJwksSha256` (and the CLI `--trusted-jwks-sha256`) to trust a bundle's
  own snapshot by hash. A hash taken from the bundle let a forged bundle verify,
  so it was removed before release: the option is refused
  (`TRUST_PIN_REMOVED`), and the CLI flag exits 5. Offline verification against
  a GeoClear-signed snapshot is a separate, future feature.

## 1.4.0

- v5.1 `policy_bundle` validation and offline replay (`validatePolicyBundle`,
  `replayPolicyBundle`).
