# Changelog

## 2.0.1 - security fix

2.0.0 was tagged in the public repository on 2026-10-23 but never published to npm; 2.0.1 is the first 2.x release on npm and includes every 2.0.0 change below.

**2.0.1 verifies a bundle only in the ZIP layout GeoClear issues bundles in.** A
bundle that was unpacked and zipped again, or re-packed by another archive
tool, is refused with a `ZIP_*` code whenever the result differs from that
layout. Most tools do differ: they add extra fields, directory entries or
metadata files, or they reorder the archive. Verify the bundle file as you
received it from GeoClear.

### Security

- **adm-zip `^0.6.1`** (was `^0.5.16`, which resolves to 0.5.x only). This
  package reads a bundle with `new AdmZip(bytes)`, `getEntries()`,
  `getEntry(name)` and the synchronous `entry.getData()`. The advisories that
  apply to that use, all fixed in 0.6.1:
  - GHSA-xcpc-8h2w-3j85 (CVE-2026-39244, high): a crafted ZIP that declares a
    huge uncompressed size forces an allocation of up to 4 GB;
  - GHSA-7q85-xj36-vmfc (CVE-2026-77301, high): the output buffer is allocated
    from the declared uncompressed size before the data is checked;
  - GHSA-rcw4-f5rp-g42v (high): an entry that declares an uncompressed size of
    0 bypasses the decompression cap;
  - GHSA-p634-w6r4-rjp2 (medium): with two entries of one name, `getEntry()` and
    extraction resolve the name to different content.

  The other advisories reported against 0.5.x concern extraction to disk
  (GHSA-vwc7-r8mq-g2x9, symbolic links at the destination; GHSA-j5f4-cc29-5x44,
  setuid and setgid bits) or the asynchronous API (GHSA-8238-w5pm-2374,
  GHSA-c6fg-446q-cg94). This package never extracts a bundle and does not use
  the asynchronous API.
- **Every ZIP reader now sees the entries the verifier reads.** adm-zip reads
  only the central directory the end record points at. A ZIP archive can show
  other readers (Info-ZIP `unzip`, `bsdtar`, macOS `ditto`, Python's `zipfile`)
  a different `receipt/receipt.jws` in several ways:
  - a second central directory;
  - data before the archive;
  - a local header naming another file than its central-directory entry;
  - a local entry the central directory does not list;
  - a Unicode Path extra field;
  - a symbolic link.

  An earlier 2.0.1 draft verified the genuine receipt in such bundles while
  those tools extracted a forged one. Before adm-zip parses anything, the raw
  bytes are now checked, and the bundle is refused
  (`ZIP_CONTAINER_NOT_CANONICAL`) unless:
  - **Overall layout:** the archive is exactly its local entries, then the
    central directory, then the end record, with nothing before, between or
    after them;
  - **End record:** it is the last 22 bytes, with no archive comment, one disk
    and no ZIP64;
  - **Local entries:** they start at byte 0, follow one another in
    central-directory order, and the last ends where the central directory
    starts, so no two entries share data;
  - **Headers agree:** each local header repeats its central-directory entry
    (name bytes, flags, method, CRC and both sizes);
  - **No extras:** no entry has an extra field (Unicode path, timestamps, ZIP64
    or any other) or a comment;
  - **Flags:** they are 0 or UTF-8 names (0x0800) only, so there is no
    encryption and no data descriptor;
  - **Version and method:** version needed is at most 2.0, and the method is
    stored or deflate, a stored entry's two sizes being equal;
  - **File type:** each entry is made on MS-DOS or Unix and is a plain regular
    file: no link, directory, device, setuid, setgid or sticky bit, and no
    MS-DOS attribute other than read-only and archive.
- **Only the names a GeoClear bundle contains** (`ZIP_ENTRY_NAME_UNKNOWN`).
  - **The closed set** (exported as `BUNDLE_ENTRY_NAMES`):
    - the 13 entries of the bundle layout in README.md;
    - `trust/key-transparency-manifest.json`,
      `trust/key-transparency-manifest.sig` and `trust/cosign-pubkey.pem`;
    - `transaction/transaction-manifest.json`, `transaction/consent-blob.json`,
      `transaction/compliance-snapshot.json` and
      `transaction/settlement-pairings.json`.

    These are every name GeoClear's bundle writer emits.
  - **Also refused:** directory entries, other files, Windows 8.3 short names
    such as `trust/JWKS-S~1.JSO`, and look-alike names.
- **Duplicate, ambiguous and unsafe names are refused**, before any entry is
  read and whatever the trust source:
  - `ZIP_ENTRY_NAME_DUPLICATE`: two entries have the same name, either exactly
    or after these normalizations:
    - `\` becomes `/`;
    - empty and `.` segments are dropped (a leading `./` or `/`);
    - trailing dots and spaces are dropped from each segment;
    - Unicode normalization (NFC) and case are ignored.

    A person who extracts such a bundle on a case-insensitive file system sees
    one file, which need not be the one the verifier read: with adm-zip 0.5.x,
    the verifier read the copy listed last.
  - `ZIP_ENTRY_NAME_UNSAFE`: an entry name is any of:
    - empty or absolute (a leading `/` or `\`, or a colon, as in a drive letter
      or a Windows stream name);
    - a path with a `..` segment, or a segment of only dots and spaces;
    - holding a control, format, line or paragraph separator, or
      default-ignorable character. That includes the HFS+ ignorables
      U+206A-U+206F, which an HFS+ volume folds into the name without them.

  Error messages show such characters as `<U+XXXX>`.
- **Entry sizes.** Each entry the verifier relies on has its own cap, which
  applies to both the uncompressed and the compressed size; an entry over its
  cap is refused (`ZIP_ENTRY_TOO_LARGE`). The caps are exported as
  `BUNDLE_ENTRY_CAPS`, and `MAX_BUNDLE_ENTRY_BYTES` is the largest, 1 MiB. Each
  is a round value at least 50 times the largest real one seen across
  GeoClear's bundle writers, the committed test bundles and earlier sample
  bundles, and never below 64 KiB. The exception is `signature/mldsa.sig`,
  which is always 4,627 bytes (an ML-DSA-87 signature, FIPS 204) and is capped
  at 64 KiB, about 14 times that:

  | Entry | Cap | Largest seen |
  |---|---|---|
  | `receipt/receipt.jws` | 1 MiB | 947 bytes |
  | `signature/mldsa-signed-input.bytes` | 1 MiB | 817 bytes (the receipt's signing input) |
  | `trust/jwks-snapshot.json` | 256 KiB | 3,205 bytes |
  | `signature/mldsa-pubkey.json` | 256 KiB | 3,901 bytes |
  | `trust/trust-anchor.txt` | 128 KiB | 1,468 bytes |
  | `signature/mldsa.sig` | 64 KiB | always 4,627 bytes |

  The receipt's cap also leaves room for the optional `policy_bundle` claim of
  the receipt schema. None of these entries grows with the response body: the
  receipt carries the body's hash, and the signing input is the receipt's own
  header and payload.
  - **The audit report is read up to 1 MiB, and skipped beyond it.**
    `audit/verification-report.json` is informational and never used to
    verify. GeoClear's bundle writer copies the response body into it twice, so
    it is about 2 to 3.3 times the body; a body above roughly 300 to 500 KB,
    depending on its shape, gives a report over 1 MiB. Such a report is not
    decompressed, `parseBundle` reports `verification_report: null` (as for a
    malformed report), and the bundle verifies on its other entries: the CLI
    prints its usual `[OK]` lines and `Bundle VALID.`. A damaged report within
    1 MiB (one that fails its CRC, cannot be decompressed or is not the size it
    declares) is treated the same way, and is never inflated past the size it
    declares. Neither its size nor damage to it makes a bundle invalid. The
    container and name checks still apply to it.
  - **Size mismatch:** an entry that does not decompress to exactly its
    declared size is refused when it is read (`ZIP_ENTRY_SIZE_MISMATCH`).
    adm-zip stops inflating at the declared size, so a longer stream is cut off.
  - **Damaged data:** an entry that cannot be decompressed (an invalid deflate
    stream) or does not match its CRC is refused when it is read
    (`ZIP_ENTRY_DATA_CORRUPT`). The verifier checks every entry's CRC itself,
    including an empty one, which the ZIP library returns without checking.
    The message names the entry; the ZIP library's own message, which can name
    a different entry, is not passed on.
  - **Total:** reading decompresses at most 3,776 KiB (about 3.7 MiB), the
    sum of the caps.
  - **Memory depends on content.** The verifier parses the receipt's payload
    and three entries (snapshot, report, ML-DSA descriptor) as JSON, so memory
    also depends on what they contain. Peak resident memory of one
    `verifyBundle` call, measured with `/usr/bin/time -l` in a fresh process on
    macOS (arm64):

    | Bundle | Node 20.20.2 | Node 22.22.0 |
    |---|---|---|
    | a GeoClear bundle | 54 MiB | 59 MiB |
    | a valid bundle with every read entry at its cap, deflated | 75 MiB | 80 MiB |
    | the same, stored | 76 MiB | 81 MiB |
    | the same, with the JSON made of empty objects (`{},{},...`), deflated or stored | 158 MiB | 165 MiB |
    | a bundle whose report is a deflate stream of 1 GiB (skipped, never inflated) | 52 MiB | 55 MiB |

    The empty-object shape is the worst shape tried, not a proven ceiling.
  - Entries the verifier does not read are never decompressed and are not
    capped.
- **A bundle without a receipt** (no `receipt/receipt.jws`, or an empty one) is
  refused with `BUNDLE_RECEIPT_MISSING`; 2.0.0 threw an uncoded error.

These refusals carry a `.code` and no `.step`; the CLI exits 4 and prints the
code. Input that is not a ZIP archive, which 2.0.0 refused with adm-zip's own
uncoded error, is now refused with `ZIP_CONTAINER_NOT_CANONICAL`. Everything
else is unchanged.

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
