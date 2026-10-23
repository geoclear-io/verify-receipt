#!/usr/bin/env node
'use strict';

/**
 * @geoclear/verify-receipt: CLI wrapper
 *
 * Usage:
 *   geoclear-verify-receipt <bundle.zip> [trust source] [--expected-env <env>|any]
 *   geoclear-verify-receipt --jws <receipt.jws> --method GET --path /api/health \
 *                           [--request-body req.json] --response-body resp.json [trust source]
 *
 * Trust source (exactly one, default the live JWKS):
 *   --jwks <jwks.json>             a JWKS you trust (used exclusively)
 *   --jwks-url <url>               the live JWKS to fetch, https only (default https://geoclear.io/.well-known/jwks.json)
 *   --offline                      refuse rather than fetch when no --jwks is given
 *
 * There is no pinned-snapshot option: a bundle's own trust/jwks-snapshot.json is
 * never a trust source. --trusted-jwks-sha256 (a pre-release 2.0.0 draft flag) is
 * refused with exit 5. To verify offline, pass --jwks with a JWKS you obtained from
 * GeoClear, not from the bundle. Unknown options, a missing option value and
 * conflicting trust sources are usage errors (exit 5).
 *
 * Output: one [OK] line per check that passed, in the order they run. For a
 * hybrid bundle:
 *   [OK]   Receipt signature (ECDSA P-384) verified with key <kid> from the <source> trust source (environment <env>)
 *   [OK]   The signed receipt names this bundle's ML-DSA-87 public key
 *   [OK]   ML-DSA-87 signature verified over the bytes the receipt signature covers
 *   [OK]   The receipt's env and endpoint claims agree with the key
 * A refusal prints [OK] only for the checks that passed before it, then one
 * [FAIL] line and the library's error message. Every printed value that comes
 * from a bundle, a receipt, a JWKS, a file name or an error message has its
 * control characters (C0, DEL, C1), bidirectional-text controls (U+061C,
 * U+200E, U+200F, U+202A-U+202E, U+2066-U+2069), zero-width characters
 * (U+200B-U+200D, U+2060), line and paragraph separators (U+2028, U+2029) and
 * byte order mark (U+FEFF) shown as \xNN / \uNNNN escapes, so it cannot move
 * the cursor, reorder or hide text, or rewrite the terminal.
 *
 * Exit codes:
 *   0 = bundle/receipt VALID
 *   1 = the receipt signature does not verify with the trusted key; for a single
 *       receipt, also a request or response that differs from what it covers
 *   2 = the signed receipt does not name the bundle's ML-DSA-87 public key
 *   3 = the ML-DSA-87 signature does not verify, is not over the receipt's signed
 *       bytes, or the bundle names another ML-DSA algorithm
 *   4 = the bundle, or a --request-body / --response-body file, is missing or
 *       cannot be read
 *   5 = CLI usage error
 *   6 = trust refused: no independent trust source, key not trusted, key
 *       metadata missing, or the receipt's claims disagree with the key
 *   7 = trust source unreadable: the --jwks file is missing or unreadable or is
 *       not a JWKS, or the live JWKS cannot be fetched or is not https
 */

const fs = require('node:fs');
const path = require('node:path');

const lib = require('./verify');

// Shown as escapes: C0 controls (including ESC), DEL, C1 controls, the Arabic letter mark,
// zero-width characters (U+200B-U+200D, U+2060), the bidirectional marks, embeddings,
// overrides and isolates, the line and paragraph separators, and the byte order mark.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060\u2066-\u2069\ufeff]/g;
function clean(value) {
  return String(value).replace(UNSAFE, (c) => {
    const n = c.charCodeAt(0);
    return n <= 0xff ? `\\x${n.toString(16).padStart(2, '0')}` : `\\u${n.toString(16).padStart(4, '0')}`;
  });
}
const say = (line = '') => console.log(clean(line));
const isoTime = (iat) => { const d = new Date(iat * 1000); return Number.isFinite(d.getTime()) ? d.toISOString() : `unrepresentable (${iat})`; };

const USAGE = [
  'Usage:',
  '  geoclear-verify-receipt <bundle.zip> [--jwks <jwks.json> | --jwks-url <url>] [--offline] [--expected-env <env>|any]',
  '  geoclear-verify-receipt --jws <receipt.jws> --method GET --path /api/health \\',
  '                          [--request-body req.json] --response-body resp.json [--jwks <jwks.json> | --jwks-url <url>] [--offline]',
  '',
  'Modes:',
  '  Evidence Bundle (.zip; ECDSA P-384 receipt, with an ML-DSA-87 signature layer when present):',
  '    geoclear-verify-receipt ./evidence.zip --jwks ./geoclear-jwks.json',
  '  Single receipt header (ECDSA P-384):',
  '    geoclear-verify-receipt --jws "$(cat receipt.jws)" \\',
  '                            --method GET --path /api/health \\',
  '                            --response-body resp.json --jwks ./geoclear-jwks.json',
  '',
].join('\n');

function usage(message) {
  if (message) process.stderr.write(`[FAIL] ${clean(message)}\n\n`);
  process.stderr.write(USAGE);
  process.exit(5);
}

const VALUE_FLAGS = {
  '--bundle': 'bundle', '-b': 'bundle', '--jws': 'jws', '--method': 'method', '--path': 'path',
  '--request-body': 'requestBody', '--response-body': 'responseBody',
  '--jwks': 'jwks', '--jwks-url': 'jwksUrl', '--expected-env': 'expectedEnv',
};
const BOOLEAN_FLAGS = { '--offline': 'offline', '-h': 'help', '--help': 'help' };

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--trusted-jwks-sha256') {
      usage('--trusted-jwks-sha256 is not supported: a bundle\'s own snapshot is never a trust source. '
        + 'Pass --jwks with a JWKS you obtained from GeoClear (not from the bundle), or let the verifier fetch the live JWKS.');
    } else if (Object.prototype.hasOwnProperty.call(VALUE_FLAGS, a)) {
      const key = VALUE_FLAGS[a];
      const value = argv[i + 1];
      if (value === undefined || value === '' || value.startsWith('--')) usage(`${a} needs a value`);
      if (out[key] !== undefined) usage(`${a} is given more than once`);
      out[key] = value;
      i++;
    } else if (Object.prototype.hasOwnProperty.call(BOOLEAN_FLAGS, a)) {
      out[BOOLEAN_FLAGS[a]] = true;
    } else if (a.startsWith('-')) {
      usage(`unknown option ${a}`);
    } else if (out.bundle === undefined) {
      out.bundle = a;
    } else {
      usage(`unexpected argument ${a}`);
    }
  }
  if (out.help) usage();
  if (out.bundle !== undefined && out.jws !== undefined) usage('pass a bundle or --jws, not both');
  if (out.bundle === undefined && out.jws === undefined) usage();
  if (out.jwks !== undefined && out.jwksUrl !== undefined) usage('pass one trust source: --jwks or --jwks-url, not both');
  if (out.offline && out.jwksUrl !== undefined) usage('--offline and --jwks-url contradict each other');
  return out;
}

const TRUST_SOURCE_UNREADABLE = new Set(['TRUST_SOURCE_UNAVAILABLE', 'TRUST_SOURCE_INVALID', 'TRUST_SOURCE_NOT_HTTPS']);

function trustSourceUnreadable(kind, message, code) {
  say('[FAIL] Trust source unreadable');
  say(`       ${message}`);
  say('');
  say(`${kind} NOT VERIFIED. Check the --jwks file or the JWKS URL.`);
  say(`Exit code: 7 (${code})`);
  process.exit(7);
}

function trustRefused(kind, err, code) {
  say('[FAIL] Trust: the key or the receipt is not trusted for this use');
  say(`       ${err.message}`);
  say('');
  say(`${kind} NOT TRUSTED. Pass --jwks with a JWKS you obtained from GeoClear (not from the bundle), or use the live JWKS.`);
  say(`Exit code: 6 (${code})`);
  process.exit(6);
}

function trustOptions(args, kind) {
  const opts = {};
  if (args.jwks !== undefined) {
    try {
      opts.jwksJson = fs.readFileSync(path.resolve(args.jwks), 'utf8');
    } catch (e) {
      trustSourceUnreadable(kind, `cannot read --jwks ${args.jwks} (${e.code || e.message})`, 'TRUST_SOURCE_UNREADABLE');
    }
  }
  if (args.jwksUrl !== undefined) opts.jwksUrl = args.jwksUrl;
  if (args.offline) opts.offline = true;
  if (args.expectedEnv !== undefined) opts.expectedEnv = args.expectedEnv === 'any' ? null : args.expectedEnv;
  return opts;
}

const SIGNATURE_OK = '[OK]   Receipt signature (ECDSA P-384) verified with the trusted key';
const NAMES_KEY_OK = '[OK]   The signed receipt names this bundle\'s ML-DSA-87 public key';

function refuse(lines, verdict, exitCode, code, message) {
  for (const l of lines) say(l);
  say(`       ${message}`);
  say('');
  say(verdict);
  say(`Exit code: ${exitCode} (${code})`);
  process.exit(exitCode);
}

async function runBundleMode(args) {
  const bundlePath = path.resolve(args.bundle);
  let zip;
  try {
    zip = fs.readFileSync(bundlePath);
  } catch (e) {
    process.stderr.write(`[FAIL] bundle not found or unreadable: ${clean(bundlePath)} (${clean(e.code || e.message)})\n`);
    process.exit(4);
  }

  say(`GeoClear Receipt Verifier v${require('./package.json').version}`);
  say(`Bundle: ${bundlePath}`);
  say('');

  // Nothing is reported as passed until verifyBundle returns or throws.
  let result;
  try {
    result = await lib.verifyBundle({ zip, ...trustOptions(args, 'Bundle') });
  } catch (err) {
    const code = err.code || 'UNKNOWN';
    const step = err.step;
    if (TRUST_SOURCE_UNREADABLE.has(code)) trustSourceUnreadable('Bundle', err.message, code);
    if (step === 0 || /^(CLAIM_|ENDPOINT_)/.test(code)) trustRefused('Bundle', err, code);
    // Print [OK] only for the checks that passed before the refusal.
    if (code === 'ML_DSA_ALG_UNSUPPORTED') {
      // Checked after the receipt signature and before the ML-DSA key binding.
      refuse([SIGNATURE_OK, '[FAIL] The ML-DSA layer names an algorithm other than ML-DSA-87; it was not verified'],
        'Bundle INVALID. ML-DSA-87 layer not verified.', 3, code, err.message);
    } else if (step === 3) {
      refuse([SIGNATURE_OK, '[FAIL] The signed receipt does not name this bundle\'s ML-DSA-87 public key'],
        'Bundle INVALID. The ML-DSA-87 public key in the bundle is not the one the receipt names.', 2, code, err.message);
    } else if (code === 'ML_DSA_SIGNED_INPUT_MISMATCH') {
      refuse([SIGNATURE_OK, NAMES_KEY_OK, '[FAIL] The ML-DSA-87 signature is not over the receipt\'s signed bytes'],
        'Bundle INVALID. ML-DSA-87 layer verification failed.', 3, code, err.message);
    } else if (step === 4) {
      refuse([SIGNATURE_OK, NAMES_KEY_OK, '[FAIL] ML-DSA-87 signature does not verify'],
        'Bundle INVALID. ML-DSA-87 layer verification failed.', 3, code, err.message);
    } else if (step === 1) {
      refuse(['[FAIL] Receipt signature (ECDSA P-384) does not verify with the trusted key'],
        'Bundle INVALID. The receipt was modified, or signed by another key.', 1, code, err.message);
    } else {
      // No verification step: the bundle itself could not be read.
      refuse(['[FAIL] The bundle could not be read'], 'Bundle INVALID.', 4, code, err.message);
    }
  }

  // Valid: one line per check that passed, in the order they ran.
  const payload = result.jws_payload || {};
  say(`[OK]   Receipt signature (ECDSA P-384) verified with key ${result.trust.kid} from the ${result.trust.source} trust source (environment ${result.trust.key.environment})`);
  if (result.pqc_overlay) {
    say(NAMES_KEY_OK);
    say('[OK]   ML-DSA-87 signature verified over the bytes the receipt signature covers');
  }
  say('[OK]   The receipt\'s env and endpoint claims agree with the key');
  say('');
  say(`Bundle VALID. Verification completed in ${result.ms}ms.`);
  say(`Mode: ${result.mode}`);
  if (payload.iss) say(`Issuer: ${payload.iss}`);
  if (typeof payload.iat === 'number') say(`Issued at: ${isoTime(payload.iat)}`);
  if (result.pqc_overlay) {
    say(`ML-DSA-87 public key fingerprint: sha384:${result.pqc_overlay.pubkey_fingerprint_sha384.slice(0, 32)}...`);
  }

  // v2.0.0: the CLI reports signature, integrity and trust only. It prints no
  // claim that describes a decision, policy or outcome, and its output and exit
  // code never depend on one.

  process.exit(0);
}

function readJsonFile(flag, file) {
  try {
    return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
  } catch (e) {
    process.stderr.write(`[FAIL] cannot read ${flag} ${clean(file)} (${clean(e.code || e.message)})\n`);
    process.exit(4);
  }
}

async function runReceiptMode(args) {
  // A single receipt (the response header) for the request and response it covers.
  const missing = ['jws', 'method', 'path', 'responseBody'].filter((k) => args[k] === undefined);
  if (missing.length) usage(`missing ${missing.map((k) => `--${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`).join(', ')}`);
  const requestBody = args.requestBody !== undefined ? readJsonFile('--request-body', args.requestBody) : null;
  const responseBody = readJsonFile('--response-body', args.responseBody);
  let payload;
  try {
    payload = await lib.verifyGeoClearReceipt({
      receipt: args.jws,
      method: args.method,
      path: args.path,
      requestBody,
      responseBody,
      ...trustOptions(args, 'Receipt'),
    });
  } catch (err) {
    const code = err.code || 'UNKNOWN';
    if (TRUST_SOURCE_UNREADABLE.has(code)) trustSourceUnreadable('Receipt', err.message, code);
    if (err.step === 0 || /^(CLAIM_|ENDPOINT_)/.test(code)) trustRefused('Receipt', err, code);
    if (code === 'REQUEST_HASH_MISMATCH' || code === 'RESPONSE_HASH_MISMATCH') {
      // Checked after the signature and the claims.
      refuse([SIGNATURE_OK, '[OK]   The receipt\'s env and endpoint claims agree with the key and the path',
        '[FAIL] The request or response differs from what the receipt covers'],
      'Receipt INVALID. The request or response is not the one the receipt was issued for.', 1, code, err.message);
    }
    refuse(['[FAIL] Receipt signature (ECDSA P-384) does not verify with the trusted key'],
      'Receipt INVALID. The receipt was modified, or signed by another key.', 1, code, err.message);
  }
  const { kid } = require('jose').decodeProtectedHeader(args.jws);
  say(`[OK]   Receipt signature (ECDSA P-384) verified with key ${kid} from the ${args.jwks !== undefined ? 'supplied' : 'live'} trust source (environment ${payload.env})`);
  say('[OK]   The receipt\'s env and endpoint claims agree with the key and the path');
  say('[OK]   Request and response hashes match the receipt');
  say('');
  say('Receipt VALID.');
  say(`Issuer: ${payload.iss}`);
  if (typeof payload.iat === 'number') say(`Issued at: ${isoTime(payload.iat)}`);
  process.exit(0);
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.bundle !== undefined) await runBundleMode(args);
  else await runReceiptMode(args);
})();
