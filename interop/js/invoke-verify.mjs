/*!
 * invoke-verify.mjs <securedDocFile> <rootFile> [expectedAction] [expectedTarget]
 *
 * Loads a secured application document (carrying a `capabilityInvocation` proof)
 * plus the root capability it ultimately authorizes, and verifies the
 * invocation using the REAL @digitalbazaar/zcap v9 reference library. Prints
 * PASS / FAIL.
 *
 *   - exit code 0  => verified  (prints PASS)
 *   - exit code 1  => not verified or error (prints FAIL + full error chain)
 *
 * The root id used as `expectedRootCapability` is taken from the root file's
 * `id`. `expectedAction` defaults to "read" and `expectedTarget` defaults to
 * "https://example.com/api/items" (the interop defaults) if not supplied.
 *
 * Examples:
 *   # root invocation (root file IS the secured doc's root)
 *   node invoke-verify.mjs ../vectors/js-invocation-root.json \
 *     ../vectors/js-invocation-root.json read https://example.com/api/items
 *
 *   # delegated invocation (root is a separate file)
 *   node invoke-verify.mjs ../vectors/js-invocation-delegated.json \
 *     ../vectors/js-invocation-delegated-root.json
 */
import {readFileSync} from 'node:fs';

import {verifyInvocation} from './lib.mjs';

const DEFAULT_ACTION = 'read';
const DEFAULT_TARGET = 'https://example.com/api/items';

/**
 * Recursively flatten the nested error chain jsonld-signatures produces.
 * jsigs wraps failures and nests sub-errors under `error.errors` (and
 * sometimes `error.cause`), so we walk both to surface the real reason.
 *
 * @param {Error} error - The top-level error from the verify result.
 * @param {number} [depth] - Current recursion depth (guards against cycles).
 * @returns {object} A plain, JSON-serializable error tree.
 */
function flattenError(error, depth = 0) {
  if(!error || depth > 10) {
    return error ? String(error) : null;
  }
  const out = {
    name: error.name,
    message: error.message
  };
  if(error.details !== undefined) {
    out.details = error.details;
  }
  // jsigs nests an array of sub-errors here
  if(Array.isArray(error.errors) && error.errors.length > 0) {
    out.errors = error.errors.map(e => flattenError(e, depth + 1));
  }
  // standard Error cause chaining
  if(error.cause) {
    out.cause = flattenError(error.cause, depth + 1);
  }
  return out;
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

async function main() {
  const [, , securedDocFile, rootFile, actionArg, targetArg] = process.argv;
  if(!securedDocFile || !rootFile) {
    console.error(
      'Usage: node invoke-verify.mjs <securedDocFile> <rootFile> ' +
      '[expectedAction] [expectedTarget]');
    process.exit(1);
  }

  const securedDocument = loadJson(securedDocFile);
  const root = loadJson(rootFile);

  const expectedAction = actionArg || DEFAULT_ACTION;
  const expectedTarget = targetArg || DEFAULT_TARGET;

  const result = await verifyInvocation({
    securedDocument,
    expectedAction,
    expectedTarget,
    // the chain's root MUST match this id; the documentLoader serves it by id
    expectedRootCapability: root.id,
    root
  });

  if(result.verified) {
    console.log('PASS');
    process.exit(0);
  }

  console.log('FAIL');
  console.log(JSON.stringify(flattenError(result.error), null, 2));
  process.exit(1);
}

main().catch(err => {
  console.log('FAIL');
  console.log(JSON.stringify(flattenError(err), null, 2));
  process.exit(1);
});
