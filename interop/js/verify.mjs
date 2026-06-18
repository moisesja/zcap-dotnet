/*!
 * verify.mjs <delegatedFile> <rootFile>
 *
 * Loads a delegated capability + its root capability from JSON files and
 * verifies the *capability delegation* proof using the REAL @digitalbazaar/zcap
 * v9 reference library. Prints PASS / FAIL.
 *
 *   - exit code 0  => verified  (prints PASS)
 *   - exit code 1  => not verified or error (prints FAIL + full error chain)
 *
 * The delegated capability is verified purely from its JSON + did:key
 * resolution; the root is registered in the documentLoader by its `id`.
 *
 * Example:
 *   node verify.mjs ../vectors/js-delegated.json ../vectors/js-root.json
 */
import {readFileSync} from 'node:fs';

import {verifyDelegation} from './lib.mjs';

/**
 * Recursively flatten the nested error chain jsonld-signatures produces.
 * jsigs wraps failures and nests sub-errors under `error.errors` (and
 * sometimes `error.cause`), so we walk both to surface the real reason.
 *
 * @param {Error} error - The top-level error from the verify result.
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
  const [, , delegatedFile, rootFile] = process.argv;
  if(!delegatedFile || !rootFile) {
    console.error('Usage: node verify.mjs <delegatedFile> <rootFile>');
    process.exit(1);
  }

  const delegated = loadJson(delegatedFile);
  const root = loadJson(rootFile);

  const result = await verifyDelegation({delegated, root});

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
