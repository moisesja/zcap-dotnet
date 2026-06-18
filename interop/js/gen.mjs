/*!
 * gen.mjs -- generate a root + single-level delegated capability using the REAL
 * @digitalbazaar/zcap v9 reference library, and write them to the shared
 * interop vectors directory.
 *
 *   - root controller key: 32 bytes all 0x01 (deterministic)
 *   - delegate key:        32 bytes all 0x02 (deterministic)
 *   - invocationTarget:    https://example.com/api/items
 *   - delegated allowedAction: ["read"], expires: now + 30 days
 *   - the delegation proof is signed by the ROOT controller key (the root's
 *     controller is the party authorized to delegate the root capability).
 *
 * Output:
 *   ../vectors/js-root.json
 *   ../vectors/js-delegated.json
 *
 * Run with:  node gen.mjs
 */
import {writeFileSync, mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

import jsigs from 'jsonld-signatures';
import {CapabilityDelegation, createRootCapability}
  from '@digitalbazaar/zcap';
import {Ed25519Signature2020}
  from '@digitalbazaar/ed25519-signature-2020';

import {
  didKeyFromSeed,
  makeDocumentLoader,
  ZCAP_CONTEXT_URL,
  ED25519_2020_CONTEXT_URL
} from './lib.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, '..', 'vectors');

const INVOCATION_TARGET = 'https://example.com/api/items';

// Deterministic seeds: 0x01 * 32 (root controller), 0x02 * 32 (delegate).
const ROOT_SEED = new Uint8Array(32).fill(0x01);
const DELEGATE_SEED = new Uint8Array(32).fill(0x02);

/**
 * Format a Date as a `YYYY-MM-DDTHH:mm:ssZ` UTC string (seconds precision, no
 * milliseconds) -- matches the shape the .NET side emits.
 *
 * @param {Date} date - The date to format.
 * @returns {string} The formatted timestamp.
 */
function toZcapTimestamp(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

async function main() {
  // ----- deterministic identities -----
  const rootController = await didKeyFromSeed(ROOT_SEED);
  const delegate = await didKeyFromSeed(DELEGATE_SEED);

  console.log('root controller did:key  :', rootController.did);
  console.log('root verificationMethod  :', rootController.verificationMethod);
  console.log('delegate     did:key     :', delegate.did);
  console.log('delegate verificationMethod:', delegate.verificationMethod);

  // ----- root capability -----
  // createRootCapability yields:
  //   { '@context': 'https://w3id.org/zcap/v1',
  //     id: 'urn:zcap:root:' + encodeURIComponent(invocationTarget),
  //     controller, invocationTarget }
  const root = createRootCapability({
    controller: rootController.did,
    invocationTarget: INVOCATION_TARGET
  });

  // ----- delegated capability (unsigned) -----
  // Single-level delegation: the parent is the root, so capabilityChain is
  // exactly [root.id] and the delegation proof is signed by the ROOT controller.
  const now = new Date();
  const expires = toZcapTimestamp(
    new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000));

  const delegatedDoc = {
    '@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
    id: `urn:uuid:${crypto.randomUUID()}`,
    controller: delegate.did,
    invocationTarget: INVOCATION_TARGET,
    allowedAction: ['read'],
    expires,
    parentCapability: root.id
  };

  // ----- sign the delegation proof with the ROOT controller key -----
  // The documentLoader must serve the root (by id), the contexts, and the
  // did:key controllers. `purpose` carries `parentCapability: root.id` so the
  // library auto-computes `capabilityChain = [root.id]` and stamps
  // `proofPurpose: 'capabilityDelegation'`.
  const documentLoader = makeDocumentLoader({roots: [root]});

  const delegated = await jsigs.sign(delegatedDoc, {
    suite: new Ed25519Signature2020({
      key: rootController.key,
      // pin a seconds-precision `created` so the wire shape matches .NET
      date: toZcapTimestamp(now)
    }),
    purpose: new CapabilityDelegation({parentCapability: root.id}),
    documentLoader
  });

  // ----- write vectors -----
  mkdirSync(VECTORS_DIR, {recursive: true});
  const rootPath = join(VECTORS_DIR, 'js-root.json');
  const delegatedPath = join(VECTORS_DIR, 'js-delegated.json');
  writeFileSync(rootPath, JSON.stringify(root, null, 2) + '\n');
  writeFileSync(delegatedPath, JSON.stringify(delegated, null, 2) + '\n');

  console.log('\nwrote', rootPath);
  console.log('wrote', delegatedPath);
  console.log('\nroot.id      :', root.id);
  console.log('delegated.id :', delegated.id);
  console.log('proof.verificationMethod:', delegated.proof.verificationMethod);
  console.log('proof.capabilityChain   :',
    JSON.stringify(delegated.proof.capabilityChain));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
