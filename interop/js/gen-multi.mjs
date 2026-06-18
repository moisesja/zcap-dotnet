/*!
 * gen-multi.mjs -- generate a root + a TWO-LEVEL delegation chain using the REAL
 * @digitalbazaar/zcap v9 reference library, and write the vectors out. This
 * exercises the deeper capabilityChain shape [rootId, {immediateParent}] (the
 * embedded-parent rule), a distinct path from the single-level [rootId] chain.
 *
 *   c0 = root controller (seed 0x01), c1 = mid (0x02), c2 = leaf (0x03)
 *   root            -> l1 (signed by c0, chain [root.id])
 *   l1              -> l2 (signed by c1, chain [root.id, {l1 embedded}])
 *
 * Output:  ../vectors/js-multi-root.json, js-multi-l1.json, js-multi-l2.json
 * Run:     node gen-multi.mjs
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

function toZcapTimestamp(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// Delegate `parent` to `controller`, signed by `signerKey`, with the given
// attenuated allowedAction + expiry. Returns the signed delegated capability.
async function delegate({parent, parentRef, controller, signerKey, allowedAction, expires, documentLoader}) {
  const doc = {
    '@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
    id: `urn:uuid:${crypto.randomUUID()}`,
    controller,
    invocationTarget: parent.invocationTarget,
    allowedAction,
    expires,
    parentCapability: parent.id
  };
  return jsigs.sign(doc, {
    suite: new Ed25519Signature2020({key: signerKey}),
    // parentRef is the parent's id (level-1) or the full parent object (deeper),
    // from which the lib computes the capabilityChain.
    purpose: new CapabilityDelegation({parentCapability: parentRef}),
    documentLoader
  });
}

async function main() {
  const c0 = await didKeyFromSeed(new Uint8Array(32).fill(0x01)); // root controller
  const c1 = await didKeyFromSeed(new Uint8Array(32).fill(0x02)); // mid
  const c2 = await didKeyFromSeed(new Uint8Array(32).fill(0x03)); // leaf

  const root = createRootCapability({
    controller: c0.did, invocationTarget: INVOCATION_TARGET
  });
  const documentLoader = makeDocumentLoader({roots: [root]});

  const now = Date.now();
  const exp30 = toZcapTimestamp(new Date(now + 30 * 864e5));
  const exp20 = toZcapTimestamp(new Date(now + 20 * 864e5));

  // level 1: root -> c1 (signed by root controller c0); chain [root.id]
  const l1 = await delegate({
    parent: root, parentRef: root.id, controller: c1.did, signerKey: c0.key,
    allowedAction: ['read', 'write'], expires: exp30, documentLoader
  });

  // level 2: l1 -> c2 (signed by c1); chain [root.id, {l1 embedded}]
  const l2 = await delegate({
    parent: l1, parentRef: l1, controller: c2.did, signerKey: c1.key,
    allowedAction: ['read'], expires: exp20, documentLoader
  });

  mkdirSync(VECTORS_DIR, {recursive: true});
  writeFileSync(join(VECTORS_DIR, 'js-multi-root.json'), JSON.stringify(root, null, 2) + '\n');
  writeFileSync(join(VECTORS_DIR, 'js-multi-l1.json'), JSON.stringify(l1, null, 2) + '\n');
  writeFileSync(join(VECTORS_DIR, 'js-multi-l2.json'), JSON.stringify(l2, null, 2) + '\n');

  console.log('wrote js-multi-{root,l1,l2}.json');
  console.log('l2.proof.capabilityChain length:', l2.proof.capabilityChain.length,
    '(expect 2: [rootId, {l1}])');
}

main().catch(err => { console.error(err); process.exit(1); });
