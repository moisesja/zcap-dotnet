/*!
 * invoke-gen.mjs -- generate Data Integrity `capabilityInvocation` (Path A)
 * vectors using the REAL @digitalbazaar/zcap v9 reference library, and write
 * them to the shared interop vectors directory.
 *
 * Produces two flavours of invocation:
 *
 *   1. ROOT invocation (`js-invocation-root.json`)
 *      - The secured document is a minimal application document.
 *      - The proof's `capability` is the ROOT id STRING
 *        (`urn:zcap:root:${encodeURIComponent(target)}`).
 *      - Signed by the ROOT controller key (seed 0x01).
 *
 *   2. DELEGATED invocation (`js-invocation-delegated.json` + its root in
 *      `js-invocation-delegated-root.json`)
 *      - First delegate root -> delegate (signed by the root controller), then
 *        invoke with the proof's `capability` set to the FULL EMBEDDED delegated
 *        zcap object.
 *      - Signed by the DELEGATE key (seed 0x02).
 *      - The matching root is written separately so the verifier can resolve
 *        the chain (the delegated zcap's `capabilityChain` references the root
 *        by id only).
 *
 * Shared parameters (deterministic so the .NET side can match byte-for-byte):
 *   - root controller key:   32 bytes all 0x01
 *   - delegate key:          32 bytes all 0x02
 *   - invocationTarget:      https://example.com/api/items
 *   - capabilityAction:      read
 *   - `created`:             seconds precision, UTC (no milliseconds)
 *
 * Run with:  node invoke-gen.mjs
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
  signInvocation,
  ZCAP_CONTEXT_URL,
  ED25519_2020_CONTEXT_URL
} from './lib.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, '..', 'vectors');

const INVOCATION_TARGET = 'https://example.com/api/items';
const CAPABILITY_ACTION = 'read';

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

// A deterministic application-document id + type so the body hashes the same
// every run (the .NET side must reproduce this exactly). The `type` is an
// absolute IRI -- it does not need to be a context-defined term, it just has to
// make the body expand to a non-empty RDF dataset (see below).
const APP_DOC_ID = 'urn:uuid:00000000-0000-0000-0000-000000000001';
const APP_DOC_TYPE = 'https://example.com/zcap-interop/vocab#InvocationRequest';

/**
 * Build the minimal application document the .NET side must reproduce.
 *
 * The body's `@context` carries the two entries the verifier needs (see
 * lib.mjs):
 *   - the zcap context, so the verifier's `checkProofContext` is satisfied
 *     (jsigs derives the proof's effective `@context` from the document's), and
 *   - the ed25519-2020 suite context, so the Ed25519Signature2020 suite's
 *     `matchProof` accepts the document.
 *
 * It also carries an `id` (`@id`) and a `type` (`@type`). These are REQUIRED:
 * the suite canonicalizes the document with JSON-LD safe mode, which REJECTS a
 * body that expands to an empty RDF dataset ("Dropping empty object"). A bare
 * `{"@context": [...]}` (or an object with only an `id`) expands to nothing, so
 * we add a `type` to emit at least one triple
 * (`<id> rdf:type <APP_DOC_TYPE>`). The invocation parameters themselves still
 * live ENTIRELY in the proof -- the body says nothing about the capability.
 *
 * @returns {object} A fresh minimal application document.
 */
function makeApplicationDocument() {
  return {
    '@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
    id: APP_DOC_ID,
    type: APP_DOC_TYPE
  };
}

async function main() {
  // ----- deterministic identities -----
  const rootController = await didKeyFromSeed(ROOT_SEED);
  const delegate = await didKeyFromSeed(DELEGATE_SEED);

  console.log('root controller did:key    :', rootController.did);
  console.log('root verificationMethod    :', rootController.verificationMethod);
  console.log('delegate     did:key       :', delegate.did);
  console.log('delegate verificationMethod:', delegate.verificationMethod);

  // pin a single seconds-precision `now` so both vectors are deterministic
  const now = new Date();
  const created = toZcapTimestamp(now);

  // ----- root capability (shared by both vectors) -----
  const root = createRootCapability({
    controller: rootController.did,
    invocationTarget: INVOCATION_TARGET
  });

  mkdirSync(VECTORS_DIR, {recursive: true});

  // =========================================================================
  // 1. ROOT invocation -- proof.capability is the root id STRING.
  // =========================================================================
  const rootInvocation = await signInvocation({
    applicationDocument: makeApplicationDocument(),
    // ROOT capabilities MUST be referenced as a string (their id)
    capability: root.id,
    capabilityAction: CAPABILITY_ACTION,
    invocationTarget: INVOCATION_TARGET,
    key: rootController.key,
    created,
    // documentLoader must serve the root by id for verification later
    roots: [root]
  });

  const rootInvocationPath = join(VECTORS_DIR, 'js-invocation-root.json');
  // The root invocation's `proof.capability` is the root id STRING only; the
  // verifier dereferences that id via the documentLoader. So the actual ROOT
  // CAPABILITY is written to its own companion file -- pass it as the <rootFile>
  // argument to invoke-verify.mjs (the secured document does not embed it).
  const rootZcapPath = join(VECTORS_DIR, 'js-invocation-root-zcap.json');
  writeFileSync(
    rootInvocationPath, JSON.stringify(rootInvocation, null, 2) + '\n');
  writeFileSync(rootZcapPath, JSON.stringify(root, null, 2) + '\n');
  console.log('\nwrote', rootInvocationPath);
  console.log('wrote', rootZcapPath);
  console.log('  proof.capability       :', rootInvocation.proof.capability);
  console.log('  proof.capabilityAction :',
    rootInvocation.proof.capabilityAction);
  console.log('  proof.invocationTarget :',
    rootInvocation.proof.invocationTarget);

  // =========================================================================
  // 2. DELEGATED invocation -- first delegate root -> delegate, then invoke
  //    with proof.capability set to the FULL EMBEDDED delegated zcap.
  // =========================================================================
  const expires = toZcapTimestamp(
    new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000));

  // build the (unsigned) delegated capability: parent is the root, so the
  // capabilityChain is exactly [root.id] and the delegation proof is signed by
  // the ROOT controller (the party authorized to delegate the root).
  const delegatedDoc = {
    '@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
    id: `urn:uuid:${crypto.randomUUID()}`,
    controller: delegate.did,
    invocationTarget: INVOCATION_TARGET,
    allowedAction: [CAPABILITY_ACTION],
    expires,
    parentCapability: root.id
  };

  const delegationLoader = makeDocumentLoader({roots: [root]});
  const delegated = await jsigs.sign(delegatedDoc, {
    suite: new Ed25519Signature2020({
      key: rootController.key,
      date: created
    }),
    purpose: new CapabilityDelegation({parentCapability: root.id}),
    documentLoader: delegationLoader
  });

  // now invoke the delegated zcap: proof.capability is the FULL embedded object,
  // signed by the DELEGATE key (the delegated zcap's controller).
  const delegatedInvocation = await signInvocation({
    applicationDocument: makeApplicationDocument(),
    // DELEGATED capabilities MUST be embedded as the full object
    capability: delegated,
    capabilityAction: CAPABILITY_ACTION,
    invocationTarget: INVOCATION_TARGET,
    key: delegate.key,
    created,
    // documentLoader must serve the root by id to dereference the chain
    roots: [root]
  });

  const delegatedInvocationPath =
    join(VECTORS_DIR, 'js-invocation-delegated.json');
  const delegatedRootPath =
    join(VECTORS_DIR, 'js-invocation-delegated-root.json');
  writeFileSync(
    delegatedInvocationPath,
    JSON.stringify(delegatedInvocation, null, 2) + '\n');
  writeFileSync(
    delegatedRootPath, JSON.stringify(root, null, 2) + '\n');

  console.log('\nwrote', delegatedInvocationPath);
  console.log('wrote', delegatedRootPath);
  console.log('  proof.capability.id        :',
    delegatedInvocation.proof.capability.id);
  console.log('  proof.capability.proof.capabilityChain:',
    JSON.stringify(
      delegatedInvocation.proof.capability.proof.capabilityChain));
  console.log('  proof.verificationMethod   :',
    delegatedInvocation.proof.verificationMethod);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
