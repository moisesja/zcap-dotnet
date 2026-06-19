/*!
 * Shared helpers for the ZCAP-LD cross-stack interop harness.
 *
 * This module wraps the REAL @digitalbazaar/zcap v9 reference library plus
 * jsonld-signatures and the Ed25519Signature2020 suite so that we can:
 *   - deterministically derive Ed25519 did:key identities from a 32-byte seed,
 *   - build a documentLoader that resolves the two JSON-LD contexts a delegated
 *     zcap needs, every did:key DID/verification method, and any in-memory root
 *     capability (keyed by its `id`), and
 *   - verify a *capability delegation* proof (NOT an invocation) on a delegated
 *     capability supplied purely as JSON (the shape the .NET side emits).
 *
 * Everything here works from JSON + did:key resolution only -- we never assume
 * digitalbazaar-internal key objects are embedded in the capabilities.
 */
import {createRequire} from 'node:module';

import jsigs from 'jsonld-signatures';
import {CapabilityDelegation, CapabilityInvocation, constants as zcapConstants}
  from '@digitalbazaar/zcap';
import {Ed25519Signature2020}
  from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020}
  from '@digitalbazaar/ed25519-verification-key-2020';
import {driver as didKeyDriver} from '@digitalbazaar/did-method-key';

// The zcap-context and ed25519-signature-2020-context packages publish their
// `js/index.js` entry points as CommonJS, so we pull them in via createRequire
// (cleanest way to get the canonical context document + URL inside an ESM file
// without guessing the bundled dist format). The zcap context is *also*
// re-exported by @digitalbazaar/zcap as `constants.ZCAP_CONTEXT(_URL)`, but we
// keep both context loads symmetric and explicit here.
const require = createRequire(import.meta.url);
const ed25519Sig2020Ctx = require('ed25519-signature-2020-context');

// ---------------------------------------------------------------------------
// Context URLs + documents.
// ---------------------------------------------------------------------------

// 'https://w3id.org/zcap/v1'
export const ZCAP_CONTEXT_URL = zcapConstants.ZCAP_CONTEXT_URL;
const ZCAP_CONTEXT = zcapConstants.ZCAP_CONTEXT;

// 'https://w3id.org/security/suites/ed25519-2020/v1'
export const ED25519_2020_CONTEXT_URL = ed25519Sig2020Ctx.constants.CONTEXT_URL;
const ED25519_2020_CONTEXT = ed25519Sig2020Ctx.CONTEXT;

// Static context table served by the documentLoader. Both contexts are returned
// with `contextUrl: null` so jsonld treats them as already-resolved documents.
const STATIC_CONTEXTS = new Map([
  [ZCAP_CONTEXT_URL, ZCAP_CONTEXT],
  [ED25519_2020_CONTEXT_URL, ED25519_2020_CONTEXT]
]);

// ---------------------------------------------------------------------------
// did:key driver (Ed25519 only).
// ---------------------------------------------------------------------------

// A driver instance configured to understand the `z6Mk` (Ed25519) multikey
// header so it can resolve did:key DIDs and individual verification methods.
const _driver = didKeyDriver();
_driver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from
});

/**
 * Deterministically derive an Ed25519 did:key identity from a 32-byte seed.
 *
 * @param {Uint8Array} seed - Exactly 32 bytes; identical seeds => identical key.
 * @returns {Promise<object>} `{key, did, verificationMethod, didDocument}`
 *   where `key` is an Ed25519VerificationKey2020 (with private material, so it
 *   can sign), `did` is `did:key:z6Mk...`, and `verificationMethod` is the
 *   full key id `did:key:z6Mk...#z6Mk...`.
 */
export async function didKeyFromSeed(seed) {
  if(!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TypeError('"seed" must be a 32-byte Uint8Array.');
  }
  // deterministic keypair from the seed (includes private key material)
  const key = await Ed25519VerificationKey2020.generate({seed});

  // build the did:key DID + set the key's id/controller so any proof it
  // creates carries `verificationMethod = did:key:z6Mk...#z6Mk...`
  const fingerprint = key.fingerprint();
  const did = `did:key:${fingerprint}`;
  key.controller = did;
  key.id = `${did}#${fingerprint}`;

  return {key, did, verificationMethod: key.id};
}

/**
 * Build a documentLoader for sign/verify operations.
 *
 * Resolves, in order:
 *   1. the two static JSON-LD contexts (zcap-v1 + ed25519-2020 suite),
 *   2. any root capability passed in `roots`, keyed by its `id`
 *      (returned as `{contextUrl: null, documentUrl: url, document: root}`),
 *   3. did:key DIDs and did:key verification-method URLs (`did:key:...#...`)
 *      via the Ed25519 did:key driver,
 * and otherwise throws (we never reach out to the network).
 *
 * @param {object} [options] - Options.
 * @param {object[]} [options.roots] - Root capabilities to serve by `id`.
 * @returns {Function} An async documentLoader(url) for jsonld-signatures.
 */
export function makeDocumentLoader({roots = []} = {}) {
  // index roots by their `id` so the zcap verifier's getRootCapability hook
  // (which calls documentLoader(rootId)) can dereference them
  const rootsById = new Map();
  for(const root of roots) {
    if(root && typeof root.id === 'string') {
      rootsById.set(root.id, root);
    }
  }

  return async function documentLoader(url) {
    // 1. static contexts
    const ctx = STATIC_CONTEXTS.get(url);
    if(ctx) {
      return {contextUrl: null, documentUrl: url, document: ctx};
    }

    // 2. in-memory root capabilities
    const root = rootsById.get(url);
    if(root) {
      return {contextUrl: null, documentUrl: url, document: root};
    }

    // 3. did:key DIDs and verification methods
    if(url.startsWith('did:key:')) {
      // `.get({url})` returns a full DID Document for a bare DID, or a single
      // public-key node (the verification method) for a `did:key:...#...` URL.
      const document = await _driver.get({url});
      return {contextUrl: null, documentUrl: url, document};
    }

    throw new Error(`Document loader: refusing to load unknown URL "${url}".`);
  };
}

/**
 * Verify a *capability delegation* proof on a delegated capability.
 *
 * Uses the reference library's CapabilityDelegation proof purpose with
 * `expectedRootCapability` set to the root id, and a documentLoader that serves
 * the root (by id) plus the contexts and did:key controllers. This is a pure
 * delegation-chain check -- it does NOT invoke the capability.
 *
 * @param {object} options - Options.
 * @param {object} options.delegated - The delegated capability JSON (with its
 *   `proof`).
 * @param {object} options.root - The root capability JSON (served via the
 *   documentLoader by its `id`, and used as the expected root).
 * @returns {Promise<object>} The full jsigs.verify() result object
 *   (`{verified, results, error?}`).
 */
export async function verifyDelegation({delegated, root}) {
  const documentLoader = makeDocumentLoader({roots: [root]});
  const suite = new Ed25519Signature2020();

  return jsigs.verify(delegated, {
    suite,
    purpose: new CapabilityDelegation({
      expectedRootCapability: root.id,
      suite
    }),
    documentLoader
  });
}

// ---------------------------------------------------------------------------
// Data Integrity `capabilityInvocation` (Path A).
// ---------------------------------------------------------------------------

/*
 * Wire-shape notes (the .NET side matches these byte-for-byte):
 *
 *  - The SECURED document is an *application document*: an arbitrary JSON-LD
 *    object that carries a `capabilityInvocation` proof. The invocation
 *    parameters (`capability` / `capabilityAction` / `invocationTarget`) live
 *    ONLY inside the proof object -- they are NOT copied into the signed
 *    document body (CapabilityInvocation.update() stamps them onto `proof`).
 *
 *  - The document body's `@context` MUST contain BOTH:
 *      1. the ZCAP context (`https://w3id.org/zcap/v1`) -- the verifier's
 *         `utils.checkProofContext` requires it to be present in the proof's
 *         effective `@context`, and jsigs derives the proof's `@context` from
 *         the *document's* `@context` at verify time (ProofSet `_getProofs`);
 *         the signed proof object therefore carries NO `@context` of its own.
 *      2. the ed25519-2020 suite context
 *         (`https://w3id.org/security/suites/ed25519-2020/v1`) -- the
 *         Ed25519Signature2020 suite's `matchProof` refuses any document that
 *         does not include the suite context.
 *    So the minimal application-document shape we use is exactly:
 *      {"@context": [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL]}
 *    (any additional, context-defined fields would also be signed; we keep it
 *    minimal so the .NET side has the smallest possible body to reproduce).
 *
 *  - Signing input (RDFC-1.0, via the suite's LinkedDataSignature base):
 *      verifyData = SHA256(canonicalize(proofOptions))
 *                || SHA256(canonicalize(applicationDocument))
 *    i.e. the PROOF-OPTIONS hash comes FIRST, the document hash SECOND. The
 *    proof-options object is canonicalized with the document's `@context`
 *    spliced in front of it (so BOTH halves canonicalize under the same
 *    `@context`), with `proofValue` stripped. Each half is canonicalized with
 *    RDFC-1.0 (jsonld -> RDF dataset -> URDNA2015), NOT JCS.
 */

/**
 * Create a Data Integrity `capabilityInvocation` proof over an application
 * document, using the REAL @digitalbazaar/zcap CapabilityInvocation purpose.
 *
 * Per CapabilityInvocation's constructor, the create-proof params are
 * `{capability, capabilityAction, invocationTarget}` and they MUST NOT be mixed
 * with any verify-proof param (`expectedAction` / `expectedTarget` /
 * `expectedRootCapability` / `suite` / `controller` / `date` /
 * `inspectCapabilityChain`) -- doing so throws
 * "Parameters for both creating and verifying a proof must not be provided
 * together." `capability` MUST be a string for a ROOT invocation (the root id)
 * and a full embedded object for a DELEGATED invocation.
 *
 * @param {object} options - Options.
 * @param {object} options.applicationDocument - The JSON-LD document to secure
 *   (its `@context` must include the zcap + ed25519-2020 contexts).
 * @param {string|object} options.capability - Root id string (root invocation)
 *   or the full embedded delegated zcap object (delegated invocation).
 * @param {string} options.capabilityAction - The action being invoked, e.g.
 *   `"read"`.
 * @param {string} options.invocationTarget - The absolute-URI target.
 * @param {object} options.key - The signing key (Ed25519VerificationKey2020
 *   with private material) belonging to the controller authorized to invoke.
 * @param {string|Date} [options.created] - Seconds-precision `created` to pin
 *   onto the proof (passed to the suite as `date`).
 * @param {object[]} [options.roots] - Root capabilities the documentLoader must
 *   serve by id (the root for a delegated invocation's embedded chain).
 * @returns {Promise<object>} The secured document (application document + a
 *   top-level `proof` whose `proofPurpose` is `capabilityInvocation`).
 */
export async function signInvocation({
  applicationDocument, capability, capabilityAction, invocationTarget, key,
  created, roots = []
}) {
  const documentLoader = makeDocumentLoader({roots});

  return jsigs.sign(applicationDocument, {
    suite: new Ed25519Signature2020({key, date: created}),
    // create-proof params ONLY (mixing in any verify param throws)
    purpose: new CapabilityInvocation({
      capability,
      capabilityAction,
      invocationTarget
    }),
    documentLoader
  });
}

/**
 * Verify a Data Integrity `capabilityInvocation` proof on a secured
 * application document.
 *
 * Per CapabilityInvocation's constructor, the verify-proof params used here are
 * `{expectedTarget, expectedAction, expectedRootCapability, suite}` -- a
 * DISJOINT set from the create params. `expectedAction` (string) and
 * `expectedTarget` (string|array) are required and validated; the proof's
 * `capabilityAction`/`invocationTarget` must match them exactly (no target
 * attenuation here). `expectedRootCapability` (validated by the base class,
 * string|array of absolute URIs) is the root id the dereferenced chain's root
 * MUST equal -- the documentLoader serves that root by id. The `suite` is used
 * to verify each delegation proof along the chain.
 *
 * For a ROOT invocation, `proof.capability` is the root id string; the chain is
 * just `[root]`. For a DELEGATED invocation, `proof.capability` is the full
 * embedded delegated zcap; the verifier walks its `capabilityChain` (the
 * embedded ancestors + the root referenced by id), so the documentLoader must
 * serve the root by id and resolve every did:key controller in the chain.
 *
 * @param {object} options - Options.
 * @param {object} options.securedDocument - The application document with its
 *   `capabilityInvocation` proof.
 * @param {string} options.expectedAction - The action the verifier requires.
 * @param {string|string[]} options.expectedTarget - The absolute-URI target(s)
 *   the verifier requires.
 * @param {string|string[]} options.expectedRootCapability - The root id(s) the
 *   chain's root must match.
 * @param {object} options.root - The root capability JSON, served by the
 *   documentLoader by its `id`.
 * @returns {Promise<object>} The full jsigs.verify() result
 *   (`{verified, results, error?}`).
 */
export async function verifyInvocation({
  securedDocument, expectedAction, expectedTarget, expectedRootCapability, root
}) {
  const documentLoader = makeDocumentLoader({roots: [root]});
  const suite = new Ed25519Signature2020();

  return jsigs.verify(securedDocument, {
    suite,
    // verify-proof params ONLY (mixing in any create param throws)
    purpose: new CapabilityInvocation({
      expectedTarget,
      expectedAction,
      expectedRootCapability,
      suite
    }),
    documentLoader
  });
}
