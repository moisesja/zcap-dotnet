# Architecture

zcap-dotnet separates capability policy from cryptographic proof machinery and
application key/storage infrastructure. The supported profile targets ZCAP v0.4.0;
see [requirements](docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md).

## Packages and boundaries

- **ZcapLd.Core**: models, creation/delegation, signing, chain validation, native
  attenuation, replay protection and signed revocation.
- **ZcapLd.AspNetCore**: dependency injection and authenticated revocation endpoints.
  It does not install an invocation HTTP-signature transport or private-key store.
- **NetCrypto / NetDid**: cryptographic primitives, key types and DID resolution.
- **DataProofsDotnet**: legacy cryptosuites and RDFC-1.0 canonicalization.
- **NetCid**: multibase encoding. Core contains thin adapters rather than separate
  implementations of these cryptographic foundations.

## Models

`Capability` represents root and delegated capabilities. `ControllerSet`,
`ProofSet`, and `InvocationCapability` preserve string/array/object wire shapes.
Roots contain only context, ID, controller and invocation target; delegated
capabilities add parent, expiry, action restrictions and delegation proofs.

`AdditionalProperties` preserves unknown capability fields. It does not make
unknown terms signature-bound under RDFC. Security decisions use supported fields.
The reserved `caveat` field is always rejected, even when stored as extension data.
There are no typed caveat models, registries or evaluation callbacks.

`Invocation` is the convenience in-stack envelope. The interoperable DI invocation
API signs an application document and places capability, action and target in its
proof. `VerificationResult` carries an outcome and optional diagnostic; bool APIs
return its `IsValid`. `CouldNotVerify` distinguishes infrastructure faults from
provably invalid authority. Denials are logged at Debug; unexpected faults at Warning.

## Services and extension points

| Service | Responsibility |
| --- | --- |
| `ICapabilityService` | Create roots and delegations, check native attenuation, construct unsigned invocations. |
| `ISigningService` | Produce proofs with consumer-provided `IDidSigner`; self-verify signatures against the resolved public key. |
| `IVerificationService` | Check proof/controller relationships, chains, target/action/expiry policy, freshness, revocation and replay. |
| `IDidSigner` | Sign using application-owned keys (HSM/KMS/Key Vault). No default implementation. |
| `IDidResolver` | Resolve key material; `DidKeyResolver` uses NetDid and `CompositeDidResolver` routes methods. |
| `IVerificationRelationshipResolver` | Authorize verification methods for the controller and proof purpose. |
| `IRootCapabilityResolver` | Resolve root trust anchors referenced by ID. Explicit-root overloads are also available. |
| `IRevocationService` / `IRevocationStore` | Record/check verifier-owned revocation state. In-memory implementations are for local development. |
| `INonceStore` | Atomic replay tracking. Share across replicas; `NullNonceStore` explicitly opts out. |

A resolver that also supplies relationship/root resolution is detected automatically.
No verification path fetches delegated ancestors by their IDs: they travel in the
embedded chain. Root resolution is an explicit trust boundary.

## Capability profile and target attenuation

`CapabilityProfile` walks capability locations before signing or trusting authority.
It inspects every proof-set member and embedded ancestor, handles typed models and
wire JSON, and bounds depth/work to reject cycles. It rejects the presence of any
`caveat` key, including null/empty values. Standalone proof verification applies the
guard before its proofless-root shortcut. Envelope invocation checks its separate
capability argument, body capability and proof capability independently. Signed revocation
also checks these representations and its explicit root before recording state. The DI
application document may have its own unrelated fields.

`InvocationTargetPolicy` shares ordinal `/`, `?`, `&` suffix checks and literal
path-traversal protection between creation and verification. Delegation creation
accepts an optional narrower `invocationTarget`; verification requires explicit
`VerificationPolicy.AllowTargetAttenuation = true`. Default false matches the JS
reference's exact-target default. Applications enforce query semantics and ensure
that routing and URL normalization agree with the authenticated target.

## Proof and chain flow

1. Create a root and register it with a trusted root resolver, or pass it explicitly.
2. Delegate a subset of actions with a bounded expiry and an optional narrower target.
3. Build `[rootId]` for the first delegation or
   `[rootId, ...ancestorIds, {immediateParent}]` for deeper delegations.
4. Sign with an authorized parent controller through `IDidSigner`.
5. At invocation, validate every chain link, authority restriction and revocation.
6. Verify the invoker's signature and controller relationship, enforce freshness,
   then atomically record the nonce before authorizing the action.

`LegacyProofCrypto` delegates to DataProofs' Ed25519Signature2020 and
EcdsaSecp256r1Signature2019 suites. `ZcapSuiteCatalog` binds proof type, key type and
context. `ProofSigningPayloadBuilder` supplies clone helpers and the test oracle.
Signing bytes remain `SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))`.
`RdfcContextDocumentLoader` serves embedded contexts offline; `ZcapJsonOptions`
provides consistent serialization and rejects duplicate JSON properties.

The DI verifier requires expected action/targets and can pin root IDs. It validates
the application context before trusting the proof so invocation fields cannot be
dropped from the signed RDF dataset. Golden vectors and the live JS harness pin
canonicalization and proof interoperability. Modern v0.4 example suites do not
require replacing this explicitly supported proof format.

## Time, revocation and replay

Delegated capabilities expire. The optional `EnforceMaxDelegationExpiration`
policy bounds each retained link's future expiration. Delegation `created` must
be parseable when present and cannot exceed allowed clock skew; requiring it is
optional. Invocation/revocation `created` additionally has a lower freshness bound
based on the nonce window. Revocation authorization intentionally exempts applicable
expiration-ceiling/created policies so removing authority remains possible; it does
not exempt unsupported caveats.

ASP.NET registers `AddZcapServices`, custom signer/resolver/root/nonce/revocation
implementations, and `MapZcapRevocationEndpoints`. The revoke POST authenticates a
signed request and caps its body. Anonymous status GET returns only ID and revoked
state. Free-form revocation `reason`/`metadata` are informational under RDFC, not
signature-bound policy.

Replicated verifiers must share authoritative revocation and replay stores. The
library does not discover unknown verifiers, distribute revocations between
independent operators, or poll a capability-supplied URI. See the
[revocation guide](docs/REVOCATION-INTEGRATION.md).

## Concurrency and limits

Core holds no private keys. Shared stores/signers/resolvers supplied by consumers
must be safe for their application concurrency. In-memory implementations use
concurrent storage. Chain traversal is bounded (maximum length 10). HTTP-signature
invocation transport, WASM integration, and a negotiated modern cryptosuite profile
remain separate work; the current interop harness tests Ed25519 delegation and DI
invocation, not every feature of every peer.
