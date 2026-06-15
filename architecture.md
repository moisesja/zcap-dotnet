# Architecture

## Overview

`zcap-dotnet` is organized as a layered library focused on capability lifecycle operations:

1. Create root capabilities
2. Delegate capabilities with attenuation
3. Sign invocation requests
4. Verify delegation chains and invocation proofs
5. Evaluate caveats across the chain

Primary assembly: `src/ZcapLd.Core`.

## Component Map

### Models (`src/ZcapLd.Core/Models`)

- `Capability`: root/delegated capability representation
- `Proof`: delegation/invocation proof representation
- `Invocation`: invocation request representation
- `InvocationCapability`: union of the two spec-defined `capability` wire shapes — a root zcap **id
  string** or the **full embedded delegated zcap object** — used by both `Invocation.Capability` and
  the invocation `Proof.Capability`; preserves the wire shape via `InvocationCapabilityJsonConverter`
  (Issue #51)
- `Caveat` + derived types:
  - `ExpirationCaveat`
  - `UsageCountCaveat`
  - `ValidWhileTrueCaveat` (remote revocation via URI check)
- `InvocationContext`: runtime context for caveat evaluation

### Service Interfaces (`src/ZcapLd.Core/Services`)

- `ICapabilityService`: create/delegate/validate capabilities
- `ISigningService`: sign capability and invocation documents
- `IVerificationService`: verify proof/chain/invocation, resolve keys, revocation API. Each verify
  method has a `...DetailedAsync` sibling returning a structured `VerificationResult`
  (`VerificationOutcome` enum + optional message) so callers can distinguish failure modes
  programmatically; the `Task<bool>` methods are thin wrappers over `(await ...DetailedAsync(...)).IsValid` (Issue #70)
- `IDidResolver`: resolve DIDs to public keys (returns `ResolvedKey` with key type); implementations: `DidKeyResolver` (wraps NetDid's `DidKeyMethod`), `CompositeDidResolver`
- `IDidSigner`: sign data using a DID's private key; no default implementation in core — consumers provide their own
- `IRootCapabilityResolver`: resolve a root capability by id so the verifier can authorize a spec-exact delegation chain (which references the root by id only — Issue #50); implementations: `InMemoryRootCapabilityResolver` (dev). No default in core — the resource owner resolves roots from its own store. A `VerificationService` also accepts an explicit root on its verify/revoke overloads, and auto-detects an `IDidResolver` that additionally implements this interface.
- `ICaveatProcessor`: caveat merge/compatibility/evaluation
- `INonceStore`: pluggable persistence contract for invocation nonce tracking (replay protection); implementations: `InMemoryNonceStore`, `NullNonceStore` (no-op)
- `IRevocationStore`: pluggable persistence contract for revocation records
- `IRevocationService`: revocation orchestration (record + lookup + expiry pruning on read)
- `IValidWhileTrueHandler`: async handler for evaluating ValidWhileTrue caveat URIs; no default in core — `HttpValidWhileTrueHandler` provided by `ZcapLd.AspNetCore`

### Service Implementations (`src/ZcapLd.Core/Services`)

- `CapabilityService`
  - Creates root capabilities
  - Creates delegated capabilities
  - Applies attenuation checks during delegation
  - Builds proof `capabilityChain` payload
- `SigningService`
  - Canonicalizes documents and delegates signing to `IDidSigner`
  - Produces delegation and invocation proofs
  - Resolves verification method URIs via `IDidResolver`
  - Resolves per-suite JSON-LD context URLs via `ICryptoSuiteProvider`
- `VerificationService`
  - Verifies delegation proofs using `ICryptoSuiteProvider` to dispatch to the correct algorithm
  - Verifies capability chains, strictly validating the spec-exact `capabilityChain` shape and rejecting
    non-spec forms (embedded root, duplicated ids, parent referenced both by id and embedded, wrong/missing
    embedded parent) — Issue #50
  - Obtains the root (referenced by id only) via an explicit-root overload, else an
    `IRootCapabilityResolver`, else fails closed
  - Verifies invocation proof + action/target + caveats
  - Enforces invocation replay protection via `INonceStore`
  - Resolves public keys via `IDidResolver` and revocation checks
  - Authorizes the proof's verification method against the controller's DID document via
    `IVerificationRelationshipResolver` (`capabilityInvocation` for invocations,
    `capabilityDelegation` for delegations) — Issue #65
  - Applies an optional, opt-in `VerificationPolicy` (off by default): when
    `EnforceMaxDelegationExpiration` is set, rejects a delegated zcap whose `expires` is more than
    `MaxDelegationExpirationMonths` (default 3) in the future, measured at verification time — the
    W3C verifier-side SHOULD (Issue #73). Enforced on the invocation/chain paths only; the
    revocation-authorization path bypasses it so a long-lived delegation stays revocable
  - Checks each delegation proof's `created` for temporal soundness (Issue #99): a future-dated
    (beyond the clock-skew tolerance) or unparseable `created` is always rejected, and a missing
    `created` is rejected only under the opt-in `VerificationPolicy.RequireDelegationProofCreated`.
    Unlike the invocation freshness check (Issue #71) there is no staleness lower-bound — a durable
    delegation signed long ago verifies until it `expires`. Detailed reason `InvalidProofTime`; like
    the expiration ceiling it is bypassed on the revocation-authorization path
- `RevocationService`
  - Persists revocation records via `IRevocationStore`
  - Applies retention/expiry behavior for revocation lookups
- `InMemoryRevocationStore`
  - Default development/testing revocation persistence
- `CaveatProcessor`
  - Evaluates caveat predicates (including async ValidWhileTrue via optional `IValidWhileTrueHandler`)
  - Merges inherited caveats across chain
  - Checks caveat compatibility (ValidWhileTrue enforces URI immutability across delegations)

### Crypto (`src/ZcapLd.Core/Cryptography`)

- `ICryptoSuite`: suite **metadata** (proof type, key type, context URL, canonicalization method) — the sign/verify crypto is delegated to DataProofs' legacy cryptosuites via `LegacyProofCrypto`
- `ICryptoSuiteProvider` / `CryptoSuiteProvider`: registry for lookup by proof type or key type
- `CryptoSuite`: parameterized `ICryptoSuite` metadata record; static factories `Ed25519()` and `P256()`
- `IDocumentCanonicalizer` / `IDocumentCanonicalizerProvider`: abstraction for pluggable canonicalization methods
- `JcsDocumentCanonicalizer`: RFC 8785 JSON Canonicalization Scheme (wraps `JsonCanonicalizer`)
- `RdfcDocumentCanonicalizer`: W3C RDFC-1.0 RDF Dataset Canonicalization — a thin adapter over `DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer` (the stack's single dotNetRDF home), with `RdfcContextDocumentLoader` serving zcap's embedded JSON-LD contexts offline
- `DocumentCanonicalizerProvider`: dictionary-backed canonicalizer registry
- `MultibaseCodec`: algorithm-agnostic multibase encoding/decoding (delegates to NetCid)
- `JsonCanonicalizer`: deterministic JSON canonicalization (RFC 8785) — delegates to `NetCid.JcsCanonicalizer` after a null-object-member strip
- `LegacyProofCrypto`: bridges signing/verification to DataProofs' legacy cryptosuites (`Ed25519Signature2020` / `EcdsaSecp256r1Signature2019`) — the byte-compatible implementations of zcap's 2020-era embedded-proof convention; `DidSignerAdapter` exposes the consumer's `IDidSigner` as a `NetCrypto.ISigner`, `ResolvedKeyTypeMap` maps the resolved key type to NetCrypto's
- `ProofSigningPayloadBuilder`: clone-without-proof helpers (production) and the reference signing-payload oracle the Compliance golden vectors assert against (JCS = doc+proof combined; RDFC-1.0 = separate SHA-256 hashes concatenated)
- `CaveatJsonConverter`: polymorphic `JsonConverter<Caveat>` — writes via runtime concrete type, reads via discriminator lookup against `CaveatTypeRegistry`. Required for cross-language interop (sign-time vs. wire-time bytes match).
- `ZcapJsonOptions.Default`: shared `JsonSerializerOptions` used by both sign-time canonicalization and verifier-time chain deserialization. Single source of truth for the encoder, null-handling, and the caveat converter.

### Models — registries (`src/ZcapLd.Core/Models`)

- `CaveatTypeRegistry.Default`: process-wide singleton mapping `Caveat.Type` discriminator strings to concrete CLR types. Pre-populated with `ExpirationCaveat`, `UsageCountCaveat`, `ValidWhileTrueCaveat`. Third-party caveat libraries register their derived types here at startup.

### Exceptions (`src/ZcapLd.Core/Exceptions`)

- Domain exceptions for capability, invocation, caveat, and crypto failures

## Data/Trust Flow

### Delegation Flow

1. Caller creates root capability via `CapabilityService.CreateRootCapabilityAsync`.
2. Caller delegates to child controller via `DelegateCapabilityAsync`.
3. `CapabilityService` validates attenuation and caveat inheritance.
4. `SigningService.SignCapabilityAsync` signs the delegated capability payload.
5. Delegated `Proof` includes a `capabilityChain` rooted at the root ID.

### Invocation Flow

1. Controller creates `Invocation` with the invoked capability, action, and target. Per ZCAP-LD v0.3
   the `capability` shape depends on what is invoked: a **root** invocation carries the root zcap **id
   string** (`Capability = root.Id`); a **delegated** DI invocation MUST embed the **full delegated
   zcap object** (`Capability = InvocationCapability.FromCapability(delegated)`) so the verifier has the
   authority chain without dereferencing it by id (Issue #51).
2. `SigningService.SignInvocationAsync` creates invocation proof; the `capability` (id string or full
   embedded object) is part of the signed canonical payload.
3. `VerificationService.VerifyInvocationAsync` checks:
   - capability chain validity (including the opt-in 3-month delegated-expiration ceiling when
     `VerificationPolicy.EnforceMaxDelegationExpiration` is enabled — Issue #73)
   - invocation proof purpose and signature
   - **invocation `capability` shape (strict)**: a root invocation MUST use the root id string, a
     delegated invocation MUST embed the full zcap whose id matches the verified capability — a
     delegated invocation supplying only an id string is rejected (Issue #51)
   - action and target constraints
   - controller authorization — resolves the controller's DID document and confirms the
     verification method is in the `capabilityInvocation` relationship (delegations use
     `capabilityDelegation`); honors cross-DID references and per-purpose key separation
   - all caveats across root→leaf chain

### Structured verification results (Issue #70)

Every verify method returns a bare `Task<bool>` **and** has a `...DetailedAsync` sibling returning a
`VerificationResult` — a `VerificationOutcome` (e.g. `Revoked`, `Expired`, `InvalidSignature`,
`UnauthorizedController`, `InvalidDelegation`, `AttenuationViolation`, `ChainTooLong`, `CaveatFailed`,
`Replayed`, `InvalidTarget`, `ActionNotAllowed`, `StaleProof`, `ExpirationTooFarInFuture`,
`InvalidProofTime`, `MalformedCapability`, `CouldNotVerify`) plus an
optional diagnostic message. This lets a caller tell *why* a capability was denied — e.g. `Revoked`
vs a broken chain — without re-deriving it. `CouldNotVerify` is the explicit "couldn't check"
(config/transient/infrastructure fault) outcome, distinct from a capability that is provably invalid
(the M7 / Issue #64 distinction surfaced at the API). Verification stays **fail-closed**: any
non-`Valid` outcome denies, and the bool methods return `IsValid`. Denials are now logged on **all**
paths (a single Debug-severity choke point on the public boundary), not just the exception path —
attacker-drivable denials log at Debug so a hostile client cannot flood the operator's Warning channel.

## Capability Chain Semantics

- Root capability is the trust anchor (`proof == null`), referenced in `capabilityChain` **by id only**
  and never embedded.
- First-level delegation chain is **exactly** `[rootId]`.
- Deeper delegations carry the root id first, then each ancestor **by id**, and embed **only** the
  immediate parent capability object as the last entry (e.g. `[rootId, firstId, {parent}]`).
- Generation (`CapabilityService.BuildCapabilityChain`) emits this minimal shape; verification
  (`VerificationService`) strictly validates it and **rejects** non-spec forms — an embedded root,
  duplicated ids, a parent referenced both by id and embedded, or a wrong/missing embedded parent
  (Issue #50).
- Because the root is by-reference, verification obtains it via an explicit-root overload or an
  `IRootCapabilityResolver` (else fails closed), then traverses the chain root→leaf and enforces
  attenuation, expiry, caveats, and revocation at each hop.

## Key Management Model

`SigningService` delegates all signing to a user-provided `IDidSigner` and all key resolution to `IDidResolver`. No default signer ships in the core package.

Production recommendation:

- Implement `IDidSigner` backed by your HSM/KMS/Key Vault
- Use `DidKeyResolver` (or `CompositeDidResolver`) for public key resolution
- Avoid plaintext key material — `InMemoryDidProvider` is for tests/examples only

## Extensibility Points

### Custom Crypto Suites

Implement `ICryptoSuite` for new signature algorithms and register via `CryptoSuiteProvider.Register()` or `AddZcapCryptoSuite<T>()` in ASP.NET DI. Built-in suites: `CryptoSuite.Ed25519()` and `CryptoSuite.P256()`. Override the `CanonicalizationMethod` default interface method to use `"RDFC-1.0"` instead of `"JCS"` for suites that require RDF canonicalization.

### Custom Caveats

Three steps:

1. Extend `Caveat` with the discriminator `Type` override and any policy fields. Mark mutable runtime state `[JsonIgnore]` — only the policy goes on the wire (otherwise mutation invalidates the signature).
2. **Register the type against its discriminator** so the polymorphic JSON converter can dispatch:
   - In-process / examples: `CaveatTypeRegistry.Default.Register<MyCaveat>("MyCaveat")` at startup.
   - ASP.NET DI: `services.AddZcapCaveatType<MyCaveat>("MyCaveat")` (mirrors `AddZcapCryptoSuite<T>()`).
3. Add evaluation logic — synchronous via `IsSatisfied` on the caveat, or async by extending `CaveatProcessor` (the ValidWhileTrue pattern below).

Skipping step 2 silently breaks cross-language interop: STJ uses the static array element type for `Capability.Caveat`, dropping derived fields at sign time. Without registration, verifier-time deserialization throws on the abstract `Caveat` base for any wire body coming in from another stack.

### ValidWhileTrue Caveat (Remote Revocation)

The `ValidWhileTrueCaveat` embeds a URI that the verifier checks at invocation time. The delegator/controller hosts the status endpoint; the verifier opts in to checking it.

- **Core**: `ValidWhileTrueCaveat` model + `IValidWhileTrueHandler` interface. `CaveatProcessor` accepts an optional handler; without one, the caveat fails closed.
- **ASP.NET**: `HttpValidWhileTrueHandler` implements `IValidWhileTrueHandler` using `IHttpClientFactory`. Register via `AddZcapValidWhileTrueSupport()`. The existing `GET /zcaps/revocations/{*capabilityId}` endpoint serves as the backend — the handler checks `!isRevoked` from the `RevocationStatusHttpResponse`.
- **Attenuation**: child capabilities cannot change a parent's ValidWhileTrue URI (enforced in `ValidateCaveatCompatibilityAsync`).

### DID Resolution

DID resolution for did:key is handled by `DidKeyResolver`, which wraps NetDid's `DidKeyMethod`. For additional DID methods (did:web, did:ion, etc.), implement `IDidResolver` and register in `CompositeDidResolver`. The resolver returns `ResolvedKey(byte[] PublicKeyBytes, string KeyType)` so the verification service knows which crypto suite to use.

**Controller authorization** is a separate concern from key resolution. `VerificationService` resolves the controller's DID *document* through a NetDid `IVerificationRelationshipResolver` (2.0.0) and confirms the proof's verification method appears in the relevant relationship — `capabilityInvocation` for invocations, `capabilityDelegation` for delegations **and revocations** (revocation is a delegation-authority action). `DidKeyResolver` also implements this interface (so did:key works out of the box); for other methods, supply a method-appropriate `IVerificationRelationshipResolver` (e.g. one wired by NetDid's `AddNetDid`) either by having your `IDidResolver` implement it or by passing it to `VerificationService` / registering it for `AddZcapServices`. Controllers whose document cannot be resolved fail closed; the log severity is attacker-aware — a malformed/unknown/unsupported controller DID (attacker-drivable) logs at **Debug**, while an unexpected/transient resolver fault logs at **Warning** (Issue #64).

> **Caution (partial self-providing resolvers):** if your `IDidResolver` implements `IVerificationRelationshipResolver` but only handles *one* DID method (e.g. did:key), it is used for **all** controllers — so a controller of a method it doesn't own resolves to `ControllerNotResolvable` and is **silently denied** (fail-closed, logged at Debug). Wire a multi-method resolver (or one that delegates per method) when your capabilities can carry controllers across DID methods.

### Revocation Storage

Implement `IRevocationStore` to persist revocation records in any backend:

- SQL/NoSQL databases
- Blockchain/smart contract clients
- Oracle bridges / remote trust infrastructure
- Distributed cache layers

### ASP.NET Revocation Endpoints

For ASP.NET hosts, use `ZcapLd.AspNetCore` to expose revocation APIs quickly:

- Register the service graph via `AddZcapServices()` — the POST/revoke endpoint resolves `IVerificationService` to authenticate + authorize a **signed** revocation request (proof-of-possession). Override the store with `AddZcapRevocationSupport<MyStore>()`.
- Expose routes via `MapZcapRevocationEndpoints(...)`
- POST body is `{ capability, signedRevocation }`; the endpoint returns `403` when unauthenticated/unauthorized. Default route prefix is `/zcaps/revocations`

### Alternative Revocation Exposure Patterns

The core library does not require ASP.NET. Revocation can be exposed through:

- gRPC service methods
- queue/topic consumers
- background workers
- CLI/admin tooling
- smart-contract relayers/oracles

These patterns should drive `IVerificationService.RevokeCapabilityAsync(Capability, Invocation)` (which enforces signature authentication + chain authorization). `IRevocationService` is the unauthenticated persistence primitive — call it directly only after authenticating and authorizing the caller yourself.

### Persistence Strategy Configuration

Recommended persistence profiles:

- Development: `InMemoryRevocationStore`
- Centralized production: database-backed `IRevocationStore`
- Decentralized production: contract/oracle-backed `IRevocationStore`
- High scale: hybrid cache + durable backing store

Reference implementation guide: `docs/REVOCATION-INTEGRATION.md`.

### Remote Invocation Interface

Library is in-process first. Service methods are interface-driven and can be wrapped by gRPC/HTTP without changing core models.

### Custom Canonicalization

Implement `IDocumentCanonicalizer` for additional canonicalization methods and register via `DocumentCanonicalizerProvider.Register()` or `AddZcapRdfcCanonicalization()` in ASP.NET DI. Built-in canonicalizers: `JcsDocumentCanonicalizer` (RFC 8785) and `RdfcDocumentCanonicalizer` (W3C RDFC-1.0 via dotNetRdf).

## Dependencies

`ZcapLd.Core` keeps a deliberately small runtime footprint (the library is intended to stay AOT/WASM-friendly per the `wasi-experimental` goal). Direct package references:

- **NetCrypto** — the cryptographic foundation: Ed25519 / P-256 sign + verify (`DefaultCryptoProvider`, `EcdsaSignatureFormat`), the key model, and key generation. `CryptoSuite` calls it directly.
- **NetDid.Core** / **NetDid.Method.Key** (2.0.0) — W3C-compliant `did:key` creation/resolution and the `IVerificationRelationshipResolver`. As of 2.0.0 NetDid itself builds on NetCrypto (it no longer bundles its own crypto), so zcap and NetDid share one crypto stack.
- **DataProofsDotnet.Rdfc** — the RDFC-1.0 / JSON-LD canonicalization `RdfcDocumentCanonicalizer` adapts; it owns the dotNetRDF dependency transitively (zcap references no RDF library directly). The default JCS path does not load it.
- **NetCid** — multibase/multicodec encoding and the RFC 8785 `JcsCanonicalizer` the JCS path delegates to (arrives transitively via NetCrypto / NetDid / DataProofs.Rdfc, all pinned to the same version).
- **Microsoft.Extensions.Logging.Abstractions** — added in Issue #64 so `VerificationService` can log the cause when it fails closed. This is the **abstractions** assembly only (it carries no concrete logging implementation): consumers who don't otherwise use `Microsoft.Extensions.*` pull in just the `ILogger` / `NullLogger` types, and the verifier defaults to `NullLogger` (zero output) when no logger is supplied.

`Microsoft.SourceLink.GitHub` is a build-only dependency (`PrivateAssets="All"`) and is not propagated to consumers.

## Non-Goals and Current Limitations

- RDFC-1.0 canonicalization runs through DataProofsDotnet.Rdfc (over dotNetRDF), which has not passed the full W3C RDFC-1.0 conformance test suite (86 test cases); zcap's golden-vector + smoke tests verify byte-stable correctness for ZCAP documents.
- No default distributed revocation backend is shipped; consumers provide their own `IRevocationStore` for production.

## Thread Safety

- `CryptoSuiteProvider` uses `ConcurrentDictionary` for proof-type lookup; suite registration is expected at startup.
- Service instances are stateless and safe for concurrent usage.
- `InMemoryDidProvider` (test helper) uses `ConcurrentDictionary` for key storage.
