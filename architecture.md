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
- `Caveat` + derived types:
  - `ExpirationCaveat`
  - `UsageCountCaveat`
  - `ValidWhileTrueCaveat` (remote revocation via URI check)
- `InvocationContext`: runtime context for caveat evaluation

### Service Interfaces (`src/ZcapLd.Core/Services`)

- `ICapabilityService`: create/delegate/validate capabilities
- `ISigningService`: sign capability and invocation documents
- `IVerificationService`: verify proof/chain/invocation, resolve keys, revocation API
- `IDidResolver`: resolve DIDs to public keys (returns `ResolvedKey` with key type); implementations: `DidKeyResolver` (wraps NetDid's `DidKeyMethod`), `CompositeDidResolver`
- `IDidSigner`: sign data using a DID's private key; no default implementation in core — consumers provide their own
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
  - Verifies capability chains
  - Verifies invocation proof + action/target + caveats
  - Enforces invocation replay protection via `INonceStore`
  - Resolves public keys via `IDidResolver` and revocation checks
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

- `ICryptoSuite`: algorithm-specific sign/verify interface (proof type, key type, context URL, canonicalization method)
- `ICryptoSuiteProvider` / `CryptoSuiteProvider`: registry for lookup by proof type or key type
- `CryptoSuite`: parameterized implementation delegating to NetDid's `DefaultCryptoProvider`; static factories `Ed25519()` and `P256()`
- `IDocumentCanonicalizer` / `IDocumentCanonicalizerProvider`: abstraction for pluggable canonicalization methods
- `JcsDocumentCanonicalizer`: RFC 8785 JSON Canonicalization Scheme (wraps `JsonCanonicalizer`)
- `RdfcDocumentCanonicalizer`: W3C RDFC-1.0 RDF Dataset Canonicalization (uses dotNetRdf for JSON-LD → N-Quads)
- `DocumentCanonicalizerProvider`: dictionary-backed canonicalizer registry
- `MultibaseCodec`: algorithm-agnostic multibase encoding/decoding (delegates to NetCid)
- `JsonCanonicalizer`: deterministic JSON canonicalization (RFC 8785)
- `ProofSigningPayloadBuilder`: builds signing payloads; JCS combines doc+proof into single object, RDFC-1.0 canonicalizes separately and concatenates SHA-256 hashes (per W3C Data Integrity spec)
- `SignatureVerifier`: helper wrapper for signature checks (accepts `ICryptoSuite` + optional `IDocumentCanonicalizer`)
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

1. Controller creates `Invocation` with capability ID, action, and target.
2. `SigningService.SignInvocationAsync` creates invocation proof.
3. `VerificationService.VerifyInvocationAsync` checks:
   - capability chain validity
   - invocation proof purpose and signature
   - action and target constraints
   - controller authorization
   - all caveats across root→leaf chain

## Capability Chain Semantics

- Root capability is the trust anchor (`proof == null`).
- First-level delegation chain can contain only the root capability ID.
- Deeper delegations carry root ID first and embed immediate parent capability object last.
- Verification traverses chain root→leaf and enforces attenuation at each hop.

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

### Revocation Storage

Implement `IRevocationStore` to persist revocation records in any backend:

- SQL/NoSQL databases
- Blockchain/smart contract clients
- Oracle bridges / remote trust infrastructure
- Distributed cache layers

### ASP.NET Revocation Endpoints

For ASP.NET hosts, use `ZcapLd.AspNetCore` to expose revocation APIs quickly:

- Register revocation services via `AddZcapRevocationSupport(...)`
- Expose routes via `MapZcapRevocationEndpoints(...)`
- Default route prefix is `/zcaps/revocations`

### Alternative Revocation Exposure Patterns

The core library does not require ASP.NET. Revocation can be exposed through:

- gRPC service methods
- queue/topic consumers
- background workers
- CLI/admin tooling
- smart-contract relayers/oracles

These patterns should call `IRevocationService` so transport logic stays separate from revocation domain logic.

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

## Non-Goals and Current Limitations

- dotNetRdf has not passed the W3C RDFC-1.0 conformance test suite (86 test cases); smoke tests verify basic correctness.
- No default distributed revocation backend is shipped; consumers provide their own `IRevocationStore` for production.

## Thread Safety

- `CryptoSuiteProvider` uses `ConcurrentDictionary` for proof-type lookup; suite registration is expected at startup.
- Service instances are stateless and safe for concurrent usage.
- `InMemoryDidProvider` (test helper) uses `ConcurrentDictionary` for key storage.
