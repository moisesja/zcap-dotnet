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
- `InvocationContext`: runtime context for caveat evaluation

### Service Interfaces (`src/ZcapLd.Core/Services`)

- `ICapabilityService`: create/delegate/validate capabilities
- `ISigningService`: sign capability and invocation documents
- `IVerificationService`: verify proof/chain/invocation, resolve keys, revocation API
- `ICaveatProcessor`: caveat merge/compatibility/evaluation

### Service Implementations (`src/ZcapLd.Core/Services`)

- `CapabilityService`
  - Creates root capabilities
  - Creates delegated capabilities
  - Applies attenuation checks during delegation
  - Builds proof `capabilityChain` payload
- `SigningService`
  - Manages key registration for local/dev use
  - Produces delegation and invocation proofs
- `VerificationService`
  - Verifies delegation proofs
  - Verifies capability chains
  - Verifies invocation proof + action/target + caveats
  - Handles DID key resolution and revocation checks
- `CaveatProcessor`
  - Evaluates caveat predicates
  - Merges inherited caveats across chain
  - Checks caveat compatibility

### Crypto (`src/ZcapLd.Core/Cryptography`)

- `Ed25519Signer`: Ed25519 sign/verify + multibase encode/decode
- `JsonCanonicalizer`: deterministic JSON canonicalization
- `SignatureVerifier`: helper wrapper for signature checks

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

Current default `SigningService` key storage is in-process memory for development/testing.

Production recommendation:

- Replace `SigningService` with a secure key backend adapter
- Use KMS/HSM/Key Vault signing operations
- Avoid long-lived plaintext key material in process memory

## Extensibility Points

### Custom Caveats

Implement new caveat types by extending `Caveat` and adding compatibility/evaluation logic in `CaveatProcessor`.

### DID Resolution

`VerificationService.ResolvePublicKeyAsync` can be replaced/extended to call a DID resolver and enforce verification-method relationship checks.

### Remote Invocation Interface

Library is in-process first. Service methods are interface-driven and can be wrapped by gRPC/HTTP without changing core models.

## Non-Goals and Current Limitations

- Full RDF Dataset Canonicalization (URDNA2015) is not yet implemented.
- Proof metadata binding follows current implementation behavior and should be reviewed for strict Data Integrity interoperability requirements.
- Revocation storage is in-memory by default.

## Thread Safety

- Key store uses `ConcurrentDictionary`.
- Service instances are safe for concurrent read-heavy usage under current in-memory model.
