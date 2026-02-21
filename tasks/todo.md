# IDidProvider Interface Segregation Refactor - 2026-02-21

## Motivation

`InMemoryDidProvider` stores private keys in plaintext memory with no protection. It should not ship in the core NuGet package. Additionally, `IDidProvider` conflates two distinct responsibilities: secret-holding signing operations and public key resolution.

## Design

Split `IDidProvider` into two interfaces following ISP:

- **`IDidResolver`** — public key resolution, no secrets. Ships with `DidKeyResolver` (handles `did:key:` method) and `CompositeDidResolver` (routes by DID method prefix). Users implement for `did:web:`, `did:ion:`, etc.
- **`IDidSigner`** — signing operations, requires secret key access. No default implementation in core. Users must provide their own (HSM, Key Vault, Trinsic, etc.).

`InMemoryDidProvider` (implements both `IDidSigner` + `IDidResolver`) moves to test project as a test helper.

### Dependency changes:
- `SigningService(IDidSigner, IDidResolver)` — needs signer for `SignAsync`, resolver for `GetVerificationMethodAsync`
- `VerificationService(IDidResolver, ICaveatProcessor, ...)` — only needs resolver for `ResolvePublicKeyAsync`

## Plan

### Phase 1: New interfaces
- [x] Create `IDidResolver.cs` — `ResolvePublicKeyAsync` + `GetVerificationMethodAsync`
- [x] Create `IDidSigner.cs` — `SignAsync`
- [x] Delete `IDidProvider.cs`

### Phase 2: Core implementations
- [x] Create `DidKeyResolver : IDidResolver` — extract `did:key:` resolution logic from `InMemoryDidProvider` (stateless, no secrets)
- [x] Rename `CompositeDidProvider` → `CompositeDidResolver : IDidResolver` (routes resolver calls by DID method prefix)

### Phase 3: Update services
- [x] Update `SigningService` — constructor takes `(IDidSigner, IDidResolver)`, field split
- [x] Update `ISigningService` doc comments (references to `IDidProvider`)
- [x] Update `VerificationService` — constructor takes `IDidResolver` instead of `IDidProvider`

### Phase 4: Move InMemoryDidProvider out of core
- [x] Move `InMemoryDidProvider` to test project as test helper (implements `IDidSigner, IDidResolver`)
- [x] Update all test files to use relocated `InMemoryDidProvider`
- [x] Update `ComplianceTestFixture` wiring
- [x] Update examples with local `InMemoryDidProvider` copy

### Phase 5: Update DI extensions
- [x] Update ASP.NET DI extensions — register `DidKeyResolver` as `IDidResolver`, require user-provided `IDidSigner`, added `AddZcapDidSigner` + `AddZcapDidResolver` methods

### Phase 6: Verify
- [x] Build solution (`dotnet build ZcapLd.sln`) — 0 errors, 0 warnings
- [x] Run full test suite (`dotnet test ZcapLd.sln`) — **Failed: 0, Passed: 187, Total: 187**
- [x] Verify no references to `IDidProvider` remain in core or ASP.NET packages — confirmed clean

## Review

Split `IDidProvider` into `IDidResolver` (public key resolution) and `IDidSigner` (signing operations) following Interface Segregation Principle. Removed insecure `InMemoryDidProvider` from the core NuGet package. Core now ships `DidKeyResolver` for did:key resolution and `CompositeDidResolver` for routing across DID methods. No default signer ships — consumers must provide their own backed by a secure key management system. ASP.NET DI extensions updated with `AddZcapDidSigner<T>()` and `AddZcapDidResolver<T>()` methods.

---

# Pluggable Crypto Suite Abstraction - 2026-02-21

## Motivation

DID methods (did:key, did:web) and signature algorithms (Ed25519, P-256, secp256k1) are orthogonal. Previously, `DidKeyResolver` only understood the `0xed01` multicodec prefix (Ed25519), and `VerificationService`/`SigningService` hardcoded `Ed25519Signer` static calls for verification. This locked consumers into Ed25519.

## Design

Three orthogonal abstractions:

- **`ICryptoSuite`** — algorithm-specific sign/verify, proof type, key type, multicodec prefix, public key length
- **`ICryptoSuiteProvider`** — registry for lookup by proof type or multicodec prefix
- **`ResolvedKey`** — record carrying key bytes + key type from resolver to verification service

## Plan

### Phase 1: New types
- [x] Create `ICryptoSuite.cs` — pluggable algorithm interface
- [x] Create `ICryptoSuiteProvider.cs` — registry interface
- [x] Create `CryptoSuiteProvider.cs` — default implementation (ConcurrentDictionary + List)
- [x] Create `Ed25519CryptoSuite.cs` — thin adapter wrapping `Ed25519Signer`
- [x] Create `ResolvedKey.cs` — `record ResolvedKey(byte[] PublicKeyBytes, string KeyType)`

### Phase 2: Update interfaces
- [x] `IDidResolver.ResolvePublicKeyAsync` returns `Task<ResolvedKey>` (was `Task<byte[]>`)
- [x] `IVerificationService.ResolvePublicKeyAsync` returns `Task<ResolvedKey>`

### Phase 3: Update implementations
- [x] `DidKeyResolver` — new `ICryptoSuiteProvider` constructor + multicodec prefix lookup
- [x] `CompositeDidResolver` — return type change
- [x] `VerificationService` — `ICryptoSuiteProvider` dependency + suite dispatch by proof type
- [x] `SignatureVerifier` — `ICryptoSuite` parameter for verify methods

### Phase 4: Update consumers
- [x] `InMemoryDidProvider` (tests + examples) — return `ResolvedKey`
- [x] Test assertion fixes (`CapabilityServiceTests`, `InMemoryDidProviderTests`, `VerificationServiceTests`)
- [x] ASP.NET DI extensions — register `Ed25519CryptoSuite`, `ICryptoSuiteProvider`, `AddZcapCryptoSuite<T>()`

### Phase 5: New tests
- [x] `CryptoSuiteProviderTests.cs` — 7 tests (registration, lookup, null handling, replacement)
- [x] `Ed25519CryptoSuiteTests.cs` — 6 tests (properties, sign/verify, wrong key)

### Phase 6: Verify
- [x] Build solution — 0 errors, 0 warnings
- [x] Run full test suite — **Failed: 0, Passed: 203, Total: 203**

### Phase 7: Documentation
- [x] Update `README.md` — feature list, Quick Start, security notes
- [x] Update `ARCHITECTURE.md` — service interfaces, crypto section, extensibility
- [x] Update `src/ZcapLd.Core/PACKAGE_README.md` — Quick Start, features, notes
- [x] Update `docs/IMPLEMENTATION-COMPLETE.md` — project structure, code examples, compliance, future enhancements

## Review

Added pluggable crypto suite abstraction (`ICryptoSuite`, `ICryptoSuiteProvider`, `CryptoSuiteProvider`, `Ed25519CryptoSuite`) and `ResolvedKey` record. DID methods and signature algorithms are now fully orthogonal — `DidKeyResolver` decodes any registered multicodec prefix, and `VerificationService` dispatches verification to the correct suite by proof type. All backward-compatible: parameterless constructors default to Ed25519. ASP.NET DI extended with `AddZcapCryptoSuite<T>()`. 203 tests passing.
