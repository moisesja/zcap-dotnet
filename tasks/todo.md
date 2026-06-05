# IDidProvider Interface Segregation Refactor - 2026-02-21

## Motivation

`InMemoryDidProvider` stores private keys in plaintext memory with no protection. It should not ship in the core NuGet package. Additionally, `IDidProvider` conflates two distinct responsibilities: secret-holding signing operations and public key resolution.

## Design

Split `IDidProvider` into two interfaces following ISP:

- **`IDidResolver`** — public key resolution, no secrets. Ships with `DidKeyResolver` (handles `did:key:` method) and `CompositeDidResolver` (routes by DID method prefix). Users implement for `did:web:`, `did:ion:`, etc.
- **`IDidSigner`** — signing operations, requires secret key access. No default implementation in core. Users must provide their own (HSM, Key Vault, etc.).

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

---

# Crypto Refinement: MultibaseCodec, Dynamic Context URL, P-256 Suite - 2026-02-21

## Motivation

Three deferred items from the crypto suite abstraction:

1. Shared utilities (`CanonicalizeDocument`, `EncodeSignature`, `DecodeSignature`) lived on `Ed25519Signer` despite being algorithm-agnostic.
2. `CapabilityService.DelegateCapabilityAsync` hardcoded the Ed25519 JSON-LD context URL — P-256 capabilities would get the wrong context.
3. No P-256 (`ICryptoSuite`) implementation existed.

## Plan

### Part 1: Extract MultibaseCodec

- [x] Create `MultibaseCodec.cs` — `Encode`, `Decode`, `CanonicalizeDocument` (algorithm-agnostic)
- [x] Remove methods from `Ed25519Signer` (breaking change, no `[Obsolete]` wrappers)
- [x] Update all callers: `SigningService`, `VerificationService`, `SignatureVerifier`, `DidKeyResolver`, `InMemoryDidProvider` (test helper), `Ed25519SignerTests`
- [x] Create `MultibaseCodecTests.cs` — 10 tests

### Part 2: Dynamic context URL

- [x] Add `ContextUrl` property to `ICryptoSuite` + `Ed25519CryptoSuite`
- [x] Add `GetByKeyType(string)` to `ICryptoSuiteProvider` + `CryptoSuiteProvider`
- [x] Add `ResolveSuiteContextUrlAsync(string signerDid)` to `ISigningService` + `SigningService`
- [x] Add `ICryptoSuiteProvider` dependency to `SigningService`
- [x] Update `CapabilityService.DelegateCapabilityAsync` — dynamic context URL resolution
- [x] Update ASP.NET DI wiring for `SigningService` with `ICryptoSuiteProvider`

### Part 3: P-256 suite

- [x] Create `EcPointCompression.cs` — internal helper for compressed EC point handling (P-256 curve equation via BigInteger)
- [x] Create `P256CryptoSuite.cs` — full `ICryptoSuite` implementation using `System.Security.Cryptography.ECDsa` (zero new dependencies)
- [x] Register P-256 in default providers: `DidKeyResolver`, `VerificationService`, `SigningService`
- [x] Register P-256 in ASP.NET DI
- [x] Create `EcPointCompressionTests.cs` — 7 tests
- [x] Create `P256CryptoSuiteTests.cs` — 11 tests
- [x] Add `InternalsVisibleTo` for test project access to internal helpers

### Phase 4: Verify

- [x] Build solution — 0 errors, 0 warnings (1 pre-existing doc warning)
- [x] Run full test suite — **Failed: 0, Passed: 232, Total: 232**

### Phase 5: Documentation

- [x] Update `README.md` — feature list, security notes
- [x] Update `ARCHITECTURE.md` — crypto section, service descriptions, extensibility
- [x] Update `PACKAGE_README.md` — feature list, notes
- [x] Update `tasks/todo.md`

## Review

Three refinements to the crypto layer:

1. **MultibaseCodec extraction**: Moved algorithm-agnostic `CanonicalizeDocument`, `Encode`, and `Decode` from `Ed25519Signer` to a new `MultibaseCodec` static class. Clean breaking change — no deprecated wrappers. All 9 core callers and test/example sites updated.

2. **Dynamic context URL**: Added `ContextUrl` to `ICryptoSuite`, `GetByKeyType` to `ICryptoSuiteProvider`, and `ResolveSuiteContextUrlAsync` to `ISigningService`. `CapabilityService` now resolves the correct JSON-LD security suite context URL from the signer's key type instead of hardcoding the Ed25519 URL.

3. **P-256 suite**: `P256CryptoSuite` implements `ICryptoSuite` for NIST P-256 using built-in `System.Security.Cryptography.ECDsa` — zero new NuGet dependencies. Includes `EcPointCompression` for compressed public key handling (decompression via P-256 curve equation, exploiting p ≡ 3 mod 4 for efficient square root). IEEE P1363 signature format (64 bytes). Registered by default in all providers and ASP.NET DI.

232 tests passing (29 new). Backward-compatible: parameterless constructors default to Ed25519 + P-256.

---

# Invocation Replay Protection via Nonce Store - 2026-02-22

## Motivation

`Invocation.Id` auto-generates a `urn:uuid:` on construction, but nothing validated uniqueness — a signed invocation could be replayed indefinitely. Additionally, `invocation.Id` was excluded from the signed canonical document, meaning an attacker could swap the ID to bypass nonce checking while keeping a valid signature.

## Plan

### Part 1: Nonce store abstraction

- [x] Create `INonceStore.cs` — single-method interface: `TryMarkAsUsedAsync` (atomic check-and-record)
- [x] Create `NullNonceStore.cs` — internal no-op for backward compatibility
- [x] Create `InMemoryNonceStore.cs` — `ConcurrentDictionary` + `TimeProvider` + periodic purge

### Part 2: Bind invocation ID to signature

- [x] Add `id = invocation.Id` to canonical document in `SigningService.SignInvocationAsync`
- [x] Add `id = invocation.Id` to canonical document in `VerificationService.VerifyInvocationAsync`

### Part 3: Integration

- [x] Add `INonceStore` + `TimeSpan _nonceWindow` fields to `VerificationService`
- [x] Add 5th constructor with nonce store; existing 4 chain with `NullNonceStore.Instance`
- [x] Add nonce check at end of `VerifyInvocationAsync` (after all validation passes)
- [x] Register `InMemoryNonceStore` in ASP.NET DI, add `AddZcapReplayProtection` extension methods

### Phase 4: Tests

- [x] `InMemoryNonceStoreTests.cs` — 8 tests (fresh, replay, expiry, concurrent, null input)
- [x] `NullNonceStoreTests.cs` — 1 test
- [x] `VerificationServiceReplayTests.cs` — 4 tests (replay rejected, different IDs, null store, invalid doesn't consume)

### Phase 5: Verify

- [x] Build solution — 0 errors
- [x] Run full test suite — **Failed: 0, Passed: 245, Total: 245**

## Review

Added invocation replay protection via pluggable `INonceStore`. The nonce store uses a single atomic `TryMarkAsUsedAsync` method to eliminate TOCTOU race conditions. `InMemoryNonceStore` uses `ConcurrentDictionary.TryAdd` for thread-safe atomic insert, with `TimeProvider` for testable time and periodic expired-entry purging. Backward-compatible: existing `VerificationService` constructors chain with `NullNonceStore.Instance` (no-op). Fixed security gap where `invocation.Id` was not included in the signed payload — it is now bound to the signature to prevent ID-swap attacks. ASP.NET DI registers `InMemoryNonceStore` by default with `AddZcapReplayProtection` extension methods for custom stores.

245 tests passing (13 new). Default nonce window: 5 minutes.
