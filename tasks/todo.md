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
