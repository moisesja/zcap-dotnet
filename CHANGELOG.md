# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0] - Unreleased

### Added

- `controller` may now be a single URI string **or** an array of URI strings on both root and delegated zcaps, per W3C ZCAP-LD v0.3 (Issue #47). Authorization succeeds when a proof's verification method matches **any** controller in the set.
- `ControllerSet` (in `ZcapLd.Core.Models`) — immutable value type modeling one or many controllers. Exposes `Values`, `Count`, `IsEmpty`, `IsArrayForm`, `Primary`, `Contains`, and `ContainsVerificationMethod`. Implicit conversions from `string` and `string[]` keep single-controller call sites ergonomic (`Controller = "did:..."` still compiles). Carries a `[JsonConverter]` that **preserves the on-wire shape** (a single controller stays a bare string; an array stays an array, even a single-element one) so JCS canonical bytes round-trip byte-stably for cross-language verifiers.
- `ControllerSetJsonConverter` (internal) — reads/writes both wire shapes and rejects malformed controller values (empty array, non-string entry, empty/whitespace string) with `JsonException`.
- `CapabilityService.DelegateCapabilityAsync` gains an optional `signerDid` parameter so any one of a multi-controller parent's controllers can sign the delegation (defaults to the parent's first controller; validated against the parent's controller set).
- A delegated zcap's `proof` may now be a single DI proof object **or** an array of proof objects, per W3C ZCAP-LD v0.3 (Issue #48). Verification succeeds when **at least one** proof is a valid, parent-authorized `capabilityDelegation` proof; non-delegation proofs are ignored and a delegation proof that fails to verify does not abort evaluation of the others.
- `ProofSet` (in `ZcapLd.Core.Models`) — immutable value type modeling one or many proofs. Exposes `Values`, `Count`, `IsArrayForm`, `Primary`, `DelegationProofs()`, `FirstDelegationProof()`, and `FirstDelegationProofWithChain()`. Implicit conversions from a single `Proof` or a `Proof[]` keep call sites ergonomic (`capability.Proof = signedProof;` and `capability.Proof = new[] { a, b };` both compile). Carries a `[JsonConverter]` that **preserves the on-wire shape** (a single proof stays a bare object; an array stays an array).
- `ProofSetJsonConverter` (internal) — reads/writes both wire shapes and rejects an empty proof array / non-object entry with `JsonException`. Each `Proof` round-trips through normal STJ, so `[JsonExtensionData]` (e.g. `domain`, `nonce`) is preserved.
- `IVerificationService.RevokeCapabilityAsync(Capability, string)` — an authorizing revocation overload (Issue #60). It **cryptographically verifies** the delegation chain before checking authorization, then confirms the revoker controls the capability or any ancestor in its delegation chain (an up-chain delegator). Returns `false` (recording nothing) when the revoker is not authorized or the chain fails verification. `revokerDid` is a DID the host has already authenticated — the library performs authorization, not authentication.

### Changed

- **BREAKING (API)**: `Capability.Proof` changes type from `Proof?` to `ProofSet?`. Reads that treated it as a single proof need `.Primary` (or `.FirstDelegationProof()`); assigning a single `Proof` continues to compile via implicit conversion. The signing APIs still produce a single proof by default, so single-proof capabilities are unchanged on the wire (`proof` stays a bare object — no one-element-array wrap).
- **BREAKING (API)**: `Capability.Controller` changes type from `string` to `ControllerSet`. Reads that previously treated it as a string need `.Primary` (the single/first controller) or `.Values`; assignments from a `string` or `string[]` continue to compile via implicit conversion. `ICapabilityService.CreateRootCapabilityAsync` / `DelegateCapabilityAsync` now take `ControllerSet` (string callers unaffected).
- Single-controller capabilities are unchanged on the wire — `controller` still serializes as a bare string, so existing signatures and pinned JCS bytes are preserved.
- New `CrossLanguageJcsInteropTests` pins lock the multi-controller shape: an array-form `controller` produces sign-time bytes byte-equal to what a peer verifier JCS-canonicalizes over the array-shaped wire body, and a single controller still emits a bare string (no one-element-array collapse).
- Dependency updates: `NetDid.Core` / `NetDid.Method.Key` 1.1.2 → 1.3.0, `Microsoft.SourceLink.GitHub` 10.0.201 → 10.0.300. Test/example tooling: `Microsoft.NET.Test.Sdk` 18.4.0 → 18.6.0, `FluentAssertions` 8.9.0 → 8.10.0, `coverlet.collector` 6.0.0 → 10.0.1, `Microsoft.Data.Sqlite` 10.0.6 → 10.0.8.
- P-256 signing/verification now explicitly requests IEEE P1363 from NetDid's format-aware overloads (`EcdsaSignatureFormat.IeeeP1363`). NetDid 1.3.0 changed the _default_ of its legacy ECDSA `Sign`/`Verify` overloads from P1363 to ASN.1 DER; the W3C `ecdsa-2019` / `EcdsaSecp256r1Signature2019` wire format requires P1363 (fixed-width `r‖s`, 64 bytes for P-256), so `CryptoSuite` pins the format to keep `proofValue` interoperable with peer Data Integrity stacks. Ed25519 (the default suite) is unaffected. Regression-guarded by `CryptoSuiteTests.P256_Sign_ProducesIeeeP1363WireFormat_NotDer`.

### Fixed

- `ICapabilityService.CreateRootCapabilityAsync` no longer forces callers to pass an `allowedActions` array the implementation discards (Issue #66). The interface declared `string[] allowedActions` (required) while the implementation declared `string[]? allowedActions = null` and never reads it for roots (roots carry no `allowedAction` per spec), so a consumer bound to the interface had to pass a throwaway value to express "no enumerated actions". The interface signature now matches the implementation (`string[]? allowedActions = null`) and documents that the parameter is ignored for roots. Non-breaking: callers passing an array still compile. (Companion `expires`/`caveats` documentation is Issue #72.)
- Confirmed and regression-pinned the array-`controller` fix for Issue #65 (M8). The empirically-confirmed defect — a spec-permitted array `controller` threw `JsonException` on deserialize under the old single-`string` model, and authorization was string-equality only — is resolved by the `ControllerSet` work (Issue #47): array controllers round-trip and authorization succeeds for any controller in the set. Added an end-to-end regression (`MultiControllerAuthorizationTests.RootInvocation_OverDeserializedArrayController_AuthorizesAnyController`) that deserializes an array-`controller` capability from JSON and authorizes an invocation signed by the second controller. Documented the remaining known limitation on `IsControllerAuthorized`: authorization is at DID-string granularity and does not resolve the controller's DID *document* to confirm the verification relationship for non-`did:key` controllers (controller DID ≠ verification-method DID) — that enhancement requires extending `IDidResolver` and is tracked as the remaining, architectural part of #65. No forgery is enabled, as the signature is always verified independently.
- `VerificationService` no longer silently discards the cause when it fails closed (Issue #64). All three public verify methods wrapped their body in a bare `catch { return false; }`, so a transient or configuration fault (a missing canonicalizer registration, an unsupported proof type, a DID-resolution network error) was reported identically to a tampered capability, with no logging anywhere in `ZcapLd.Core` — a misconfiguration silently denied **all** valid capabilities. The verifier now accepts an optional `ILogger<VerificationService>` (defaults to `NullLogger`) and the catch blocks `catch (Exception ex)` and log a warning with the cause before returning false (fail-closed is preserved). `ZcapLd.AspNetCore`'s `AddZcapServices` wires the container's logger. Adds a lightweight `Microsoft.Extensions.Logging.Abstractions` dependency to `ZcapLd.Core`. (A structured result/typed-exception channel — distinguishing "invalid" from "couldn't check" — remains tracked as #70.)
- `VerificationService.VerifyCapabilityProofAsync` now honours **ancestor** revocation, not just the leaf's (Issue #63). It checked only `capability.Id` for revocation and ignored the immediate parent embedded in `proof.capabilityChain[^1]`, so a capability whose parent had been revoked still passed the single-proof check — an incoherence with `VerifyCapabilityChainAsync`, which checks revocation for every link. The shared single-delegation-proof verifier now also rejects a proof whose resolved parent (embedded in the chain, or the chain-walk parent) has been revoked, so both the standalone proof check and chain verification honour ancestor revocation. Regression-guarded by `VerificationServiceTests.VerifyCapabilityProof_WithRevokedImmediateParent_ShouldReturnFalse`.
- Replay protection is now ON by default in the convenience `VerificationService` constructors (Issue #62). The 2-, 3-, and 4-argument constructors previously funnelled to `NullNonceStore.Instance`, whose `TryMarkAsUsedAsync` always reports "not seen", so the documented `new VerificationService(resolver, caveatProcessor)` path (the README Quick Start) gave **zero** replay protection — a captured valid invocation could be replayed indefinitely. The convenience constructors now default to `new InMemoryNonceStore()`; `NullNonceStore` is reachable only by deliberately passing it to the explicit `INonceStore` constructor. `InMemoryNonceStore` is process-local — supply a shared store for multi-node verifiers (documented on the constructor and in the README). Regression-guarded by `VerificationServiceReplayTests.VerifyInvocation_TwoArgConstructor_RejectsReplayByDefault`.
- Delegating a capability with an expiration more than three months out no longer throws at create time (Issue #61). The W3C ZCAP-LD 3-month expiration ceiling is a **verifier-side SHOULD measured at invocation time**, not a create-time MUST — but `CapabilityService.DelegateCapabilityAsync` enforced it as an unconditional hard `throw` inside `ValidateAttenuation`, blocking even the construction of a legitimately long-lived delegation the parent permits, with no opt-out (the limit was a non-configurable `const`). The create-time throw (and the now-unused `MaxExpirationMonths` const) are removed; attenuation (child ≤ parent expiry) is still enforced. The ceiling moves to the verify path behind a policy flag (Issue #73). The misnamed `SHOULD-04` compliance test (named a *verifier* test but driving `DelegateCapabilityAsync`) now asserts that long-lived delegation succeeds at create time.
- Closed an unauthenticated denial-of-capability gap in revocation (Issue #60). `RevokeCapabilityAsync(string capabilityId, string revokerDid)` performed **no** authorization — it stored the revocation and unconditionally returned `true`, so any caller could revoke anyone's capability (a stored revocation immediately flips `VerifyCapabilityChainAsync`/`VerifyInvocationAsync` to `false`). The bare-string overload is now documented explicitly as performing no authorization (the `revokerDid` is audit attribution only; the host must authorize before calling), and the misleading "True if revocation was successful" XML doc is corrected. A new authorizing overload `RevokeCapabilityAsync(Capability, string)` checks the revoker against the capability's delegation chain and returns `false` (recording nothing) when unauthorized — making a `false` return reachable and meaningful. (The `ZcapLd.AspNetCore` revocation endpoint still accepts a bare `revokerDid`; binding it to a signed revocation invocation is tracked separately.)
- `CapabilityService.ValidateCapabilityAsync` no longer rejects capabilities whose `allowedAction` contains values other than `read`/`write` (Issue #59). ZCAP-LD treats actions as an application-defined vocabulary — `read`/`write` are illustrative examples, not a closed allow-list — so the previous hard-coded check declared spec-conformant capabilities invalid, including ones this library mints (e.g. `delete`, `admin`, `share`) and cryptographically verifies via `VerifyCapabilityChainAsync`. The closed allow-list block is removed; the real constraints remain enforced elsewhere (attenuation child ⊆ parent at delegation/chain verification, and membership in `allowedAction` at invocation time). A deployment that genuinely wants vocabulary restriction should layer it as an injected policy. The `SHOULD-05` compliance test now asserts a custom action validates.
- `VerificationService.VerifyInvocationAsync` no longer rejects every invocation received as JSON (Issue #58). `Proof.Capability` is typed `object?`; after `System.Text.Json` deserialization it is a `JsonElement` (not a CLR `string`), so the proof/invocation consistency check read it with an `as string` cast that always yielded `null`, failing the check and rejecting all wire invocations — the canonical resource-server flow (receive JSON → deserialize → verify). It only ever passed in-process, where `SigningService` assigns a CLR `string`. The check now normalizes `Proof.Capability` via the existing `TryExtractStringValue` helper (handles both boxed `string` and `JsonElement` of kind `String`). Regression-guarded by `VerificationServiceTests.VerifyInvocation_AfterJsonRoundTrip_ShouldReturnTrue`.
- `CapabilityService.ValidateCapabilityAsync` now rejects root zcaps that carry any field outside the permitted set (Issue #49). Per W3C CCG ZCAP-LD v0.3, a root zcap contains exactly `@context`, `id`, `controller`, and `invocationTarget`, and "MUST NOT have any other fields." Root validation previously rejected only `proof`, `expires`, and `parentCapability`, so an externally-supplied root carrying `allowedAction`, `caveat`, or unknown extension fields (captured in `AdditionalProperties` via `[JsonExtensionData]`) passed validation. The root branch now also rejects non-null `AllowedAction`/`Caveat` and a non-empty `AdditionalProperties`; these must be absent (not empty), matching the strict shape `CreateRootCapabilityAsync` already emits. Delegated zcaps, which legitimately carry these fields, are unaffected.
- Concrete `Caveat` subclasses no longer emit duplicate `"Type"` / `"type"` keys on the wire (Issue #45). STJ on .NET 10 doesn't auto-inherit `[JsonPropertyName("type")]` from the abstract base override declaration; without an explicit attribute on the override, the runtime catalogues the override as a separate `JsonPropertyInfo` and emits the CLR name `"Type"` alongside the inherited `"type"`. Both keys landed on the wire, JCS preserved them both, and signature verification failed against any other Data Integrity implementation. Fix: re-apply `[JsonPropertyName("type")]` on `ExpirationCaveat`, `UsageCountCaveat`, and `ValidWhileTrueCaveat` overrides. Fourth and final layer of the cross-stack canonicalization contract from #34 / #36 / #37 / #39.

## [2.1.0] - Released

### Fixed

- Root capabilities and invocation proofs no longer emit empty/null optional fields on the wire (Issue #37). `allowedAction`, `caveat`, `parentCapability`, `expires`, `proof` (on root capabilities) and `capabilityChain` (on invocation proofs) are omitted when unset. Strict cross-language parsers (`zcap-py` and others) reject `"allowedAction": []` / `"capabilityChain": []` / `null` on optional fields when present, so emit-as-empty broke cross-stack interop. Companion to PR #34's flat-shape fix.
- `Caveat[]` polymorphic serialization preserves derived-class fields across the signing boundary (Issue #39). Previously, STJ used the static array element type for `Capability.Caveat`, silently dropping derived fields like `Expires`, `Uri`, or third-party budget counters at sign time. Sign-time JCS now produces byte-identical bytes to whatever a cross-language verifier (`zcap-py` and friends) computes over the wire body re-emitted via the runtime concrete type.

### Added

- `CaveatTypeRegistry` (in `ZcapLd.Core.Models`) with a `Default` singleton pre-populated with the in-library caveat types. Third-party caveat libraries register their derived types via `CaveatTypeRegistry.Default.Register<T>(discriminator)` so the polymorphic JSON converter can dispatch deserialization across packages.
- `ZcapJsonOptions.Default` (in `ZcapLd.Core.Cryptography`) — single source of truth for the `JsonSerializerOptions` shared by sign-time canonicalization and verifier-time chain deserialization (RFC 8785-compatible escaping, `WhenWritingNull`, the caveat converter).
- `AddZcapCaveatType<TCaveat>(string discriminator)` ASP.NET DI extension on `IServiceCollection`, mirroring the `AddZcapCryptoSuite<T>()` shape.
- `CaveatJsonConverter` — internal `JsonConverter<Caveat>` wired into `ZcapJsonOptions.Default`. `Write` dispatches to the runtime concrete type so derived fields are emitted; `Read` resolves the `type` discriminator against `CaveatTypeRegistry.Default` and deserializes via reflection, throwing `JsonException` with a registry-friendly hint when the discriminator is unknown.

### Changed

- **BREAKING (wire format)**: `Capability.AllowedAction` and `Capability.Caveat` are now nullable (`string[]?` / `Caveat[]?`). Previously defaulted to `Array.Empty<>()`, producing `[]` on the wire. JCS canonical bytes change for any root capability, so signatures over the old shape no longer verify.
- **BREAKING (wire format)**: `Proof.CapabilityChain` is now nullable (`object[]?`) and omitted on invocation proofs, which spec-correctly carry no chain.
- **BREAKING (wire format)**: capabilities with non-empty caveats now sign over the full caveat shape (including derived-class fields), not the discriminator-only stub. Signatures over the old shape no longer verify.
- **BREAKING (semantics)**: `UsageCountCaveat.CurrentUses` is now `[JsonIgnore]`. It's runtime state, not the signed policy — including it in the canonical bytes would invalidate the signature on every increment. Only `MaxUses` (the policy) is part of the wire body now.
- All five optional `Capability` fields (`AllowedAction`, `Expires`, `ParentCapability`, `Caveat`, `Proof`), `Invocation.Proof`, and `Proof.CapabilityChain` carry `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`.
- `CapabilityService.CreateRootCapabilityAsync` no longer assigns `Array.Empty<>()` / `null` to optional fields — they stay unset.
- `CapabilityService.InheritCaveats` returns `Caveat[]?` and yields `null` when neither parent nor child supplies caveats, so delegations with no caveats also stay clean on the wire.
- `SigningService.SignInvocationAsync` no longer sets `CapabilityChain = Array.Empty<object>()` on invocation proofs.
- `ProofSigningPayloadBuilder.ModelSerializerOptions` now resolves to `ZcapJsonOptions.Default`; `VerificationService` chain deserialization uses the same options. Sign-time and verifier-time JSON paths share one configuration.
- New `CrossLanguageJcsInteropTests` fixtures pin the new wire shape: root capability emits only `{@context, controller, id, invocationTarget}`; invocation proofs no longer contain `"capabilityChain"`; capabilities with `ExpirationCaveat` / `ValidWhileTrueCaveat` produce sign-time bytes byte-equal to whatever a cross-language verifier JCS-canonicalizes over the wire body.

## [1.2.0] - Released

### Added

- RDFC-1.0 (W3C RDF Dataset Canonicalization) support via dotNetRdf.Core v3.5.1 (Issue #29)
- `IDocumentCanonicalizer` interface for pluggable canonicalization methods
- `JcsDocumentCanonicalizer` (RFC 8785 JSON Canonicalization Scheme)
- `RdfcDocumentCanonicalizer` (RDFC-1.0 via dotNetRdf: JSON-LD → N-Quads)
- `IDocumentCanonicalizerProvider` / `DocumentCanonicalizerProvider` registry
- `ICryptoSuite.CanonicalizationMethod` default interface method (returns `"JCS"` for backward compatibility)
- `AddZcapRdfcCanonicalization()` ASP.NET Core DI extension to enable RDFC-1.0
- 24 new tests for canonicalization abstractions and RDFC-1.0 integration

### Changed

- `ProofSigningPayloadBuilder` supports suite-specific canonicalization: JCS (combined object) or RDFC-1.0 (separate document + proof options, SHA-256 hash concatenation per W3C Data Integrity spec)
- `SigningService` and `VerificationService` accept `IDocumentCanonicalizerProvider` to resolve per-suite canonicalizer
- `SignatureVerifier` accepts optional `IDocumentCanonicalizer` parameter
- `MultibaseCodec.CanonicalizeDocument()` removed (replaced by `IDocumentCanonicalizer`)

## [1.1.0] - Released

### Changed

- Replaced `Ed25519CryptoSuite`, `P256CryptoSuite`, `Ed25519Signer`, and `EcPointCompression` with single parameterized `CryptoSuite` class delegating to NetDid's `DefaultCryptoProvider` (Issue #23)
- `CryptoSuite.Ed25519()` and `CryptoSuite.P256()` static factory methods replace individual suite classes

### Removed

- `Ed25519Signer` static class (replaced by `DefaultCryptoProvider`)
- `EcPointCompression` internal class (replaced by NetDid's `DecompressEcPoint`)
- `Ed25519CryptoSuite` class (replaced by `CryptoSuite.Ed25519()`)
- `P256CryptoSuite` class (replaced by `CryptoSuite.P256()`)
- Direct `NSec.Cryptography` dependency (now transitive via NetDid.Core)

## [1.0.0] - Released

### Added

- DID resolution via [NetDid](https://www.nuget.org/packages/NetDid.Core) packages (`NetDid.Core`, `NetDid.Method.Key`)
- `DidKeyResolver` as adapter over NetDid's `DidKeyMethod`
- `MultibaseCodec` delegates to `NetCid.Multibase` (replaces `SimpleBase`)
- 12 new NetDid integration tests

### Removed

- `SimpleBase` dependency (replaced by NetCid transitive from NetDid)
- `ICryptoSuite.MulticodecPrefix` property (multicodec handled by NetDid)
- `ICryptoSuite.PublicKeyLength` property (unused in production)
- `ICryptoSuiteProvider.GetByMulticodecPrefix()` method (multicodec handled by NetDid)

### Changed

- `DidKeyResolver` no longer takes `ICryptoSuiteProvider` constructor parameter (**breaking**)
- `CryptoSuiteProvider` simplified: replaced `List<ICryptoSuite>` + lock with `ConcurrentDictionary` for key type lookup

## [0.3.3] - 2026-03-03

### Changed

- `InvocationContext` property injection (Issue #15)
- Updated GitHub Actions checkout to v6

## [0.3.2] - 2026-02-28

### Fixed

- `Context` property JSON deserialization (`object` typed properties become `JsonElement` after ASP.NET round-trip)

## [0.3.1] - 2026-02-28

### Fixed

- `Proof.CapabilityChain` JSON deserialization causing signature verification failures over HTTP (null fields in `JsonElement` bypass `WhenWritingNull` serialization option)

## [0.3.0] - 2026-02-28

### Changed

- Enhanced revocation processing and validation

## [0.2.1] - 2026-02-26

### Fixed

- Patch fixes

## [0.2.0] - 2026-02-24

### Changed

- Version stabilization

## [0.1.1] - 2026-02-23

### Added

- Revocation framework: `IRevocationService`, `IRevocationStore`, `InMemoryRevocationStore`
- ASP.NET revocation endpoints (`AddZcapRevocationSupport()`, `MapZcapRevocationEndpoints()`)
- ValidWhileTrue caveat support with `IValidWhileTrueHandler` interface
- `HttpValidWhileTrueHandler` in `ZcapLd.AspNetCore`

## [0.1.0] - 2026-02-20

### Added

- Initial release
- Capability creation, delegation, and chain verification
- Invocation signing and verification
- Caveat processing (expiration, usage count)
- Ed25519 and P-256 crypto suites via `ICryptoSuite` / `ICryptoSuiteProvider`
- Replay protection via `INonceStore` (`InMemoryNonceStore`, `NullNonceStore`)
- DID resolution via `DidKeyResolver` with `did:key` support
- ASP.NET Core integration package (`ZcapLd.AspNetCore`)
- 245 tests, security compliance audit
