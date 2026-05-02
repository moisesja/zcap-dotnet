# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0] - Unreleased

### Fixed

- Root capabilities and invocation proofs no longer emit empty/null optional fields on the wire (Issue #37). `allowedAction`, `caveat`, `parentCapability`, `expires`, `proof` (on root capabilities) and `capabilityChain` (on invocation proofs) are omitted when unset. Strict cross-language parsers (`zcap-py` and others) reject `"allowedAction": []` / `"capabilityChain": []` / `null` on optional fields when present, so emit-as-empty broke cross-stack interop. Companion to PR #34's flat-shape fix.

### Changed

- **BREAKING (wire format)**: `Capability.AllowedAction` and `Capability.Caveat` are now nullable (`string[]?` / `Caveat[]?`). Previously defaulted to `Array.Empty<>()`, producing `[]` on the wire. JCS canonical bytes change for any root capability, so signatures over the old shape no longer verify.
- **BREAKING (wire format)**: `Proof.CapabilityChain` is now nullable (`object[]?`) and omitted on invocation proofs, which spec-correctly carry no chain.
- All five optional `Capability` fields (`AllowedAction`, `Expires`, `ParentCapability`, `Caveat`, `Proof`), `Invocation.Proof`, and `Proof.CapabilityChain` carry `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`.
- `CapabilityService.CreateRootCapabilityAsync` no longer assigns `Array.Empty<>()` / `null` to optional fields — they stay unset.
- `CapabilityService.InheritCaveats` returns `Caveat[]?` and yields `null` when neither parent nor child supplies caveats, so delegations with no caveats also stay clean on the wire.
- `SigningService.SignInvocationAsync` no longer sets `CapabilityChain = Array.Empty<object>()` on invocation proofs.
- New `CrossLanguageJcsInteropTests` fixtures pin the new wire shape: root capability emits only `{@context, controller, id, invocationTarget}`, and invocation proofs no longer contain `"capabilityChain"`.

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
