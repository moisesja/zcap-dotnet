# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
