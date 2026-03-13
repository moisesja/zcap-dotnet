# ZCAP-LD Ecosystem Analysis

Research conducted March 2026. Covers all known ZCAP-LD implementations, related JS libraries, and feasibility of porting ZcapLd.Core to JavaScript/TypeScript.

## Existing Implementations

Only **3 implementations** of ZCAP-LD exist worldwide:

| Implementation | Language | Maintainer | Status | License |
|----------------|----------|-----------|--------|---------|
| `@digitalbazaar/zcap` | JavaScript | Digital Bazaar (spec authors) | Active (v9.0.0) | BSD-3-Clause |
| `ssi-zcap-ld` | Rust | SpruceID | Active (v0.8.x) | Apache-2.0 |
| `ZcapLd.Core` | .NET | This project | Active (v1.0.0) | - |

No Python, Go, or Java implementations exist.

---

## JavaScript Ecosystem (Digital Bazaar)

Digital Bazaar (the spec authors) maintain a family of packages around `@digitalbazaar/zcap`:

### Core Library

**`@digitalbazaar/zcap`** (v9.0.0) — The reference implementation.

- npm: `@digitalbazaar/zcap`
- GitHub: [digitalbazaar/zcap](https://github.com/digitalbazaar/zcap)
- 486 commits, ~29 stars
- Author: Dave Longley (CTO of Digital Bazaar, co-author of the ZCAP-LD spec)

**v9 breaking changes** (important for interoperability):
- `expires` is **required** on delegated capabilities and **prohibited** on root capabilities
- `invocationTarget` must be specified in invocation proofs
- Last delegated zcap in chain must be fully embedded; all others by ID reference

### Companion Packages

| Package | Purpose |
|---------|---------|
| `@digitalbazaar/ezcap` | High-level opinionated zcap client (browser + Node.js) |
| `@digitalbazaar/ezcap-express` | Express.js middleware for zcap-protected endpoints |
| `@digitalbazaar/http-signature-zcap-invoke` | HTTP Signature-based zcap invocation |
| `@digitalbazaar/http-signature-zcap-verify` | HTTP Signature-based zcap verification (Node 22+) |
| `@digitalbazaar/zcap-context` | JSON-LD context (`https://w3id.org/zcap/v1`) |

### Other JS Implementations (not recommended)

| Package | Status | Notes |
|---------|--------|-------|
| `@digitalcredentials/ezcap` | Active | MIT fork of ezcap by Digital Credentials Consortium |
| `jlinc-zcap` | Abandoned (2021) | Tied to JLINC's DID infrastructure |
| `ocapld` | Deprecated | Pre-rename of `@digitalbazaar/zcap` — 7 known vulnerabilities |

---

## Rust Ecosystem (SpruceID)

**`ssi-zcap-ld`** — Part of SpruceID's broader SSI (Self-Sovereign Identity) crate.

- Crate: [ssi-zcap-ld](https://crates.io/crates/ssi-zcap-ld) (v0.5.0 standalone / v0.8.x in parent)
- GitHub: [spruceid/ssi](https://github.com/spruceid/ssi) (251 stars, 76 forks)
- Security audit by Trail of Bits (March 2022)
- Supports: Ed25519, P-256, secp256k1, did:key, did:jwk, did:web, did:pkh

**`cacao-zcap-rs`** — Bridges CAIP-74 Chain-Agnostic Capability Objects (CACAO) with ZCAP-LD. Enables SIWE (Sign-In With Ethereum) messages in zcap delegation chains.

---

## Related: UCAN (Alternative Object-Capability Approach)

UCAN (User Controlled Authorization Network) shares the same object-capability security model but uses JWTs instead of JSON-LD, addresses by CID instead of URL, and is not directly compatible with ZCAP-LD.

- **`ucanto`** — UCAN RPC framework by Storacha (formerly web3.storage). Production-proven. TypeScript-first.

---

## Feature Comparison: ZcapLd.Core vs @digitalbazaar/zcap

| Feature | `ZcapLd.Core` v1.0.0 | `@digitalbazaar/zcap` v9 |
|---------|----------------------|--------------------------|
| Root capabilities | Yes | Yes |
| Delegation chains | Yes | Yes |
| Invocation | Yes | Yes |
| Chain verification | Yes (depth limit enforced) | Yes |
| Caveat processing | Yes (expiration, usage count, ValidWhileTrue) | Partial (expires, allowedAction) |
| **Revocation** | **Built-in** (`IRevocationService`, `IRevocationStore`) | External (via `ezcap-express`) |
| **Replay protection** | **Built-in** (`INonceStore`) | Not built-in |
| Canonicalization | RFC 8785 JCS | Full URDNA2015 / RDFC-1.0 |
| Crypto suites | Built-in Ed25519 + P-256 | Suite-agnostic (pluggable via `jsonld-signatures`) |
| DID resolution | `DidKeyResolver` (NetDid adapter) | Via document loaders (consumer-provided) |
| `expires` on root caps | Allowed | Prohibited (v9 breaking) |
| ASP.NET / Express integration | `ZcapLd.AspNetCore` | `ezcap-express` |
| Dependency weight | Lighter (NSec, NetDid) | Heavy (`jsonld`, `rdf-canonize`, `jsonld-signatures`) |

**Key differentiators for ZcapLd.Core:**
1. Built-in revocation with pluggable persistence
2. Built-in replay protection via nonce store
3. Richer caveat system (ValidWhileTrue with remote checking)
4. Lighter dependency footprint

**Key differentiators for @digitalbazaar/zcap:**
1. Full RDFC-1.0 canonicalization (spec-normative)
2. Written by the spec authors
3. Suite-agnostic architecture
4. Broader ecosystem of companion packages

---

## JavaScript Port Feasibility

### Library Surface Area

ZcapLd.Core is ~3,500 LOC across 42 files:

| Directory | Lines | Files | Description |
|-----------|-------|-------|-------------|
| Services/ | ~1,400 | 15 | Core interfaces and implementations |
| Models/ | ~350 | 8 | Capability, Proof, Invocation, Caveat, etc. |
| Cryptography/ | ~1,200 | 13 | Suites, signers, canonicalizer, multibase |
| Exceptions/ | ~60 | 1 | Custom exception hierarchy |

### Public API Summary

**Interfaces:** 10 (ICapabilityService, ISigningService, IVerificationService, IDidResolver, IDidSigner, ICaveatProcessor, IRevocationService, IRevocationStore, INonceStore, IValidWhileTrueHandler)

**Models:** 9 classes (Capability, Proof, Invocation, Caveat + 3 subtypes, InvocationContext, ResolvedKey, SignatureResult, RevocationRecord, RevocationRequest)

**Crypto types:** 7 public classes/interfaces (ICryptoSuite, ICryptoSuiteProvider, CryptoSuiteProvider, Ed25519CryptoSuite, P256CryptoSuite, Ed25519Signer, SignatureVerifier, JsonCanonicalizer, MultibaseCodec)

### Recommended JS/TS Dependencies

| Concern | Package | Why |
|---------|---------|-----|
| Ed25519 + P-256 signing | `@noble/curves` | Zero deps, 6 audits, MIT, covers both curves |
| JSON canonicalization | `canonicalize` | RFC 8785 (matches our approach) |
| Multibase / multicodec | `multiformats` | Standard ecosystem package |
| did:key resolution | `key-did-resolver` | Supports Ed25519, P-256, secp256k1 |
| DID resolution framework | `did-resolver` (DIF) | 522 dependents, method-agnostic |
| TypeScript | Required | Preserves strict type contracts |

### .NET Features Requiring JS Equivalents

| .NET Feature | JS Equivalent | Difficulty |
|--------------|--------------|------------|
| `async/await` + `Task<T>` | `async/await` + `Promise<T>` | Easy |
| `ConcurrentDictionary` | `Map` (JS is single-threaded) | Easy |
| `CancellationToken` | `AbortController` / `AbortSignal` | Easy |
| `record` types | TypeScript `readonly` classes/interfaces | Easy |
| `[JsonPropertyName]` | Custom serialization or class-transformer | Easy |
| `System.Security.Cryptography.ECDsa` | `@noble/curves` P-256 | Medium |
| NSec.Cryptography (Ed25519) | `@noble/curves` Ed25519 | Medium |
| `BigInteger` (EC point decompression) | `@noble/curves` handles internally | Medium |
| `DateTime` | `Date` or `temporal` (Stage 3) | Easy |
| `TimeProvider` (testability) | DI of clock function | Easy |

### Port Strategy Options

#### Option A: Build on `@digitalbazaar/zcap`

Use the reference implementation and add revocation/replay/caveat features on top.

**Pros:** Spec compliance via the canonical impl, RDFC-1.0 canonicalization included.
**Cons:** Heavy dependency tree (`jsonld` ~500KB, `rdf-canonize`), tied to Digital Bazaar's architecture, different design philosophy.

#### Option B: Standalone TypeScript port (recommended)

Port ZcapLd.Core's architecture directly to TypeScript with lightweight dependencies.

**Pros:** Same architecture across .NET and JS, lighter dependencies (~50KB total vs ~500KB+), full control, differentiates from Digital Bazaar with built-in revocation/replay.
**Cons:** More upfront work, must maintain spec compliance independently.

### Effort Estimate (Option B)

| Category | Difficulty | Est. Effort |
|----------|-----------|-------------|
| Models + exceptions | Easy | 2-3 days |
| Crypto suites (Ed25519 + P-256) | Medium | 3-4 days |
| Core services (capability, signing, verification) | Medium | 4-5 days |
| Caveat processing | Easy | 1-2 days |
| Revocation + replay protection | Easy | 2-3 days |
| DID resolution (did:key adapter) | Easy | 1-2 days |
| Test port (276+ tests) | Medium | 3-4 days |
| Package setup, CI, docs | Easy | 1-2 days |
| **Total** | **Medium** | **~3 weeks** |

---

## Conclusion

ZcapLd.Core occupies a unique position: it is one of only 3 ZCAP-LD implementations in existence, and the only one with built-in revocation and replay protection. A TypeScript port using `@noble/curves` + `canonicalize` + `multiformats` would fill a gap in the JS ecosystem where the only alternative is Digital Bazaar's heavier, more opinionated reference implementation.
