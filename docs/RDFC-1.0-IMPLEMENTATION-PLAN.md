# Add RDFC-1.0 Canonicalization Support (Suite-Specific)

Status: **Implemented** (v1.2.0, Issue #29)

## Context

ZcapLd.Core currently uses RFC 8785 JCS for all canonicalization. The W3C ZCAP-LD spec delegates to Data Integrity cryptosuites, which determine the canonicalization method:
- `Ed25519Signature2020`, `eddsa-rdfc-2022` → **RDFC-1.0** (spec-normative)
- `eddsa-jcs-2022` → **JCS** (what we have)

Goal: support both methods, selected per crypto suite. Existing suites keep JCS (backward compatible). New suites can use RDFC-1.0.

### Background: What is RDFC-1.0?

RDFC-1.0 (RDF Dataset Canonicalization 1.0, formerly URDNA2015) is a W3C standard that produces a deterministic serialization of JSON-LD documents by:

1. Expanding JSON-LD to RDF quads (resolving `@context`, compact IRIs)
2. Canonicalizing blank node identifiers deterministically
3. Sorting quads lexicographically
4. Outputting N-Quads — a unique byte representation regardless of input formatting

Unlike JCS (which only sorts JSON keys), RDFC-1.0 **understands JSON-LD semantics**. This means proofs signed with RDFC-1.0 can be verified by any implementation that supports the same cryptosuite (e.g., Digital Bazaar's `@digitalbazaar/zcap`), enabling cross-implementation interoperability.

### .NET Library Landscape

| Library | RDFC-1.0 | JSON-LD | W3C Conformance | Maintained | Dependencies |
|---------|----------|---------|-----------------|------------|-------------|
| **dotNetRdf.Core** v3.5.1 | Yes (Nov 2023 draft) | Yes (1.1) | NOT TESTED | Yes (Feb 2026) | Heavy (~1MB) |
| json-ld.net | Unclear | Yes (1.0 only) | NOT TESTED | No (Mar 2022) | Light |
| JsonLd.Normalization | URDNA2015 only | Partial | NOT TESTED | No (Mar 2023) | Light |
| From scratch | Full | No | Can target 86/86 | You own it | Zero |

**No .NET library has passed the W3C RDFC-1.0 conformance test suite** (86 test cases). The W3C conformance report lists 11 implementations (Java, Python, C++, JavaScript, Rust, Elixir, TypeScript, Ruby) but no C#/.NET.

## Key Design Decisions

1. **dotNetRdf.Core** (v3.5.1, MIT) provides JSON-LD 1.1 + RDFC-1.0. Added to ZcapLd.Core for now.
2. **`IDocumentCanonicalizer`** interface with two implementations: `JcsDocumentCanonicalizer`, `RdfcDocumentCanonicalizer`.
3. **`ICryptoSuite.CanonicalizationMethod`** — default interface method returning `"JCS"`. New RDFC-1.0 suites override to `"RDFC-1.0"`.
4. **Payload construction differs per method:**
   - JCS: combines document + proof into single anonymous object, canonicalizes once (current behavior)
   - RDFC-1.0: canonicalizes document and proof options separately, concatenates canonical forms (per W3C Data Integrity spec)
5. Backward-compatible constructors on `SigningService` and `VerificationService` default to JCS-only.

## Implementation Steps

### Phase 1 — New abstractions (no behavior change)

**New files:**

| File | Description |
|------|-------------|
| `src/ZcapLd.Core/Cryptography/IDocumentCanonicalizer.cs` | Interface: `string Method`, `byte[] Canonicalize(object document)` |
| `src/ZcapLd.Core/Cryptography/JcsDocumentCanonicalizer.cs` | Wraps existing `JsonCanonicalizer.Canonicalize()` |
| `src/ZcapLd.Core/Cryptography/RdfcDocumentCanonicalizer.cs` | Uses dotNetRdf: JSON-LD parse → `RdfCanonicalizer` → N-Quads bytes |
| `src/ZcapLd.Core/Cryptography/IDocumentCanonicalizerProvider.cs` | Interface: `IDocumentCanonicalizer GetByMethod(string method)` |
| `src/ZcapLd.Core/Cryptography/DocumentCanonicalizerProvider.cs` | Dictionary-backed registry |

**Modify:**
- `src/ZcapLd.Core/Cryptography/ICryptoSuite.cs` — Add `string CanonicalizationMethod => "JCS"` (default interface method; Ed25519CryptoSuite and P256CryptoSuite unchanged)
- `src/ZcapLd.Core/ZcapLd.Core.csproj` — Add `<PackageReference Include="dotNetRdf.Core" Version="3.5.1" />`

### Phase 2 — Wire through the pipeline

**Modify `ProofSigningPayloadBuilder.cs`:**
- Add `IDocumentCanonicalizer` parameter to `CanonicalizeCapabilityPayload()` and `CanonicalizeInvocationPayload()`
- For `method == "JCS"`: current behavior (combined anonymous object → canonicalize)
- For `method == "RDFC-1.0"`: canonicalize document and proof options separately, concatenate canonical bytes
- Replace `MultibaseCodec.CanonicalizeDocument(payload)` with `canonicalizer.Canonicalize(...)` calls

**Modify `SigningService.cs`:**
- Add `IDocumentCanonicalizerProvider` field
- New full constructor: `(IDidSigner, IDidResolver, ICryptoSuiteProvider, IDocumentCanonicalizerProvider)`
- Backward-compatible constructors default to JCS-only provider
- In `SignCapabilityAsync` / `SignInvocationAsync`: resolve canonicalizer from suite, pass to payload builder

**Modify `VerificationService.cs`:**
- Add `IDocumentCanonicalizerProvider` field
- New full constructor adds `IDocumentCanonicalizerProvider` parameter
- Backward-compatible constructors (5 existing) chain through to full constructor with JCS-only default
- In `VerifyDelegationProofAsync` / `VerifyInvocationAsync`: resolve canonicalizer from suite, pass to payload builder

**Modify `MultibaseCodec.cs`:**
- Remove `CanonicalizeDocument()` method (was a pass-through to JCS, only called from `ProofSigningPayloadBuilder` which now uses `IDocumentCanonicalizer`)

**Modify `SignatureVerifier.cs`** (test utility):
- Add optional `IDocumentCanonicalizer?` parameter, default to `JcsDocumentCanonicalizer`

**Modify `Ed25519Signer.cs`:**
- Update `SignJson` / `VerifyJson` convenience methods to use `JcsDocumentCanonicalizer` directly instead of `MultibaseCodec.CanonicalizeDocument`

### Phase 3 — DI wiring

**Modify `ZcapRevocationServiceCollectionExtensions.cs`:**
- Register `JcsDocumentCanonicalizer` as `IDocumentCanonicalizer` (TryAddEnumerable)
- Build `IDocumentCanonicalizerProvider` from all registered `IDocumentCanonicalizer` instances
- Update `SigningService` and `VerificationService` factories to pass `IDocumentCanonicalizerProvider`
- Add `AddZcapRdfcCanonicalization()` extension to register `RdfcDocumentCanonicalizer`

### Phase 4 — Tests

**New test files:**

| File | Tests |
|------|-------|
| `tests/.../Cryptography/JcsDocumentCanonicalizerTests.cs` | Delegates to JsonCanonicalizer, deterministic output |
| `tests/.../Cryptography/RdfcDocumentCanonicalizerTests.cs` | JSON-LD with @context canonicalizes to N-Quads, determinism, error handling |
| `tests/.../Cryptography/DocumentCanonicalizerProviderTests.cs` | Registration, lookup, unknown method throws |
| `tests/.../Cryptography/RdfcComplianceTests.cs` | 3-5 W3C RDFC-1.0 test vectors (smoke tests) |
| `tests/.../Integration/RdfcCanonicalizeIntegrationTests.cs` | Round-trip sign/verify with RDFC-1.0 canonicalizer |

**Modify existing test files (update calls to pass canonicalizer where needed):**
- `SignatureVerifierTests.cs`
- `MultibaseCodecTests.cs` (remove `CanonicalizeDocument` test)

### Phase 5 — Documentation

- Update `ARCHITECTURE.md` — canonicalization section
- Update `README.md` — RDFC-1.0 setup instructions
- Update `CLAUDE.md` — architecture notes
- Update `CHANGELOG.md` — new entry

## Critical Files

| File | Role |
|------|------|
| `src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs` | Central canonicalization dispatch — must handle both JCS and RDFC-1.0 payload construction |
| `src/ZcapLd.Core/Services/SigningService.cs` | Resolves canonicalizer from suite, passes to payload builder |
| `src/ZcapLd.Core/Services/VerificationService.cs` | Same pattern for verification path |
| `src/ZcapLd.Core/Cryptography/ICryptoSuite.cs` | Gets `CanonicalizationMethod` property |
| `src/ZcapLd.AspNetCore/DependencyInjection/ZcapRevocationServiceCollectionExtensions.cs` | DI wiring |

## Canonical Output Comparison

Given the same ZCAP-LD root capability, JCS and RDFC-1.0 produce structurally different canonical forms:

**Input (Capability object):**
```json
{
  "@context": ["https://w3id.org/zcap/v1"],
  "id": "urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents",
  "controller": "did:key:z6MkRdfcOwner",
  "invocationTarget": "https://storage.example.com/rdfc-documents",
  "allowedAction": ["read", "write"]
}
```

**JCS output (243 bytes) — compact JSON with sorted keys:**
```json
{"@context":["https://w3id.org/zcap/v1"],"allowedAction":["read","write"],"caveat":[],"controller":"did:key:z6MkRdfcOwner","id":"urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents","invocationTarget":"https://storage.example.com/rdfc-documents"}
```

**RDFC-1.0 output (291 bytes) — sorted N-Quads (RDF triples):**
```nquads
<urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents> <https://w3id.org/security#allowedAction> "read" .
<urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents> <https://w3id.org/security#allowedAction> "write" .
<urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents> <https://w3id.org/security#controller> <did:key:z6MkRdfcOwner> .
<urn:zcap:root:https%3A%2F%2Fstorage.example.com%2Frdfc-documents> <https://w3id.org/security#invocationTarget> <https://storage.example.com/rdfc-documents> .
```

Key differences:
- **JCS** treats the document as opaque JSON — sorts keys alphabetically, normalizes whitespace. Fast but has no understanding of JSON-LD semantics.
- **RDFC-1.0** expands JSON-LD to RDF quads using `@context`, resolves compact IRIs (e.g. `controller` → `https://w3id.org/security#controller`), canonicalizes blank node identifiers, and sorts quads lexicographically. This enables cross-implementation interoperability with any system that supports the same cryptosuite.

## Known Challenges

1. **RDFC-1.0 requires valid JSON-LD**: The `Capability` model has `@context` and is valid JSON-LD. The proof options object needs `@context` added for RDFC-1.0 canonicalization. `ProofSigningPayloadBuilder` will handle this when `method == "RDFC-1.0"`.
2. **dotNetRdf.Core dependency weight**: ~1MB + 12 transitives (Newtonsoft.Json, AngleSharp, etc.). Can be extracted to a separate package later; the interface-based design makes this trivial.
3. **dotNetRdf NOT in W3C conformance report**: Smoke tests using official W3C test vectors (test002, test003, test006) verify blank-node renaming, lexicographic sorting, and identity preservation. See `RdfcComplianceTests.cs`.

## Verification

```bash
dotnet build ZcapLd.sln                              # Compiles clean
dotnet test ZcapLd.sln                               # All existing + new tests pass
dotnet run --project examples/ZcapLd.Examples         # Examples still work (JCS path)
dotnet pack src/ZcapLd.Core -c Release                # Packs successfully
dotnet pack src/ZcapLd.AspNetCore -c Release          # Packs successfully
```
