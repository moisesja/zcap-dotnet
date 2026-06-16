# Design decision: where does cryptographic-suite extensibility live?

**Status:** Draft for maintainer decision — blocks the final Stage C cleanup (#108).
**Branch:** `108-golden-vector-harness`
**Date:** 2026-06-15

---

## TL;DR

After Stage C delegated all proof cryptography to DataProofs' legacy cryptosuites, zcap still
exposes a **public crypto-suite extension surface** — `ICryptoSuite`, `ICryptoSuiteProvider`,
`CryptoSuite`, and `AddZcapCryptoSuite<T>()` — that no longer does what it advertises. We must
decide what that surface becomes.

**Recommendation: remove it (Option A).** zcap should not be a crypto-extension point; new
curves/suites are added in the foundation (NetCrypto + DataProofs), and zcap supports a **fixed,
internal** set of suites. zcap keeps a *small, internal, public-method-backed* table only for the
W3C suite metadata DataProofs does not carry (the suite `@context` URL).

---

## 1. Layering — who owns what

| Layer | Owns | "Add a new curve" means… |
|---|---|---|
| **NetCrypto** | cryptographic primitives (sign/verify per algorithm, key model, key types) | add a primitive/key type here |
| **DataProofs** | Data Integrity proof machinery: `ICryptosuite` (canonicalize + hash + a NetCrypto primitive → a proof), the pipeline, the cryptosuite registry; `DataProofsDotnet.Legacy` ships the `Ed25519Signature2020` / `EcdsaSecp256r1Signature2019` suites | add a cryptosuite here |
| **zcap** | the ZCAP-LD domain: capabilities, delegation chains, caveats, invocation, revocation, **authorization policy** | *use* a suite to sign/verify — not a crypto or proof-format library |

The migration's north star: **zcap delegates to the foundation as much as possible.** Extensibility
of *cryptography* and *proof formats* therefore belongs downstream, not in zcap.

---

## 2. What the API was, and what Stage C did to it

### Before the migration — `ICryptoSuite` was a real crypto abstraction

```csharp
public interface ICryptoSuite {
    string ProofType { get; }              // "Ed25519Signature2020"
    string KeyType { get; }                // "Ed25519VerificationKey2020"  (W3C verification-method type)
    string ContextUrl { get; }             // "https://w3id.org/security/suites/ed25519-2020/v1"
    string CanonicalizationMethod { get; } // "JCS" | "RDFC-1.0"
    byte[] Sign(byte[] data, byte[] privateKey);
    bool   Verify(byte[] data, byte[] signature, byte[] publicKey);
}
```

A consumer could implement a custom `ICryptoSuite` (e.g. secp256k1), register it via
`AddZcapCryptoSuite<T>()` / a `CryptoSuiteProvider`, and zcap's `SigningService` /
`VerificationService` would call `suite.Sign` / `suite.Verify` to do the proof crypto.
**zcap was a crypto-extension point**, and RDFC was opted into the same way — by registering a suite
whose `CanonicalizationMethod` is `"RDFC-1.0"` (see `RdfcEndToEndTests`, `examples/Program.cs`).

### After Stage C

- All proof sign/verify now flows through the `LegacyProofCrypto` engine, which dispatches to the
  **DataProofs.Legacy** suites. Its dispatch **hardcodes the two known proof types**.
- Follow-up 2 reduced `ICryptoSuite` to **metadata-only** (Sign/Verify removed).
- The public surface still exists, but:
  - it carries only metadata; and
  - registering a custom suite gives zcap metadata for a proof type **the engine cannot sign or
    verify** (the engine only knows the two built-ins). The "extension point" is half-wired.

---

## 3. The problem, precisely

1. **The surface is misleading.** `AddZcapCryptoSuite<MyCurve>()` looks like it adds a curve, but
   the engine won't use it — the consumer gets silent failures (sign throws / verify returns false)
   for the custom proof type.
2. **It's at the wrong layer.** Per the architecture, a new curve is a NetCrypto primitive + a
   DataProofs cryptosuite. zcap re-exposing a crypto-suite extension point duplicates the concern and
   binds consumers to a zcap-specific abstraction instead of the shared one.

(`AddZcapCryptoSuite<T>` currently has **no callers** in the repo — tests and examples never use it —
so removing it breaks nothing internally.)

---

## 4. The constraint: a little metadata is irreducibly zcap's

Even with crypto fully delegated, zcap needs some per-suite metadata that **DataProofs does not
expose**:

| zcap needs | where it comes from |
|---|---|
| proof `type` (`Ed25519Signature2020`) | the DataProofs.Legacy suite already knows it ✓ |
| **W3C key-type string** (`Ed25519VerificationKey2020`) for the #68 resolver↔suite binding | the NetCrypto.KeyType ↔ string map zcap already has (`ResolvedKeyTypeMap`) ✓ — no per-suite field needed |
| **suite `@context` URL** (`…/ed25519-2020/v1`) | **zcap-specific; not in DataProofs.** *Confirmed still used*: `ISigningService.ResolveSuiteContextUrlAsync` → `CapabilityService` stamps it onto capabilities |
| JCS vs RDFC selection | a zcap config choice, not a suite property |

So **whatever we choose, zcap retains a small fixed mapping** (proof-type → context URL, keyed by key
type). The real question is whether that mapping is a **public, consumer-extensible** surface or a
**closed, internal** detail. `ResolveSuiteContextUrlAsync` stays public either way; only its backing
changes.

---

## 5. Options

### Option A — Remove the crypto-suite surface (recommended)

- Delete `AddZcapCryptoSuite<T>`; delete/internalize `ICryptoSuite` / `ICryptoSuiteProvider` /
  `CryptoSuite` / `CryptoSuiteProvider`.
- Replace with an **internal fixed table** (`ZcapSuiteInfo`): key type → (proof type, context URL).
  `#68` uses the existing `ResolvedKeyTypeMap`. `ResolveSuiteContextUrlAsync` reads the table.
- `SigningService` / `VerificationService` drop the `ICryptoSuiteProvider` constructor parameters.
- `AddZcapRdfcCanonicalization()` becomes a **flag/option** the engine reads (one canonicalization
  for the process), replacing the per-suite `CanonicalizationMethod` override.
- Adding a curve = NetCrypto primitive + DataProofs suite + a **one-line zcap wiring** (a table entry
  + an engine case). Never a consumer DI call.

| | |
|---|---|
| **Pros** | Honest, minimal public surface; single extensibility path (the foundation); fully matches the north star. |
| **Cons** | A consumer wanting a third curve via zcap DI can't — they contribute it upstream and zcap wires it. (That path is already non-functional post-Stage-C, so this is making reality explicit, and is arguably correct.) RDFC becomes process-global rather than per-suite. |
| **Churn** | Moderate: `SigningService` (metadata lookup), `VerificationService` (6 ctors lose a param), DI (`AddZcapServices`, remove `AddZcapCryptoSuite`, rework `AddZcapRdfcCanonicalization`), tests (`CryptoSuiteProviderTests` delete, `RdfcEndToEndTests` + example RDFC enablement change, the `RdfcEd25519CryptoSuite` helpers go away, ~handful of explicit-provider service-construction sites). Gated by the 497 tests + byte-identity goldens. |

### Option B — Keep `ICryptoSuite` public (metadata), remove only `AddZcapCryptoSuite`

- `ICryptoSuite` / `CryptoSuite` stay public as a metadata type the built-ins expose; remove the
  registration extension so no consumer can inject one. RDFC enablement keeps the
  `CanonicalizationMethod` model (a metadata suite), just no longer consumer-registrable.

| | |
|---|---|
| **Pros** | Much less churn; keeps a typed metadata surface; still closes the (broken) extension point. |
| **Cons** | Keeps a public type whose only role is internal metadata; a half-measure that doesn't fully realize "zcap exposes no crypto-suite concept." |
| **Churn** | Small: delete `AddZcapCryptoSuite`; DI registers the fixed built-ins directly. |

### Option C — Status quo (keep metadata-only `ICryptoSuite` + `AddZcapCryptoSuite`)

| **Pros** | Zero work. | **Cons** | The misleading half-wired extension point remains; contradicts the agreed principle. |

### Option D — Make zcap genuinely crypto-extensible (rejected per your direction)

Re-expose a working zcap-level cryptosuite registry. **Rejected**: extensibility belongs at
NetCrypto / DataProofs, not zcap.

---

## 6. Recommendation

**Option A.** It is the only option that leaves zcap with an honest, minimal public surface and a
single extensibility path (the foundation). The churn is moderate and fully gated by the existing
497 tests + the byte-identity golden vectors. **Option B** is a reasonable lighter step if you want
to minimize churn now and internalize fully later.

---

## 7. Questions for you

1. **Option A or B?** (A = remove the surface; B = keep `ICryptoSuite` public as metadata, just drop
   registration.)
2. **RDFC as a process-global flag** (Option A) acceptable, or do you want to retain per-suite
   canonicalization selection?
3. **Roadmap:** any near-term curves (secp256k1, P-384, BLS)? If yes, we'll make the internal
   "one-line wiring" ergonomic, but it stays a zcap code change, not consumer DI.

---

## Appendix — affected files (Option A)

- **src/Cryptography:** delete/internalize `ICryptoSuite`, `ICryptoSuiteProvider`, `CryptoSuite`,
  `CryptoSuiteProvider`; add internal `ZcapSuiteInfo` table. `LegacyProofCrypto` unchanged.
- **src/Services:** `SigningService`, `VerificationService` (drop provider ctor params; read the
  table). `ResolveSuiteContextUrlAsync` stays on `ISigningService`, backed by the table.
- **src/AspNetCore DI:** `ZcapRevocationServiceCollectionExtensions` — `AddZcapServices` (no provider
  wiring), remove `AddZcapCryptoSuite<T>`, rework `AddZcapRdfcCanonicalization` to a flag.
- **tests:** delete `CryptoSuiteProviderTests`; trim `CryptoSuiteTests`; rewire `RdfcEndToEndTests` /
  `RdfcCanonicalizeIntegrationTests` RDFC enablement; remove `RdfcEd25519CryptoSuite` helper; update
  explicit-provider service-construction sites.
- **examples:** `RdfcEd25519CryptoSuite.cs` + `Program.cs` RDFC enablement.
- **docs:** ARCHITECTURE, AGENTS, CHANGELOG (note the removed extension surface).
