# zcap-dotnet ⇄ W3C ZCAP-LD & @digitalbazaar/zcap — Definitive Compatibility Report

**Date:** 2026-06-18
**Scope:** How close is zcap-dotnet to (a) 100% W3C ZCAP-LD v0.3 spec compliance and (b) wire interop with the reference implementation `@digitalbazaar/zcap` (v9.0.2-0). Interop with `zcap-py` is explicitly out of scope.
**Method:** Multi-agent workflow (119 agents, ~6.7M tokens). Phase 1 extracted every normative MUST/SHOULD from the [W3C-CCG spec](https://w3c-ccg.github.io/zcap-spec/), reverse-engineered `@digitalbazaar/zcap` from its GitHub source (`jsonld-signatures`, `ed25519-signature-2020`, `zcap-context`), and mapped zcap-dotnet's `src/ZcapLd.Core`. Phase 2 ran a 10-dimension gap analysis; **every finding was then handed to an independent adversarial skeptic** that re-read the source / re-fetched upstream and tried to refute it. 105 findings were produced; **0 were refuted**; severities were corrected during verification. The two headline code-fix claims (allowedAction omit-to-widen; root-id charset divergence) were additionally re-verified by hand for this report, including running `Uri.EscapeDataString` on .NET 10.0.100.

> **Update (2026-06-18): the RDFC delegation round-trip is now PROVEN live.** A cross-stack harness ([`interop/`](../interop/), run via [`interop/run-interop.sh`](../interop/run-interop.sh)) signs a delegated capability on one stack and verifies it on the other using the **real `@digitalbazaar/zcap` v9.0.1** library. All six checks pass: dotnet→db verifies, db→dotnet verifies, both tamper negatives are rejected, and a two-level chain `[rootId, {parent}]` verifies both ways. This replaces the inference below for **capability delegation**. Still unproven (out of scope): **invocation** interop (blocked structurally by the envelope mismatch, blocker #2) — see §7.

---

## 1. Executive Summary

zcap-dotnet is a faithful, security-hardened implementation of the W3C ZCAP-LD v0.3 data model and verification algorithm. Its data model, root-id derivation, delegation-chain shape, crypto-suite metadata, and verification security all track the spec and `@digitalbazaar/zcap` closely — frequently *more* strictly. However, **wire interop with `@digitalbazaar/zcap` is broken in the default configuration**, and there is one confirmed attenuation-soundness defect.

| Metric | Score | Basis |
|---|---|---|
| **W3C ZCAP-LD v0.3 spec compliance** | **~94%** | One outright `noncompliant` finding (allowedAction omit-to-widen, R-DEL-ACTION-ATTEN) plus a few `partial` verify-path strictness gaps (`@context` value not checked on verify, root-no-extra-fields incomplete on verify, root-`expires` not rejected on verify). Data model, chain algorithm, expiration, caveat inheritance, and verification security are otherwise fully compliant. |
| **`@digitalbazaar/zcap` wire interop (out of the box)** | **Broken / non-interoperable by default** | The default JCS canonicalization produces signatures **no spec reference implementation can verify**. An interoperable RDFC-1.0 path exists but is opt-in, and even on that path the invocation envelope and a root-id charset edge case need work. |

### The single biggest blocker

**Default canonicalization is JCS (RFC 8785); `@digitalbazaar/zcap` is RDFC-1.0 only.** A JCS-signed zcap-dotnet capability can *never* verify in `@digitalbazaar/zcap` because the signed bytes are mathematically different (JCS signs one combined JSON object; digitalbazaar signs `SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))`, 64 bytes, proof-hash first). This is outbound-fatal (dotnet→db). zcap-dotnet ships the correct RDFC-1.0 path, but it is opt-in (`AddZcapRdfcCanonicalization()` / `"RDFC-1.0"`), so the default silently emits a private, non-interoperable wire format.

Evidence: [SigningService.cs:24-27](../src/ZcapLd.Core/Services/SigningService.cs#L24-L27); [VerificationService.cs:114](../src/ZcapLd.Core/Services/VerificationService.cs#L114); DataProofs `LegacyCryptosuiteBase.BuildJcsSigningInput`; `jsonld-signatures` `LinkedDataSignature.createVerifyData` (`util.concat(proofHash, docHash)`).

---

## 2. Interop Blockers (severity-ordered)

### Blocker 1 — Default JCS canonicalization is wire-incompatible with `@digitalbazaar/zcap` (RDFC-1.0)
- **What breaks:** Every capability and invocation zcap-dotnet *signs* under the default JCS path is unverifiable by `@digitalbazaar/zcap`. JCS feeds the canonical UTF-8 of `{document fields + nested proof-minus-proofValue}` directly to Ed25519; digitalbazaar verifies `SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))`. Different signed message ⇒ verification always fails.
- **Direction:** **Outbound (dotnet→db) is fatal and unavoidable.** Inbound (db→dotnet) is *not* strictly broken: DataProofs' `LegacyCryptosuiteBase.VerifyProof` tries both canonicalization variants, so a JCS-default zcap-dotnet verifier can fall back to RDFC and accept a digitalbazaar capability when the RDFC N-Quads match.
- **Root cause:** Default `canonicalizationMethod = "JCS"` in `SigningService` and `VerificationService`; RDFC is opt-in.
- **Fix:** Make RDFC-1.0 the default for any interop-targeting deployment, *or* document loudly that JCS-signed zcaps are a private, non-interoperable wire format. The interoperable path already exists and is byte-correct (see note); it just isn't the default.
- Evidence: [SigningService.cs:24-27](../src/ZcapLd.Core/Services/SigningService.cs#L24-L27); [VerificationService.cs:114](../src/ZcapLd.Core/Services/VerificationService.cs#L114); [ProofSigningPayloadBuilder.cs:114-120](../src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs#L114-L120); decompiled `LegacyCryptosuiteBase.BuildJcsSigningInput`/`BuildRdfcSigningInput`; fetched `jsonld-signatures`.

> **The RDFC-1.0 path itself is confirmed byte-identical to digitalbazaar:** same hash order (proof-hash first), SHA-256, 64-byte layout ([ProofSigningPayloadBuilder.cs:152-168](../src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs#L152-L168)); proof-options `@context` copied from the document `@context` matching digitalbazaar's `canonizeProof`; embedded `zcap-v1.jsonld` / `ed25519-2020-v1.jsonld` term-sets byte-equivalent to upstream. The golden vector pins the final payload SHA-256 `1A9A00A5066EE02B0E3B3AAB2BA3E9E6B125FE876CC5C4EFA4C3100CCD039586` ([CanonicalizationGoldenVectorTests.cs:54-73](../tests/ZcapLd.Core.Tests/Compliance/CanonicalizationGoldenVectorTests.cs#L54-L73)). So enabling RDFC genuinely fixes **outbound capability** interop.

### Blocker 2 — Invocation envelope: zcap-dotnet signs a self-contained `{id,capability,capabilityAction,invocationTarget}` document; digitalbazaar signs an arbitrary application payload
- **What breaks:** Even on the RDFC path, cross-stack *invocation* interop fails because the signed **document graph differs**. zcap-dotnet canonicalizes a fixed Invocation envelope as the document half ([Invocation.cs:33-46](../src/ZcapLd.Core/Models/Invocation.cs#L33-L46)), carrying `capability`/`capabilityAction`/`invocationTarget` in **both** the top-level document **and** the proof object ([SigningService.cs:204-214](../src/ZcapLd.Core/Services/SigningService.cs#L204-L214), "COMPLIANCE FIX C-05"). digitalbazaar keeps those fields **only in the proof object** and signs the application's own request payload as the document.
- **Direction:** Both.
- **Root cause:** Deliberate self-contained-envelope design vs digitalbazaar's "attach a proof to an API-acceptable document" model.
- **Fix:** Either (a) explicitly scope invocation interop out, or (b) add a mode that signs an arbitrary application document with an invocation proof whose only invocation metadata lives in the proof object.
- Evidence: [Invocation.cs:33-46](../src/ZcapLd.Core/Models/Invocation.cs#L33-L46); [SigningService.cs:204-214](../src/ZcapLd.Core/Services/SigningService.cs#L204-L214); fetched `CapabilityInvocation.js`.

> Correction recorded during verification: the originally-claimed "fields only in the body, not the proof" framing was wrong — zcap-dotnet carries them in **both** places. The real break is the differing document graph, independent of (and additional to) the JCS/RDFC mismatch.

### Blocker 3 — RDFC invocation `@context` is bare `zcap/v1`; suite vocabulary may not expand to digitalbazaar's terms *(severity: major)*
- **What breaks:** For RDFC invocations, `CanonicalizeInvocationRdfc` injects only `https://w3id.org/zcap/v1` onto both the invocation doc and proofOptions ([ProofSigningPayloadBuilder.cs:144-150](../src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs#L144-L150)). The proof terms (`Ed25519Signature2020`, `proofValue`, `proofPurpose`) live in the ed25519-2020 suite context, not zcap/v1, so they may be dropped/mismapped vs digitalbazaar's expanded graph.
- **Direction:** Both.
- **Fix:** Include the suite context (`https://w3id.org/security/suites/ed25519-2020/v1`) in the proofOptions `@context`; add a cross-stack RDFC invocation golden vector before claiming interop.
- Evidence: [ProofSigningPayloadBuilder.cs:144-150](../src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs#L144-L150); [RdfcContextDocumentLoader.cs:24-31](../src/ZcapLd.Core/Cryptography/RdfcContextDocumentLoader.cs#L24-L31).

### Blocker 4 — Root id encoding diverges from `encodeURIComponent` on `! ' ( ) *` *(severity: major)*
- **What breaks:** [CapabilityService.cs:49](../src/ZcapLd.Core/Services/CapabilityService.cs#L49) uses `Uri.EscapeDataString`. **Verified by execution on .NET 10.0.100:** it escapes `!`→`%21`, `'`→`%27`, `(`→`%28`, `)`→`%29`, `*`→`%2A`, whereas JS `encodeURIComponent` leaves all five unescaped. For any `invocationTarget` containing those characters, zcap-dotnet's root id string differs byte-for-byte from the id digitalbazaar computes, breaking canonicalization-independent `chain[0]` / root-dereference string equality.
- **Direction:** Both (the differing string breaks chain references each way); the unfixed residual is **dotnet→db** (digitalbazaar resolves the root by exact-string id and re-derives via `encodeURIComponent`; the dotnet verifier is decode-tolerant via `Uri.UnescapeDataString`, [VerificationService.cs:1402-1411](../src/ZcapLd.Core/Services/VerificationService.cs#L1402-L1411)).
- **Severity:** corrected down from "blocker" — conditional, only triggers on targets containing `! ' ( ) *`, and full signature interop already requires the non-default RDFC path.
- **Fix:** Post-process `EscapeDataString` output to un-escape exactly `%21 %27 %28 %29 %2A` → `! ' ( ) *` (case-insensitive hex), escaping nothing additional. Do **not** touch `~` (both stacks already leave it literal). Add a golden vector covering a target with all of `! ' ( ) * ~` against a digitalbazaar-produced id.
- Evidence: [CapabilityService.cs:49](../src/ZcapLd.Core/Services/CapabilityService.cs#L49); executed `.NET 10`: `!→%21, '→%27, (→%28, )→%29, *→%2A, ~→~`; MDN `encodeURIComponent`.

> For the overwhelmingly common case — plain http(s) URLs with `: / ? & = #` and alphanumerics — the two encoders match byte-for-byte (`:`→`%3A`, `/`→`%2F`, …), so typical root ids interoperate.

### Non-blockers worth noting (interop-narrowing, not breaking)
- **EcdsaSecp256r1Signature2019 (P-256) has no `@digitalbazaar/zcap` counterpart** — digitalbazaar ships/tests Ed25519 only and serves no `ecdsa-2019/v1` context. A P-256 zcap will not verify against an out-of-the-box digitalbazaar deployment. **Major** semantic gap (dotnet→db); not a spec violation (the spec is suite-neutral). Use Ed25519Signature2020 for guaranteed interop. Evidence: [ZcapSuiteCatalog.cs:27-30](../src/ZcapLd.Core/Cryptography/ZcapSuiteCatalog.cs#L27-L30); [LegacyProofCrypto.cs:125](../src/ZcapLd.Core/Cryptography/LegacyProofCrypto.cs#L125); digitalbazaar `package.json` (Ed25519-only devDeps).
- **Custom caveats (UsageCount, ValidWhileTrue) are silently ignored by digitalbazaar** — it has no generic caveat engine; signature still verifies (the `caveat` field is tolerated). **Major** semantic gap (dotnet→db). See §5.

---

## 3. Spec-Compliance Gaps (MUST / SHOULD not met), by category

### caveats-attenuation — **NONCOMPLIANT (the one outright violation)**
- **R-DEL-ACTION-ATTEN (MUST): `allowedAction` omit-to-widen.** When a parent restricts `allowedAction` and a child **omits** it, zcap-dotnet treats the child as unrestricted and **accepts** it; digitalbazaar's `hasValidAllowedAction` rejects it (`parentAllowedAction.includes(undefined) === false`). At invoke time only the leaf's `allowedAction` is checked, so a child that omits the field silently widens authority back to "any action." Attenuation-soundness defect, both directions, **major**.
  - Fix: in `VerificationService.ValidateAttenuation`, when `parent.AllowedAction` is non-empty, require the child to be present and a subset (reject null/empty child). Mirror in `CapabilityService.ValidateAttenuation` at create time. Same shape as the omit-`expires` bypass already closed for the expiration ceiling.
  - Evidence: [VerificationService.cs:1200-1207](../src/ZcapLd.Core/Services/VerificationService.cs#L1200-L1207), [598-601](../src/ZcapLd.Core/Services/VerificationService.cs#L598-L601); [CapabilityService.cs:314-325](../src/ZcapLd.Core/Services/CapabilityService.cs#L314-L325); digitalbazaar `lib/utils.js hasValidAllowedAction`.
  - The both-present array subset case *is* byte-compatible: `childActions.All(a => parentActions.Contains(a))` matches `allowedAction.every(...)`.

### data-model — partial (verify-path strictness gaps)
- **R-CTX-1 / R-CTX-2 (MUST): `@context` value not validated on the verify path.** The crypto verify paths perform **no** `@context` validation; the only checks live in the optional `CapabilityService.ValidateCapabilityAsync` (never called by the crypto paths), and even there `IsStringContext`/`IsArrayContext` check the *kind*, not the *value* ([CapabilityService.cs:430-440](../src/ZcapLd.Core/Services/CapabilityService.cs#L430-L440)). digitalbazaar enforces root `@context === zcap/v1` and delegated `context[0] === zcap/v1` at verify time. Under JCS the `@context` bytes are signed (so a tampered context breaks the signature), limiting exposure to hand-crafted producers. **Minor.**
  - Fix: fold root==`zcap/v1` / delegated index-0==`zcap/v1` into `VerifyBuiltChainAsync`; compare the actual URL, not just the kind.
- **R-ROOT-NOEXTRA (MUST NOT): root extra-field rejection incomplete on verify.** `ValidateRootCapabilityInvariants` ([VerificationService.cs:1427-1449](../src/ZcapLd.Core/Services/VerificationService.cs#L1427-L1449)) already rejects `parentCapability`, a delegation `proof`, empty `controller`, and a malformed `invocationTarget`. The residual gap vs the create-time validator is `expires`, `allowedAction`, `caveat`, `AdditionalProperties` on a root — of which only **root-`expires`** is an actual divergence from digitalbazaar. Bounded because the root is dereferenced locally (trusted resolver). **Minor.**
  - Fix: add the `expires`/`allowedAction`/`caveat`/`AdditionalProperties` checks inside `ValidateRootCapabilityInvariants`.
- **Create side is clean:** roots emit exactly `@context/id/controller/invocationTarget` ([CapabilityService.cs:52-59](../src/ZcapLd.Core/Services/CapabilityService.cs#L52-L59) + `WhenWritingNull`), satisfying the MUST NOT outbound.

### crypto-suites / did-key-multibase — partial (non-canonical type strings, no interop impact)
- **P-256 did:key VM type `EcdsaSecp256r1VerificationKey2019` is non-canonical** for modern did:key (which emits `Multikey`/`JsonWebKey2020`). Self-consistent .NET-to-.NET; out of scope for digitalbazaar (no P-256 path). **Minor.** Evidence: [DidKeyResolver.cs:167](../src/ZcapLd.Core/Services/DidKeyResolver.cs#L167); [ZcapSuiteCatalog.cs:27-30](../src/ZcapLd.Core/Cryptography/ZcapSuiteCatalog.cs#L27-L30).

### Fully-compliant SHOULDs handled correctly
- **R-DEL-EXP-CEIL (SHOULD, 3-month ceiling):** correctly opt-in (`VerificationPolicy.EnforceMaxDelegationExpiration`, default false), mirroring digitalbazaar's configurable `maxDelegationTtl`. When on, it also rejects unbounded (no-`expires`) delegated links and applies to every non-root link. [VerificationPolicy.cs](../src/ZcapLd.Core/Services/VerificationPolicy.cs).
- **R-CHAIN-LEN-SHOULD (limit 10):** `MaxChainLength = 10` matches digitalbazaar exactly (counting convention included), enforced during the walk (DoS-resistant). [VerificationService.cs:38](../src/ZcapLd.Core/Services/VerificationService.cs#L38).
- **R-INV-ID (SHOULD, id-as-nonce):** zcap-dotnet *requires* `id` and replay-checks it — stricter than the SHOULD (see §5).

---

## 4. Compatibility Scorecard

| Dimension | Spec compliance | DB wire interop | Notes |
|---|---|---|---|
| **data-model** | Mostly compliant; 2 partial verify-path gaps | OK on creation; minor laxness inbound | Field names byte-identical to zcap-v1 context. `@context` value + root-extra-field checks missing on verify path. |
| **root-id** | Compliant (prefix + format) | **Major edge break** on `! ' ( ) *` | `urn:zcap:root:` byte-identical; `Uri.EscapeDataString` ≠ `encodeURIComponent` on five chars. Verifier is decode-tolerant; outbound id string still diverges. |
| **delegation-chain** | Fully compliant | Interoperable (shape-compatible) | Spec-exact build + strict shape validation (root-by-id, immediate parent embedded, ancestors-by-id, ordered, length≤10, no cycles, prefix-binding). |
| **canonicalization** | Partial (JCS default is a private format) | **BLOCKER (outbound)**; inbound works via fallback | JCS default unverifiable by db. RDFC path byte-identical to db (hash order, SHA-256, 64-byte, contexts). DataProofs verifier tries both variants. |
| **crypto-suites** | Compliant (Ed25519); P-256 partial | Ed25519 OK; **P-256 major gap** | `Ed25519Signature2020` / `Ed25519VerificationKey2020` / base58btc proofValue / no `cryptosuite` field all match db. P-256 absent upstream. P384/Secp256k1/X25519 are dead-end key mappings (no catalog entry). |
| **invocation** | Compliant (purposes, capability shape, proof fields) | **BLOCKER ×2** (envelope graph; JCS) + major RDFC `@context` | Root=string/delegated=embedded shape matches db exactly. But self-contained envelope ≠ db's application-payload document. |
| **expires-ttl** | Compliant | OK | Delegated `expires` required + not-expired enforced on verify; root MUST-NOT-have-`expires` not enforced on verify (minor). Child≤parent narrowing enforced. 3-month ceiling opt-in. |
| **caveats-attenuation** | **Noncompliant** (allowedAction omit-to-widen); else compliant | **Major** (caveats invisible to db); attenuation otherwise byte-equiv | invocationTarget delimiter logic (`/ ? &`) byte-equivalent; zcap adds a `..` path-traversal guard db lacks (safe-direction). Inheritance + chain-wide eval implemented (db has neither). |
| **verification-security** | Compliant (often stricter) | OK | Signature-before-auth ordering; suite↔key-type binding; no-trust-wire-root; self-contained chain. Controller auth: db *also* enforces per-purpose relationship; zcap marginally looser on flat controller-list membership (did:key unaffected). |
| **did-key-multibase** | Compliant (Ed25519); P-256 VM type partial | OK (Ed25519) | `did:key:z6Mk…#z6Mk…` byte-identical; `0xed01` multicodec + base58btc; key type derived from multicodec; exhaustive fragment match (no X25519 substitution). |

---

## 5. What zcap-dotnet does that `@digitalbazaar/zcap` does NOT — and whether it breaks wire interop

| Feature | digitalbazaar | Wire-interop impact |
|---|---|---|
| **Revocation** (`capabilityRevocation` proofPurpose + `revoke` action) | No revocation engine (out of scope for the reference lib). | **No format break.** A `capabilityRevocation` proof is a zcap-dotnet-private control-plane object; it never appears on the standard capability/invocation path. Auth model (any controller along the verified chain may revoke; `RevokedBy` is the authenticated VM, never client-asserted) is sound. Revocation-auth deliberately skips the 3-month ceiling, delegation-`created`, and required-`expires` gates so long-lived/malformed/non-expiring delegations stay revocable. |
| **Replay protection** (nonce via `invocation.Id` + proof.created freshness) | No nonce store; replay left to the consuming API. | **No new wire field** (reuses the spec invocation `id` as nonce). But zcap-dotnet **requires** `invocation.Id` (spec/db: SHOULD) — a db invocation lacking `id` is rejected (`MalformedCapability`). **Minor**, db→dotnet. |
| **Invocation proof.created freshness window** (future-skew 1 min, staleness lower-bound 5 min) | db default applies **no** freshness window to invocation `created` (`maxTimestampDelta=Infinity`). | **No wire change.** A db-issued invocation that is future-dated or older than 5 min may be rejected by default zcap-dotnet (`StaleProof`). **Minor**, db→dotnet. Widen `nonceWindow`/`freshnessClockSkew` for high-latency interop. |
| **Rich pluggable caveats** (`ExpirationCaveat`, `UsageCountCaveat`, `ValidWhileTrueCaveat`; chain-wide eval + inheritance) | No generic caveat engine — only `expires`, `allowedAction` subsetting, `invocationTarget` attenuation. | **Signature-safe but semantically dangerous, dotnet→db, major.** A zcap-dotnet capability whose security depends on a `UsageCount`/`ValidWhileTrue` caveat **verifies in db with the caveat silently un-enforced** — granting access zcap-dotnet would deny. For cross-stack security rely only on `expires`/`allowedAction`/`invocationTarget`. |
| **`..` path-traversal rejection in attenuated targets** | Pure lexical `startsWith`; no dot-segment guard. | Safe-direction hardening (fails closed): a `..`-containing attenuated target db accepts can be rejected by zcap-dotnet. **Minor**, dotnet→db, not an auth bypass. |

---

## 6. Prioritized Remediation Roadmap to Reach Interop

Ordered by interop leverage × correctness; effort in rough engineer-days (S ≈ <1, M ≈ 1–3, L ≈ 3–5).

> **Status (4.0.0): items 1–3 below are IMPLEMENTED.** JCS was removed entirely (RDFC-1.0 is the only canonicalization), the `allowedAction` omit-to-widen bypass is closed on both the verify and create paths, and the root-id encoder now matches `encodeURIComponent`. See `CHANGELOG.md` (4.0.0) and the regression tests in `CapabilityServiceTests` / `VerificationServiceTests` / `ProofGoldenVectorTests`.

1. ✅ **Done (4.0.0) — RDFC-1.0 is the only canonicalization.** Rather than flip a default, JCS support was removed outright: `SigningService`/`VerificationService` no longer take a `canonicalizationMethod`, `AddZcapRdfcCanonicalization()` is gone, and the live `interop/run-interop.sh` harness verifies cross-stack delegation against `@digitalbazaar/zcap`. **Highest leverage.**
2. ✅ **Done (4.0.0) — `allowedAction` omit-to-widen MUST violation fixed.** A null/empty child `allowedAction` under a restricting parent is rejected on the verify path and at create time. Closes the one outright spec noncompliance.
3. ✅ **Done (4.0.0) — root-id encoding matches `encodeURIComponent`.** `UriEncoding.EncodeUriComponent` un-escapes `%21 %27 %28 %29 %2A`; covered by a regression test using a target with `! ' ( ) * ~`.
4. **Include the suite context in RDFC invocation proofOptions `@context`.** *Effort: S–M.* Add `ed25519-2020/v1`; add a cross-stack RDFC invocation golden vector.
5. **Add a digitalbazaar-compatible invocation mode (proof-on-application-document).** *Effort: M–L.* Sign an arbitrary application payload with an invocation proof carrying `capability`/`capabilityAction`/`invocationTarget` **only in the proof object**. Structural fix for cross-stack invocation; until then, document invocation interop as out of scope.
6. **Tighten verify-path data-model strictness for db parity.** *Effort: S–M.* Fold into the verify path: root/delegated `@context` value checks; root `expires`/`allowedAction`/`caveat`/`AdditionalProperties` rejection (inside `ValidateRootCapabilityInvariants`).
7. **Document the semantic-only divergences loudly.** *Effort: S.* Custom caveats not enforced cross-stack; P-256 has no db counterpart; revocation/replay are zcap-dotnet-private; freshness window tighter than db's (no-window) default.
8. **(Optional) Align minor clock/skew + cleanup.** *Effort: S.* Drop the 1-second create-side `expires`-narrowing tolerance; remove or wire the dead P384/Secp256k1/X25519 key-type mappings.

---

## 7. Honest Caveats — what could not be verified, and corrections recorded

**Verified live (2026-06-18) — capability delegation:**
- The "RDFC matches digitalbazaar" conclusion is now **confirmed by a live round-trip**, not just inference. The [`interop/`](../interop/) harness uses the real `@digitalbazaar/zcap` 9.0.1 (+ `jsonld-signatures` 11.6.0, `@digitalbazaar/ed25519-signature-2020` 5.4.0). Six checks pass: outbound (dotnet RDFC → db verify) ✅, inbound (db → dotnet RDFC verify) ✅, both tamper negatives rejected ✅, and a two-level chain `[rootId, {parent}]` both directions ✅. This closes the prior "no live round-trip" caveat for delegation and substantiates remediation item 1.

**Still not verified end-to-end:**
- **Invocation** interop has *not* been round-tripped — it is structurally blocked by the envelope mismatch (blocker #2), so it is deliberately out of the harness's scope (remediation item 5 must land first).
- The RDFC invocation `@context` concern (Blocker 3) is a reasoned risk that term expansion *may* diverge; not disproven by a live round-trip (no invocation round-trip exists yet).

**Factual corrections folded in during adversarial verification:**
- **REFERENCE_DATA was wrong** that modern .NET `Uri.EscapeDataString` agrees with `encodeURIComponent` on `! ' ( ) *`. Verified by execution on .NET 10.0.100: it escapes all five. The divergence is real (Blocker 4).
- **Root-id encoding severity corrected** blocker→major (conditional on those characters; signature interop already needs RDFC).
- **Invocation envelope mechanism corrected:** fields are in **both** body and proof, not "body only." The break is the differing document graph.
- **Controller-authorization finding corrected:** zcap-dotnet is **not stricter** than db on per-purpose relationship checks (db's `CapabilityProofPurpose`/`ControllerProofPurpose` enforce them too); zcap is marginally **looser** on db's additional flat controller-list membership test; did:key controllers (the default) diverge in neither direction.
- **db `created > expires` rule** lives in `CapabilityDelegation.js` `update()` (create-time), not `checkCapability`; zcap-dotnet's `Expired` gate covers it except a ~1-minute clock-skew corner (deliberately dropped, #99).
- **db invocation freshness:** db's default has **no** freshness window (`maxTimestampDelta=Infinity`) — so zcap-dotnet's window is the stricter side.
- **`MultibaseCodec` 'z'-only guard is test-only** — unused on the production proofValue path (DataProofs owns it).
- **Inbound JCS verifier is not strictly broken** — DataProofs `VerifyProof` tries both canonicalization variants.

**Refuted findings:** none — all 105 findings survived adversarial review, with the severity/direction corrections above.

---

## Appendix A — Minor findings (24)

| Dimension | Finding | Spec | Direction |
|---|---|---|---|
| data-model | `@context` value not validated on the verification path | partial | db→dotnet |
| data-model | Root id format `urn:zcap:root:{EscapeDataString(target)}` (compliant for http(s) targets) | compliant | both |
| data-model | Root extra-field rejection on verify path incomplete (R-ROOT-NOEXTRA partial) | partial | db→dotnet |
| data-model | Invocation document carries no `@context` (model has no field) | compliant | both |
| root-id | Verify-path decode-equality target check tolerates the encoding divergence (one-directional mitigation) | partial | dotnet→db |
| canonicalization | JCS binds `capabilityChain` verbatim; RDFC binds it via `@context` (interop-neutral when contexts match) | compliant | both |
| canonicalization | JCS path fails closed on documents that already carry a `proof` member (proof chains) | compliant | na |
| crypto-suites | P-256 ECDSA signature is P1363 (raw `r‖s`), correct for EcdsaSecp256r1Signature2019 | compliant | na |
| crypto-suites | Suite set is a closed, non-consumer-extensible catalog (Ed25519 + P-256 only) | compliant | na |
| invocation | Replay protection (nonce via invocation id) is zcap-dotnet-only | compliant | db→dotnet |
| invocation | `invocationTarget` absolute-URI: db enforces `':'`; zcap relies on capability-target matching | compliant | na |
| expires-ttl | Root MUST-NOT-have-`expires` enforced at create time but NOT on verify | partial | db→dotnet |
| expires-ttl | 3-month verifier TTL ceiling opt-in (off by default) — defensible for a SHOULD | compliant | both |
| expires-ttl | db's delegation `created > expires` check not implemented | compliant | dotnet→db |
| expires-ttl | Invocation proof.created freshness bounded by nonce window (5m) + skew (1m) — stricter than db | compliant | both |
| caveats-attenuation | `..` path-traversal rejection is zcap-dotnet hardening absent in db | compliant | dotnet→db |
| caveats-attenuation | Caveat node shape (type discriminator + custom props) JSON-LD-droppable but does NOT break db RDFC verify | compliant | dotnet→db |
| verification-security | Controller auth uses DID-doc verification-relationship resolution (stricter than db string match) | compliant | db→dotnet |
| verification-security | db's `created > expires` delegation rule intentionally dropped | compliant | both |
| verification-security | Invocation/revocation proof.created window is a policy extra; no wire change | compliant | db→dotnet |
| verification-security | Replay via `invocation.Id` nonce is a policy extra; no extra wire field | compliant | db→dotnet |
| verification-security | Signed revocation adds wire-visible `capabilityRevocation` purpose + `revoke` action absent from db | na | dotnet→db |
| did-key-multibase | P-256 did:key VM type `EcdsaSecp256r1VerificationKey2019` non-standard for did:key | partial | na |
| did-key-multibase | `DidKeyResolver` requires `publicKeyMultibase`, no `publicKeyJwk` fallback | compliant | db→dotnet |

## Appendix B — Methodology detail

- **Workflow:** `zcap-interop-analysis` (4 phases: Reference → Gap → Verify → Synthesize). 119 agents, ~6.7M subagent tokens, 1,033 tool calls.
- **Reference sources:** W3C-CCG ZCAP-LD v0.3 spec; `@digitalbazaar/zcap` v9.0.2-0 (`lib/CapabilityDelegation.js`, `CapabilityInvocation.js`, `utils.js`, `constants.js`, `package.json`); `@digitalbazaar/zcap-context`; `jsonld-signatures` `LinkedDataSignature.js`; decompiled `DataProofsDotnet.Legacy` 1.0.0 (`LegacyCryptosuiteBase`).
- **Adversarial verification:** each of 105 findings was independently re-checked by a skeptic agent tasked to refute it; 0 refuted; severities and directions corrected where overstated.
- **Hand re-verification for this report:** `allowedAction` omit-to-widen (read [VerificationService.cs:598-601](../src/ZcapLd.Core/Services/VerificationService.cs#L598-L601), [1200-1207](../src/ZcapLd.Core/Services/VerificationService.cs#L1200-L1207)); `Uri.EscapeDataString` charset (executed on .NET 10.0.100).
