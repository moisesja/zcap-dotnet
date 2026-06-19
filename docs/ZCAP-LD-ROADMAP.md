<!--
Generated from the verified delta-roadmap workflow (2026-06-18) + the compatibility analysis.
Status: the three spec/doc closeouts in §5 items 1-3 are implemented on branch
verify-path-spec-closeouts (this PR). Invocation interop (§2, items 4-6) is tracked in issue #117
(Path A = Data Integrity proof, chosen) + a follow-up issue for Path B (HTTP Signatures).
-->

# ZCAP-LD .NET → 100% W3C Compliance + @digitalbazaar/zcap Interop Roadmap

## 1. Status line

**Where we are (4.0.0, HEAD `72381ce` / PR #116):** Delegation interop is **done** — RDFC-1.0 is the default/only canonicalizer, `allowedAction` and root-id-only references ship, and delegation round-trips against `@digitalbazaar/zcap` 9.0.1 (`interop/run-interop.sh` exercises dotnet-sign→db-verify, db-sign→dotnet-verify, and tamper-reject).

**What blocks "100%":**
- **Invocation interop is entirely open** — zcap-dotnet signs the *wrong document graph*. This is the single largest remaining piece (deferred issue **#117**).
- **Four verify-path spec MUSTs are unmet** — `@context` value validation (root + delegated), delegated `@context[0]` ordering / suite-presence, and root extra-field rejection. The *create* path is already correct; the *verify* path never runs those checks.
- **Two semantic divergences are doc-only** — P-256 has no db counterpart; custom caveats (UsageCount/ValidWhileTrue) are invisible to db.

---

## 2. The critical path: invocation interop (#117)

### Root cause
zcap-dotnet builds a **self-contained `Invocation` document** `{id, capability, capabilityAction, invocationTarget, @context}` and RDFC-signs *that*, with the invocation fields living in the signed body **and** duplicated into the proof (`SigningService.SignInvocationProofAsync` SigningService.cs:177-219 → `ProofSigningPayloadBuilder.CanonicalizeInvocationRdfc` ProofSigningPayloadBuilder.cs:112-127). `@digitalbazaar/zcap` **never does this.** Even on identical RDFC the signed N-Quads differ, so the `proofValue` is over different bytes and cross-stack verification fails.

### What db actually signs/verifies — two shapes
- **(A) Data Integrity (DI) `capabilityInvocation` proof** — db signs an **arbitrary application payload** (even an empty `{}`) and attaches a proof whose `proofPurpose=capabilityInvocation`. The invocation metadata (`capability`, `capabilityAction`, `invocationTarget`) lives **only in the proof** (`lib/CapabilityInvocation.js` `update()` lines 153-159; `_getTailCapability` returns `{capability: proof.capability}`). `capability` is the **root id string** OR the **full embedded delegated zcap object** (delegated-as-id-only is rejected). No `capabilityChain` on the invocation proof. Signed bytes = `SHA256(canonicalize(proofOptions)) || SHA256(canonicalize(applicationDoc))`.
- **(B) HTTP Signatures** — the real-world ezcap/`ZcapClient.request` wire (`@digitalbazaar/http-signature-zcap-invoke`). **No JSON-LD, no RDFC.** `capability-invocation` header (root: `zcap id="...",action="..."`; delegated: `zcap capability="<base64url(gzip(json))>",action="..."`) + an HTTP-Signature `authorization` header over `['(key-id)','(created)','(expires)','(request-target)','host','capability-invocation'(,content-type,digest)]`, signature **base64 (not multibase)**. The server reconstructs the same DI proof and runs the **same** `CapabilityInvocation.validate` core (`http-signature-zcap-verify/lib/index.js:203-220`).

### Recommended target: **A first, then B**
Path A is the minimal JSON-LD-native change — it reuses zcap-dotnet's existing RDFC + Ed25519Signature2020 `LegacyProofCrypto` stack and the **already-installed** harness (`interop/js/node_modules` has zcap 9.0.1 + `jsonld-signatures` + `@digitalbazaar/ed25519-signature-2020`; nothing else needed). Path B is the dominant *deployed* protocol but needs new npm deps and a separate header builder; ship it as a follow-up.

### Exact zcap-dotnet changes (Path A)
- **`ProofSigningPayloadBuilder.CanonicalizeInvocationRdfc`** (ProofSigningPayloadBuilder.cs:112-127) — **rewrite**: `document` = the **application payload** (default `{}` when bodyless), **not** `ToFieldDictionary(invocationWithoutProof)`; `proofOptions` = proof minus `proofValue`; set `proofOptions["@context"]` to the **array** `["https://w3id.org/zcap/v1","https://w3id.org/security/suites/ed25519-2020/v1"]` (not the bare string at line 116/119/122). `CloneInvocationWithoutProof` (ProofSigningPayloadBuilder.cs:56-68) becomes irrelevant to the signed bytes.
- **`SigningService.SignInvocationProofAsync`** (SigningService.cs:177-219) — sign `SHA256(canonicalize(proofOptions)) || SHA256(canonicalize(applicationDoc))`; set `proof.Context` to the suite-aware array; **truncate `created` to second precision** (db does `.toISOString().slice(0,-5)+'Z'`); keep `capability`/`capabilityAction`/`invocationTarget` **only** in the proof.
- **`VerificationService.VerifyInvocationCoreAsync`** (VerificationService.cs:505-654) — read the invocation fields from the **proof** (already does, ~578-585) but **drop** the requirement that they also appear in a self-contained `Invocation` body (current hard-requires `invocation.Id` at 518-522 and `invocation.Capability` matching at 552-555); consistency-check against the application payload + invoked capability instead. Add **`@context` value validation on the proof** (MUST include `https://w3id.org/zcap/v1` — mirrors db `utils.checkProofContext`). Keep delegated-embed-required (matches db). Recompute the signature over `proofOptions || applicationDoc`.
- **`Invocation.cs`** — stop treating it as the signed document; add an optional `object? Payload` (application doc) the proof attaches to, with `id` demoted to a local replay nonce.
- **`InvocationCapability.cs`** — **no change**; it already models db's exact `root-id-string | full-embedded-delegated-object` union (`FromCapability`/`FromId`/`IsRootReference`). Only ensure the embedded delegated zcap serializes byte-for-byte (context-array-first, second-precision dates, no null members).
- **`ZcapSuiteCatalog`** — expose the per-proof-type DI context URL (ed25519-2020/v1, already catalogued at ZcapSuiteCatalog.cs:25 and served by `RdfcContextDocumentLoader.cs:29-30`) so capability- and invocation-proof paths build identical `@context` arrays from one source.

### The `@context` fix (item: `rdfc-invocation-suite-context`)
Today both production (`LegacyProofCrypto.BuildDocumentElement` LegacyProofCrypto.cs:117-130, bare `ZcapContext` at LegacyProofCrypto.cs:26/125) and the test oracle (ProofSigningPayloadBuilder.cs:119/122) inject **only** `zcap/v1`. Ed25519Signature2020 proof terms (`proofValue`/`created`/`verificationMethod`) come from the **suite** context, so without `https://w3id.org/security/suites/ed25519-2020/v1` they won't JSON-LD-expand to db's terms. Mirror the *delegation* path, which already does this (CapabilityService.cs:120-124; `CanonicalizeCapabilityRdfc` ProofSigningPayloadBuilder.cs:103-105). **This fix is only validatable once the envelope is fixed** — there is no invocation round-trip today.

### Harness round-trip
Add `interop/js/invoke-verify.mjs` using `jsigs.verify(applicationDocument, {suite: new Ed25519Signature2020(), purpose: new CapabilityInvocation({expectedAction, expectedTarget, expectedRootCapability: urn:zcap:root:<encodeURIComponent(target)>, suite}), documentLoader})`. Reverse direction uses `jsigs.sign(...)` with `purpose: new CapabilityInvocation({capability, capabilityAction, invocationTarget})`. Wire 4 cases into `run-interop.sh` (currently delegation-only, lines 13-14): dotnet-sign→db-verify (PASS), db-sign→dotnet-verify (PASS), tamper-each→reject (FAIL).

---

## 3. Spec-compliance closeouts (verify-path MUST/MUST NOT)

The create path already enforces all of these; they are simply not called by the crypto verify paths (`VerificationService` never calls `CapabilityService.ValidateCapabilityAsync` — see the in-code note at VerificationService.cs:904). Natural homes: `ValidateRootCapabilityInvariants` (the shared root chokepoint, VerificationService.cs:1428-1450, reached from chain-build :1084 and standalone :1417) for roots; the `VerifyBuiltChainAsync` per-link loop (VerificationService.cs:883-954) for delegated links.

| ID | Level | Gap | One-line fix |
|----|-------|-----|--------------|
| **R-CTX-1-ROOT** | MUST | Root `@context` **value** never checked on verify | In `ValidateRootCapabilityInvariants`, require `root.Context` to be the exact string `https://w3id.org/zcap/v1`; else `MalformedCapability`. |
| **R-CTX-2-DELEGATED** | MUST | Delegated `@context[0]` value/order never checked | In the `VerifyBuiltChainAsync` loop (chain[1..]), require `child.Context` to be an array whose **[0]** equals `https://w3id.org/zcap/v1` (positional, matching db). |
| **R-CTX-2-SUITE** (NEW item) | MUST | Suite context presence in delegated `@context` not checked | Same loop: also assert the signing suite's context (ed25519-2020/v1) is present so proof terms expand. |
| **R-ROOT-NOEXTRA** | MUST NOT | Verify rejects only `parentCapability`/`proof`/empty-controller/bad-target (4 of 8); **misses** root `expires`/`allowedAction`/`caveat`/`AdditionalProperties` | Extend `ValidateRootCapabilityInvariants` to reject `root.Expires`/`root.AllowedAction`/`root.Caveat != null` and `root.AdditionalProperties is { Count: > 0 }` — parity with CapabilityService.cs:262-271. (Per the report, root-`expires` is the only *active* db divergence; the other three are the spec MUST NOT.) |

All four are reachable from the invocation path via chain dereference and are exactly what db enforces (`utils.checkCapability`).

---

## 4. Semantic / documentation-only gaps (no code)

| Item | Reality | Action |
|------|---------|--------|
| **P-256 (`R-P256-NO-COUNTERPART`)** | `ZcapSuiteCatalog.cs:27-30` registers EcdsaSecp256r1Signature2019; db ships **Ed25519 only** and serves no ecdsa-2019/v1 context. The P-256 did:key VM type (`DidKeyResolver.cs:167` → `EcdsaSecp256r1VerificationKey2019`) is non-canonical but self-consistent .NET-to-.NET. **Not a spec violation** (suite-neutral). | Already documented in `docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md:64,85`. **Residual:** surface the warning in README/ARCHITECTURE or an XML doc-comment on the P256 catalog entry: "Ed25519Signature2020 required for guaranteed cross-stack interop." |
| **Custom caveats (`R-CUSTOM-CAVEATS-OPAQUE`)** | zcap-dotnet enforces UsageCount/ValidWhileTrue chain-wide (`CaveatProcessor` → VerificationService.cs:633); db has no engine and **silently un-enforces** them, granting access zcap-dotnet would deny. Inherent divergence — no fix. | Loud warning already in interop-analysis doc (lines 65/118/135). **Residual:** one sentence in README.md + a `/// remarks` on `UsageCountCaveat`/`ValidWhileTrueCaveat`: "NOT enforced by @digitalbazaar/zcap; for cross-stack security rely only on `expires`/`allowedAction`/`invocationTarget`." |

---

## 5. Sequenced plan (the to-do list)

> Branch first per repo policy (`git checkout -b <issue>-<slug>`); rebase onto `origin/main` before the first edit.

| # | PR | Effort | Depends on | Acceptance criterion |
|---|----|--------|-----------|----------------------|
| **1** | **Verify-path `@context` value + order + suite-presence** (R-CTX-1/2 + NEW) | **S** | — | Unit tests: a hand-crafted root with `@context != zcap/v1` and a delegated with `@context[0] != zcap/v1` (or missing suite context) are rejected with `MalformedCapability`; all existing delegation interop cases still pass. |
| **2** | **Verify-path root extra-field rejection** (R-ROOT-NOEXTRA) | **S** | — (independent of #1) | A wire/resolver root carrying `expires`/`allowedAction`/`caveat`/extra `AdditionalProperties` is rejected on the crypto verify path; parity with CapabilityService.cs:262-271 proven by test. |
| **3** | **Doc-only divergence callouts** (P-256, custom caveats) | **S** | — | README.md + XML doc-comments carry the cross-stack warnings; `docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md` items 7-style notes marked done. |
| **4** | **Invocation DI envelope — sign + verify** (#117 / R-INV-ENVELOPE + R-INV-RDFC-CONTEXT) | **L** | #1 (reuses the `@context` value check on the proof) | zcap-dotnet emits a `{applicationDocument, proof}` DI invocation; `interop/js/invoke-verify.mjs` `jsigs.verify` returns `verified: true`; reverse (`jsigs.sign` → dotnet verify) passes; tamper rejects. |
| **5** | **Invocation interop wired into harness** | **M** | #4 | `interop/run-interop.sh` round-trips an invocation **both directions** (dotnet→db, db→dotnet) plus tamper-reject, alongside the existing delegation cases; CI green. |
| **6** | **HTTP-Signature invocation envelope** (`ZcapHttpSignature` builder/verifier — Path B) | **L** | #4 (shares the `CapabilityInvocation` validation semantics; needs new npm deps) | New harness case verifies dotnet-emitted `capability-invocation`+`authorization` headers via `@digitalbazaar/http-signature-zcap-verify`; root + delegated (gzip+base64url) + base64 signature + digest header round-trip. |

**Rationale:** #1-#3 are quick, independent spec/doc closeouts that can land immediately and raise compliance without touching the envelope. #4 is the keystone (the actual interop blocker) and depends on the proof-`@context` value check from #1. #5 proves #4 end-to-end. #6 delivers the dominant real-world transport but is a clean follow-up requiring no crypto-core changes.

---

## 6. Honest caveats

- **DI-proof vs HTTP-Signature is the key open question.** `@digitalbazaar/zcap`'s *own tests* exercise the DI `capabilityInvocation` proof (Path A), and the harness already has those packages — so A is the safest, lowest-friction target to *prove* interop. **But the actually deployed real-world wire is HTTP Signatures** (ezcap `ZcapClient.request` via `http-signature-zcap-invoke`), which needs no RDFC at all. If the consuming use case is "talk to a live db HTTP service," **Path A alone is insufficient** and #6 becomes mandatory, not optional. **Resolver:** confirm the concrete deployment target (library-level jsigs interop vs HTTP service calls) before committing #6's scope.
- **Second-precision `created` and byte-exact embedded-zcap serialization are unproven until the round-trip runs.** db truncates to second precision and expects context-array-first, no-null-member JSON; any drift fails silently as a signature mismatch. #4's acceptance test is the only real validation — do not trust unit tests alone.
- **The suite-context `@context` fix (#4) cannot be validated in isolation** — there is no invocation round-trip today, so it must land *with* the envelope change, not before.
- **R-ROOT-NOEXTRA strictness — RESOLVED (PR #118 review).** db's `checkCapability` *ignores* unknown root fields and rejects only root `expires`; `Capability.AdditionalProperties` (`[JsonExtensionData]`) exists to round-trip such fields. So `expires`/`allowedAction`/`caveat` are rejected **unconditionally** on the verify path, while rejecting **unknown/unmodeled** root fields is gated behind the opt-in `VerificationPolicy.RejectUnknownRootFields` (default `false`) — strict-conformance verifiers opt in; the default stays db-compatible.
- **No gaps were invented beyond the verified inputs.** Items classified `partial`/doc-only by the verifier (P-256, custom caveats) are treated as documentation tasks, not code blockers, per their confirmed verdicts.
