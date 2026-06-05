# Issue #51 — Support delegated DI invocation `capability` as full zcap object

**Branch:** `51-delegated-di-invocation-full-zcap`
**Spec:** W3C CCG ZCAP-LD v0.3 — *Invoking a Delegated ZCAP*: "When invoking using a DI proof, the `capability` property must express the full delegated zcap."

## Evaluation result (confirmed by workflow + direct inspection)

Issue is **still open**. Today the `capability` field is string-only end-to-end:
- `Invocation.Capability` is `string` ([Invocation.cs:29](../src/ZcapLd.Core/Models/Invocation.cs#L29)).
- `Proof.Capability` is `object?` with **no** `JsonConverter` → embedded objects round-trip as a `JsonElement` read as a string ([Proof.cs:98](../src/ZcapLd.Core/Models/Proof.cs#L98)).
- Signing copies the string ID into the proof; no root/delegated branch ([SigningService.cs:197](../src/ZcapLd.Core/Services/SigningService.cs#L197)).
- Verification compares everything by string equality / `TryExtractStringValue` ([VerificationService.cs:442,449-452](../src/ZcapLd.Core/Services/VerificationService.cs#L442)).
- No test embeds a full delegated zcap object.

## Design decisions (approved by user)

1. **Dedicated `InvocationCapability` union type** + `InvocationCapabilityJsonConverter` (string ID for root, embedded `Capability` for delegated). Implicit `string` conversion for source compat.
2. **Strict spec mode** — when the invoked capability is delegated (`parentCapability` set), `invocation.capability` MUST embed the full zcap; a bare ID string is rejected.

---

## Plan

### Phase A — Model
- [ ] A1. Add `src/ZcapLd.Core/Models/InvocationCapability.cs`: sealed type with `Id` (root ref), `EmbeddedCapability` (delegated), `IsRootReference`, `CapabilityId => EmbeddedCapability?.Id ?? Id!`. Factory: `FromId(string)`, `FromCapability(Capability)`, `implicit operator InvocationCapability(string)`.
- [ ] A2. Add `InvocationCapabilityJsonConverter` (in `Cryptography/`, wired into `ZcapJsonOptions.Default`): `Write` emits a JSON string for root refs and a full embedded object (via the shared model options) for delegated; `Read` branches on `JsonTokenType.String` vs `StartObject`, deserializing the object into `Capability`. Throw on any other token (malformed reject).
- [ ] A3. Change `Invocation.Capability` from `string` → `InvocationCapability` (default empty). Keep `[JsonPropertyName("capability")]`.
- [ ] A4. Change `Proof.Capability` from `object?` → `InvocationCapability?` (reuses the converter; `[JsonIgnore(WhenWritingNull)]`). Remove the now-dead `TryExtractStringValue` path for capability.

### Phase B — Signing
- [ ] B1. `SigningService`: `proof.Capability = invocation.Capability` now carries the union faithfully; the embedded object flows into the proof and signed payload automatically. Add a guard: if signing a delegated invocation, the embedded capability must be present and carry its delegation proof.
- [ ] B2. (Ergonomics) Add `CapabilityService.CreateInvocation(...)` overloads/helpers: one for a root ID string, one that embeds a delegated `Capability`. Keeps callers from hand-building the union.

### Phase C — Canonicalization
- [ ] C1. `ProofSigningPayloadBuilder.CloneInvocationWithoutProof`: strip only the **invocation's** top-level proof; **preserve** the embedded delegated zcap and its own delegation `proof` + `capabilityChain`. Confirm the union serializes deterministically under JCS (sorted keys, embedded object included).
- [ ] C2. Verify sign-time bytes == verifier-time bytes over a delegated invocation wire body.

### Phase D — Verification (strict)
- [ ] D1. `VerifyInvocationAsync`: branch on `string.IsNullOrEmpty(capability.ParentCapability)`.
  - **Root:** `invocation.Capability` MUST be a root ref (string) whose `CapabilityId == capability.Id`. Reject embedded-object form for root (or accept id-match — default: require string for root, per spec).
  - **Delegated (strict):** `invocation.Capability` MUST be `EmbeddedCapability != null`; reject string-only. The embedded id MUST equal `capability.Id`; validate the embedded zcap's delegation proof + `capabilityChain` by reusing `ValidateDelegationChain` / `TryExtractEmbeddedParentFromProofChain` / `ValidateAttenuation`.
- [ ] D2. Replace the `proof.Capability` consistency check: compare `invocation.Proof.Capability.CapabilityId` (and shape) against `invocation.Capability` via the union, not `TryExtractStringValue`.
- [ ] D3. Ensure caveat inheritance / expiry / revocation / replay all still run against the embedded delegated zcap.
- [ ] D4. Audit the revocation invocation path (`Invocation.RevokeAction`) — ensure a delegated revocation embeds the full object under strict mode.

### Phase E — Tests (add, per issue "Tests to Add")
- [ ] E1. Model/serialization: root→string round-trip; delegated→object round-trip; serialize delegated with full embedded zcap; malformed `capability` rejected.
- [ ] E2. Signing: root invocation → string in `proof.capability`; delegated → full object in `proof.capability` + signed payload.
- [ ] E3. Verification: root verifies; delegated-with-object verifies; **delegated string-only rejected**; embedded id mismatch rejected; embedded chain/proof invalid rejected.
- [ ] E4. Cross-language/canonical: pin JCS canonical bytes for a delegated invocation proof with embedded zcap; assert sign-time == verify-time bytes.

### Phase F — Migrate impacted call sites + docs
- [ ] F1. Update existing **delegated**-invocation tests/examples to embed the full zcap (strict mode). Root-invocation sites keep compiling via implicit string conversion. Files to audit: `CrossLanguageJcsInteropTests.cs`, `NormativeIntegrationComplianceTests.cs`, `EndToEndTests.cs`, `RdfcEndToEndTests.cs`, `VerificationServiceTests.cs`, `VerificationServiceReplayTests.cs`, `examples/ZcapLd.Examples/Program.cs`, `src/ZcapLd.Core/PACKAGE_README.md`.
- [ ] F2. Update docs: `README.md`, `ARCHITECTURE.md`, relevant `docs/`, and the auto-memory `MEMORY.md` note for the new union type.
- [ ] F3. `dotnet build ZcapLd.sln` + `dotnet test ZcapLd.sln` green. Update this file's review section + `tasks/lessons.md` if any correction occurs.

## Risks / notes
- **Breaking change** (intended): strict mode rejects string-only delegated invocations; `Invocation.Capability` type changes (mitigated by implicit `string` conversion for root). Warrants a minor/major version bump + changelog note.
- Reuse existing chain-validation helpers rather than duplicating — the embedded zcap is just another `Capability` to run through the established delegation-chain validator.
- Keep JCS determinism: the embedded object must serialize through the same `ZcapJsonOptions.Default` so cross-stack bytes match.

## Review (completed)

**Outcome:** Issue #51 resolved. Delegated DI invocations now carry the full embedded delegated zcap;
strict verification rejects a delegated invocation that supplies only an id string. Root invocations
keep the id-string shape. **436 tests green** (was 423; +13 new #51 compliance tests), full solution
builds clean, and all 11 console examples run with expected output.

**Rebase note:** Before implementing, rebased onto `origin/main`, which had advanced 4 commits including
#50 ("spec-exact capabilityChain"), a 403-line refactor of `VerificationService`. Re-read the
refactored verification (new `BuildCapabilityChainAsync` / `IRootCapabilityResolver` / `explicitRoot`)
and confirmed #51 was still open before proceeding.

**What shipped:**
- `Models/InvocationCapability.cs` — sealed union (root-id string | embedded `Capability`), implicit
  `string` conversion, `FromId`/`FromCapability`, `CapabilityId`/`IsRootReference`/`EmbeddedCapability`.
- `Cryptography/InvocationCapabilityJsonConverter.cs` — string ⇄ id, object ⇄ full `Capability`
  through shared `ZcapJsonOptions.Default`; rejects malformed (non-string/object, embedded w/o id).
- `Invocation.Capability` `string`→`InvocationCapability`; `Proof.Capability` `object?`→`InvocationCapability?`.
- `VerificationService.VerifyInvocationCoreAsync` — strict root-vs-delegated branch (root MUST be id
  string; delegated MUST embed the full zcap, id-bound to the verified capability); proof/body shape
  consistency. Revocation path updated to `.CapabilityId` but stays lenient (id string).
- **No change needed** in `SigningService` (union assignment aligns) or `ProofSigningPayloadBuilder`
  (`CloneInvocationWithoutProof` copies the union; `ToFieldDictionary` serializes the embedded object
  via the converter) — the embedded zcap flows into the signed payload automatically.
- Migrated all delegated-invocation call sites in tests + examples to `InvocationCapability.FromCapability(...)`.
- Docs: README, PACKAGE_README, ARCHITECTURE.md, AGENTS.md updated. `docs/IMPLEMENTATION-COMPLETE.md`
  left as a stale historical record (already out of sync with #50).

**Breaking change (rides into the unreleased 3.0.0):** `Invocation.Capability` / `Proof.Capability`
types changed; delegated invocations must embed the full zcap. Mitigated for root/revocation paths by
the implicit `string` conversion.

**New tests** (`tests/Compliance/DelegatedInvocationComplianceTests.cs`, 13): model round-trips
(root string / delegated object / malformed reject ×2), signing (root→string, delegated→object in
proof.capability), verification (root ✓, delegated ✓, delegated-string-only ✗, embedded-id-mismatch ✗,
embedded-chain-invalid ✗), canonicalization (pinned JCS bytes for the embedded shape, sign-time ==
wire-time bytes).
