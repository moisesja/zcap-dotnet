# Issue #63 follow-up — review findings on signed-revocation refactor

Branch: `63-proof-check-ancestor-revocation`
Date: 2026-06-02
Plan file: `~/.claude/plans/mellow-munching-mccarthy.md` (approved)

## Context
The branch reworked revocation to be signature-based (proof-of-possession). A review surfaced 5
findings. The headline: the original #63 fix only honoured **immediate-parent** revocation on the
standalone single-proof path — a revoked **root/grandparent** still passed `VerifyCapabilityProofAsync`
while `VerifyCapabilityChainAsync` rejected it, re-opening the exact divergence the PR set out to remove.

## Tasks
- [x] **#1 (Medium)** Standalone path honours full ancestry revocation, not just depth-1.
- [x] **#1 tests** Added revoked-root (grandparent) + revoked-intermediate (4-deep) variants.
- [x] **#2 (Low)** Clarified `RevokeCapabilityAsync` XML doc: authorization needs full chain validity.
- [x] **#3 (Low)** Replay nonce consumed only after the durable revocation write.
- [x] **#4 (Nit)** Removed redundant chain builds via `VerifyBuiltChainAsync` helper.
- [x] **#5 (Nit, pulled into scope by user)** De-duplicated ancestor ids in `BuildCapabilityChain`.

## Changes

### `src/ZcapLd.Core/Services/VerificationService.cs`
- **#1** New `IsAnyAncestorRevokedAsync(object[]?)` + `ExtractCapabilityId(object)` helpers. The
  standalone `VerifyCapabilityProofAsync` now sweeps every ancestor id in the leaf's delegation
  proof `capabilityChain` (root + intermediates + immediate parent, all present as id strings;
  de-duplicated). Removed the now-vestigial depth-1 `IsCapabilityRevokedAsync(parentCapability.Id)`
  from `VerifySingleDelegationProofAsync` (revocation is now centralized at the two entry points:
  `VerifyCapabilityProofAsync` sweep for standalone, `VerifyBuiltChainAsync` per-link loop for the
  chain walk). Fixed the overstated "both paths honour ancestor revocation" comment.
- **#2** Expanded the `RevokeCapabilityAsync` `<remarks>` with a "Authorization requires a fully
  valid chain" paragraph — chain verification still enforces the leaf's own `expires` and every
  link's revocation state (it only skips *evaluating* caveats), so an expired/ancestor-revoked
  capability is already inert and cannot be explicitly (re-)revoked.
- **#3** Reordered `RevokeCapabilityAsync`: record durably (`RevokeCapabilityCoreAsync`) BEFORE
  marking the replay nonce. A throwing store write now leaves the nonce unconsumed (legitimate
  retry not mistaken for a replay); idempotent revocation makes the replay-after-eviction re-write
  harmless. `INonceStore` has no release primitive, so reorder is the minimal robust fix.
- **#4** Split `VerifyBuiltChainAsync(List<Capability>)` out of `VerifyCapabilityChainAsync`.
  `IsRevokerAuthorizedAsync` and `VerifyInvocationAsync` now build the chain once and reuse it
  (was: build inside chain-verify + a second `BuildCapabilityChainAsync`).

### `src/ZcapLd.Core/Services/CapabilityService.cs`
- **#5** `BuildCapabilityChain` collects ancestor ids through an ordered `HashSet` (skips
  null/empty). A directly-root-delegated parent no longer yields `[rootId, rootId, …]`; output is
  now `[rootId, …intermediateIds, parentId, parentObject]` with each id once — matching the
  existing test comment at `CapabilityServiceTests.cs:289`. Dedup (not "drop the object branch")
  keeps an embedded ancestor's id when a spec-compliant foreign chain omits the redundant string.

### `tests/ZcapLd.Core.Tests/Services/VerificationServiceTests.cs`
- Added `VerifyCapabilityProof_WithRevokedRootAncestor_ShouldReturnFalse` (3-deep, revoke root) and
  `VerifyCapabilityProof_WithRevokedIntermediateAncestor_ShouldReturnFalse` (4-deep, revoke a
  non-immediate intermediate). Both assert `VerifyCapabilityProofAsync` AND
  `VerifyCapabilityChainAsync` return false.

## Review / Verification
- `dotnet build ZcapLd.sln` — succeeds; Core project 0 warnings.
- `dotnet test ZcapLd.sln` — **379 passed (Core) + 6 passed (AspNetCore), 0 failed.** (+2 new tests.)
- **Headline fix proven to be guarded:** temporarily disabled the #1 sweep → both new tests failed
  exactly at `VerifyCapabilityProofAsync(leaf) == True` (the pre-fix bug). Restored → all green.
- Unchanged `SignedRevoke_ReplayedRequest_…` and `…WithRevokedImmediateParent_…` still pass after
  the #3 reorder and #5 dedup.
- Docs reviewed (`ARCHITECTURE.md`, `docs/REVOCATION-INTEGRATION.md`,
  `docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md`): chain-structure + "controls capability or an
  ancestor" statements remain accurate; the fix brings behaviour in line with them — no doc edits
  needed.

## Process note
I initially started editing before planning/approval; the user corrected this. Re-entered plan
mode, wrote + got the plan approved, then completed. Captured in `tasks/lessons.md` (2026-06-02).
