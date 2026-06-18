# Recommended interop code fixes (RDFC-only, attenuation, root-id)

Branch: `rdfc-default-attenuation-rootid-fixes` (off origin/main @ #115 merged).
User decision: **full compliance — remove JCS entirely, no backwards compatibility.**

## Fix #2 — allowedAction omit-to-widen (spec MUST, security)
- [ ] `VerificationService.ValidateAttenuation` (~1200): when parent restricts
      allowedAction, require child present AND subset (reject null/empty child).
- [ ] `CapabilityService.ValidateAttenuation` (create, ~314): when parent
      restricts, reject null/empty `allowedActions`.
- Only bites when an ANCESTOR restricts (roots have no allowedAction, so
  first-level "omit = all" stays valid). Matches digitalbazaar hasValidAllowedAction.

## Fix #3 — root-id encodeURIComponent parity
- [ ] Add `UriEncoding.EncodeUriComponent` (un-escape %21 %27 %28 %29 %2A).
- [ ] Use it in `CapabilityService` root-id derivation (was `Uri.EscapeDataString`).
- Verify path decodes via UnescapeDataString (round-trips) — no change needed.

## Fix #1 — remove JCS, RDFC-1.0 only (BREAKING, no back-compat)
- [ ] `LegacyProofCrypto`: always RDFC; drop JCS branch + ValidateCanonicalizationMethod.
- [ ] `SigningService`: drop 3-arg ctor + `_canonicalizationMethod`; always RDFC.
- [ ] `VerificationService`: drop `canonicalizationMethod` param everywhere; always RDFC.
- [ ] `ProofSigningPayloadBuilder`: drop JCS methods (keep RDFC).
- [ ] Delete `JcsDocumentCanonicalizer.cs`, `JsonCanonicalizer.cs` (if unused after).
- [ ] DI: drop `AddZcapRdfcCanonicalization` + `RdfcCanonicalizationMarker` + resolver; wire RDFC always.
- [ ] Tests: delete JCS-only tests; update RdfcEndToEnd/interop/examples to drop param.
- [ ] Docs: AGENTS.md, README, architecture, interop report (RDFC is the only mode now).

## Verify
- [x] `dotnet test ZcapLd.sln` green — 443 Core + 33 AspNetCore.
- [x] `interop/run-interop.sh` still passes (all 6) after API change.

## Review (2026-06-18) — DONE ✅

All three fixes implemented + regression-tested; version bumped to **4.0.0** (breaking).

- **#1 RDFC-only**: removed JCS entirely. `SigningService`/`VerificationService` drop the
  `canonicalizationMethod` param; `LegacyProofCrypto`/`ProofSigningPayloadBuilder` are RDFC-only;
  deleted `JcsDocumentCanonicalizer.cs` + `JsonCanonicalizer.cs`; removed `AddZcapRdfcCanonicalization()`
  + `RdfcCanonicalizationMarker`. Deleted/converted JCS tests; re-pinned `ProofGoldenVectorTests`
  proofValue to the RDFC value (`zaBYygkT…`). **Side effect:** revocation `reason`/`metadata` are
  informational under RDFC (undefined JSON-LD terms dropped from N-Quads); bound fields + revoker
  auth unaffected. Repurposed `SignedRevoke_TamperedReason_*` test accordingly.
- **#2 allowedAction omit-to-widen**: rejected on verify (`VerificationService.ValidateAttenuation`)
  + create (`CapabilityService.ValidateAttenuation`). New tests: `VerifyChain_ChildOmits…`,
  `DelegateCapability_OmitsAllowedActionUnderRestrictingParent_Throws`.
- **#3 root-id**: `UriEncoding.EncodeUriComponent` (un-escapes %21 %27 %28 %29 %2A). New test:
  `CreateRootCapability_EncodesInvocationTargetLikeEncodeUriComponent`.
- Docs: AGENTS.md, README.md, ARCHITECTURE.md, CHANGELOG (4.0.0), interop report §6 marked done.
- Examples Example 10 rewritten (was "RDFC vs JCS"); interop CLI updated to the new API.
