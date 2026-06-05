# Issue #70 [L5] — Structured failure-reason channel for verification

Branch: `70-verification-result-channel` (off refreshed `main` @ 28a6d2d, after PR #97/#51 merged).

## Problem (from the workflow evaluation)
- All `IVerificationService` verify methods return bare `Task<bool>`; the 8 distinct failure
  modes (revoked, expired, bad signature, broken chain, unauthorized controller, caveat failure,
  replay, chain-too-long) collapse to `false`. Consumers must re-derive the reason.
- Part-B logging (issue #64) only fires on the **exception** path; the structurally-valid denial
  branches (revoked/expired/signature/replay/…) return `false` silently.

## Design (additive, non-breaking)
New public types in `Models/`:
- `VerificationOutcome` enum: `Valid`, `MalformedCapability`, `InvalidSignature`,
  `UnauthorizedController`, `InvalidDelegation`, `AttenuationViolation`, `ChainTooLong`,
  `Expired`, `Revoked`, `CaveatFailed`, `Replayed`, `InvalidTarget`, `ActionNotAllowed`,
  `CouldNotVerify` (the M7 "couldn't check" case).
- `VerificationResult` record: `Outcome`, `Message?`, `IsValid`, `Valid` static, `Fail(...)`.

`IVerificationService`: add `...DetailedAsync` siblings returning `Task<VerificationResult>` for
proof (×2), invocation (×3), chain (×2). Keep existing `Task<bool>` methods as thin wrappers
(`=> (await ...DetailedAsync(...)).IsValid`). Revocation stays `bool` (control-plane, out of scope).

`VerificationService`: thread `VerificationResult` through the internal verify helpers
(`VerifyCapabilityProofCoreAsync`, `VerifyDelegationProofAsync`, `VerifySingleDelegationProofAsync`,
`VerifyInvocationCoreAsync`, `VerifyCapabilityChainCoreAsync`, `VerifyBuiltChainAsync`); each early
`return false` becomes `return VerificationResult.Fail(outcome, msg)`. Add a single `LogAndReturn`
choke point on the public boundary that logs every non-`CouldNotVerify` denial at Debug (closes the
part-B gap; `CouldNotVerify` already logged with type-aware severity by `LogFailedClosed`).

## Tasks
- [x] `Models/VerificationOutcome.cs`
- [x] `Models/VerificationResult.cs`
- [x] `IVerificationService.cs`: 7 `...DetailedAsync` methods + XML docs
- [x] `VerificationService.cs`: thread results, bool wrappers, `LogDenial` (named `LogDenial`, not `LogAndReturn`)
- [x] Build green (whole solution — 0 errors; Core 0 warnings)
- [x] Tests: `tests/.../Services/VerificationResultTests.cs` — 16 tests, one per outcome + bool parity + null-throw
- [x] All tests green (Core 458, AspNetCore 6, 0 failures)
- [x] Docs: ARCHITECTURE.md, README.md (verify API), AGENTS.md notes, MEMORY.md
- [x] Review section + lessons

## Verification
- Every named failure mode maps to a distinct `VerificationOutcome`. ✓ (16 tests assert each)
- `bool` methods unchanged in behavior (fail-closed); `(await Detailed).IsValid == bool`. ✓ (parity test + 227 pre-existing Services tests still green)
- Denial reasons now logged on ALL paths, not just exceptions. ✓ (`LogDenial` boundary choke point)

## Review (2026-06-05)
**Delivered both asks of #70.** (A) PRIMARY: public `VerificationResult`/`VerificationOutcome` + 7
`...DetailedAsync` overloads; bool methods are now `(await Detailed).IsValid` wrappers. (B) MINIMUM:
denials logged on every path via `LogDenial` (Debug severity, attacker-aware), not just the exception
path — and `CouldNotVerify` makes the M7/#64 "couldn't check vs invalid" distinction explicit at the API.

**Design choice:** threaded `VerificationResult` through the internal verify helpers rather than mapping
at the surface — each early `return false` became a specific outcome at the orchestration layer where
the checks are already separate statements, so the mapping is unambiguous. Multi-proof loop
(`VerifyDelegationProofAsync`) aggregates by returning the last specific failure (exact in the common
single-proof case). Per-proof catch classifies expected validation exceptions → `InvalidDelegation`,
unexpected → `CouldNotVerify` (mirrors `LogFailedClosed` severity split).

**Scope held:** revocation methods stay `bool` (control-plane; #70 is about *verify*). No interface
consumers broke — `VerificationService` is the only implementer; `SigningService`, AspNetCore endpoints,
and examples use the bool methods, all preserved.

**Files:** +`Models/VerificationOutcome.cs`, +`Models/VerificationResult.cs`,
`IVerificationService.cs` (+7 methods), `VerificationService.cs` (threaded results + `LogDenial`),
+`tests/.../VerificationResultTests.cs` (16), docs (ARCHITECTURE/README/AGENTS/MEMORY).

**Not done (left to user):** GitHub issue #70 not closed/commented — awaiting review. Branch
`70-verification-result-channel` not committed/pushed (per repo policy: commit only when asked).
