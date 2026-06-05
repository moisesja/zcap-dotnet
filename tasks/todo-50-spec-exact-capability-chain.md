# Issue #50 — Generate & verify spec-exact `capabilityChain`

Branch: `50-spec-exact-capability-chain`. Spec: https://w3c-ccg.github.io/zcap-spec/

## Problem (confirmed via multi-agent evaluation, 3/3 skeptics high-confidence)

`CapabilityService.BuildCapabilityChain` produced a non-spec `capabilityChain`: it **embedded the
root** at first level (`[rootId, {root}]`) and emitted the immediate parent **both** as an id-string
*and* embedded at deeper levels. The verifier was hard-coupled to that shape (required `Length >= 2`
with an embedded last entry, so it would reject a spec-exact `[rootId]`) and had no way to resolve a
root referenced by id. Because `capabilityChain` is inside the signed proof, this breaks strict
cross-language verification.

## Plan items

- [x] Rewrite `BuildCapabilityChain` → spec-exact (`[rootId]` / `[rootId, {D1}]` / `[rootId, D1.id, {D2}]`); reuse the 4-way id extractor; drop the double-emit.
- [x] Add `IRootCapabilityResolver` (+ `InMemoryRootCapabilityResolver` dev impl) and explicit-root overloads on `IVerificationService` (`VerifyCapabilityChainAsync`, `VerifyCapabilityProofAsync`, `VerifyInvocationAsync`, `RevokeCapabilityAsync`).
- [x] Thread root resolution into the verifier (chain walk **and** standalone single-proof path) with precedence *explicit → resolver → fail-closed*; bind the root (id + target-encoding) to prevent substitution.
- [x] Strict shape validation rejecting non-spec chains (embedded root, duplicate ids, parent both id+embedded, wrong/missing embedded parent, out-of-order ancestors) — single helper shared by both verifier paths.
- [x] Auto-detect an `IDidResolver` that also implements `IRootCapabilityResolver` (mirrors the existing `IVerificationRelationshipResolver` pattern) → zero ctor churn in tests/consumers.
- [x] Tests: new `CapabilityChainShapeTests` (generation L1/L2/L3 + accept + fail-closed + 4 negative shapes); registered roots via per-file helper / explicit-root overloads; rewired AspNetCore revocation integration tests; recast the inverted-intent test; fixed misleading embedded-root literals.
- [x] AspNetCore `AddZcapRootCapabilityResolver<T>()` + DI wiring; console + revocation-demo examples register roots.
- [x] Docs: README (new "Delegation Chains & Root Resolution" + 3.0.0 breaking-change note), ARCHITECTURE.md, AGENTS.md.

## Decisions (user-approved)

- Root resolution = **`IRootCapabilityResolver` + explicit-root overloads** (not resolver-only / param-only).
- Back-compat = **strict reject** of legacy shapes — a breaking change appropriate for the in-progress **3.0.0** major release.

## Review / results

- **Verification:** `dotnet build ZcapLd.sln` clean (0 code warnings); `dotnet test ZcapLd.sln` → **417 passing** (411 Core + 6 AspNetCore), 0 failing. Console examples run with all delegated verifies `True (expected: True)`; both example hosts build.
- The W3C JCS/RDFC interop fixtures already encoded `[rootId]` for first-level and required **no change** — they ratify the fix.
- Removed the originally-planned 3-arg `VerifyInvocationAsync(inv, cap, root)` overload: it was ambiguous with the `contextProperties` overload on a bare `null`. Kept the 4-arg `(inv, cap, root, props)`.
- Made the standalone `VerifyCapabilityProofAsync` path reuse the same strict validator as the chain walk (single source of truth) so both reject non-spec shapes identically.

## Acceptance criteria — all met

Generated chain spec-exact ✅ · verifier accepts spec-exact ✅ · verifier rejects embedded/duplicated/non-minimal ✅ · existing flows pass after fixture updates ✅ · full suite green ✅.
