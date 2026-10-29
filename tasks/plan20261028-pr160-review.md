# PR #160 review

User intent: inspect the newly opened PR, assess tests, commit clarity, scope and critical-path risks, then post a specific, candid review on GitHub. No production changes requested.

- [x] Identify PR, base/head, description, scope and commits.
- [x] Inspect implementation and tests; independently challenge security findings.
- [x] Run relevant checks and reproduce actionable defects where possible.
- [x] Post review anchored to the inspected head and record results.

Review target: `75fdf9f1b6556ff363ed1f8ed422d6fa42e8f723`, base `2363a29eeb375124bd200424ebd8e5973494514a`.
Plan: examine caveat signing/attenuation, enforcement/rollback, proof and identifier changes, dependency/DI wiring; use one independent adversarial reviewer. Check findings against base to distinguish new regressions. Validate exact head before posting.

Results so far:
- Local `dotnet test ZcapLd.sln --no-restore`: 673 Core and 37 ASP.NET tests pass; four existing documentation warnings.
- Local `bash interop/run-interop.sh`: 12 baseline and 118 profile checks pass.
- GitHub CI at the reviewed head: ci-core, ci-aspnet, ci-interop successful.
- Reproduced proof-set order dependence in `/private/tmp/pr160-proofset-probe/Program.cs`: two parent representations have identical grant fields and distinct valid proofs; a child signed against the second verifies alone. Prepending a junk proof embedding the first parent causes InvalidDelegation; reversing the proof order returns Valid. Independent reviewer and primary both ran the reproduction. Existing multi-proof positive tests reuse one identical chain, missing this case.
- No new authorization bypass confirmed. The reproduced issue is valid-input rejection, not an escalation claim.
- PR description is stale: it lists the malformed proof-member outcome fix as unaddressed, although head 75fdf9f implements it; local Core test count is now 673.
- Exact-base control (`2363a29`, isolated source and dependencies in `/private/tmp/pr160-base-control`): both proof orders return Valid. Primary independently reran both compiled probes. Confirms introduced P2 regression at VerificationService.cs:383–387/1264.
- Posted review: https://github.com/moisesja/zcap-dotnet/pull/160#pullrequestreview-5691323513, anchored to 75fdf9f. Requested candidate-specific chain verification, both-order positive tests, and retention of the conflicting-parent security regression test. Also noted scope, vague version commit subject, and stale PR description.
- GitHub connector returned 403 for review and conversation writes. Authenticated local GitHub CLI successfully created the COMMENT review; no approval or merge was submitted.
- No production/test files changed. Preserved the unrelated concurrent edit to `tasks/plan20261028-dataproofs-1.5.0.md`.

## Requested re-review

User asks to re-review and, under the existing instruction, post the result.
Local follow-up is `d0195397bb9768bf5dd8984e63ed515df502cd40`; initially GitHub still names `75fdf9f`.

- [x] Inspect the candidate-chain fix and new tests; adversarially challenge chain binding and work bounds.
- [x] Rebuild and rerun original reproduction, relevant tests, and integration checks.
- [x] Recheck published head, post an accurately scoped follow-up review, and record results.

Re-review results:
- Local d019539 fixes the original reproduction: both proof orders now return Valid. Rebuilt the probe to avoid stale binaries.
- `dotnet test ZcapLd.sln --no-restore`: 679 Core + 37 ASP.NET passed. `bash interop/run-interop.sh`: 12 + 118 passed.
- Independent adversarial review confirmed proof-to-parent binding, signed ancestor-id consistency, and bounded candidate search. Additional revocation probe accepted authority from a second valid chain and refused authority from an invalid candidate. No new blocking defect confirmed.
- The PR description corrected the previously stale malformed-member follow-up and prior test count.
- Live GitHub head remained 75fdf9f immediately before posting; local d019539 was not published. Posted a COMMENT review explicitly distinguishing the validated local fix from the unchanged PR head and requesting that the fix be pushed: https://github.com/moisesja/zcap-dotnet/pull/160#pullrequestreview-5691516027.
- No production/test edits or remote branch changes. Stopped the stalled sandbox reproduction after the successful rebuilt rerun completed.
