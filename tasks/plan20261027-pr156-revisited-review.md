# PR #156 revisited review

User intent: read the revised PR and discussion, assess bugs/security/tests/scope/commit clarity,
and post a candid, specific review comment. No production implementation changes requested.

Target: bd1a264a9df27c6fc6aca49d950b85978ec09dcf, base c09631d96777e105ce49f9f2ea5d9ce0ffe6d327.
Preserve the pre-existing untracked tasks/plan20261026-pr156-review.md.

- [x] Create review branch and read PR metadata and discussion.
- [x] Inspect full diff and surrounding critical paths; compare earlier feedback with fixes.
- [x] Have one adversarial reviewer independently probe the revision.
- [x] Run solution tests and inspect commit history/current CI.
- [x] Substantiate or refute findings and post the authorized GitHub comment.
- [x] Record validation and report the posted comment.

Plan check-in: review the root trust/scoping gates and route decoder, verify regression coverage,
then post only supported findings or a scoped approving comment.

Validation so far: dotnet test ZcapLd.sln --no-restore passed 503 Core and 32 ASP.NET tests.
GitHub ci-core, ci-aspnet and ci-interop all succeeded on bd1a264. Three descriptive commits;
18-file scope is mostly tests/docs for related endpoint/root-revocation fixes. Earlier explicit-root
scope and resolver-dependency concerns are addressed; issue #158 accurately tracks the remaining
pre-existing cross-root/shared-store collision vulnerability.

Finding: missing custom-root explicit-overload security regression. All existing borrowed-root
forgeries use reserved urn:zcap:root IDs, so the prefix guard masks loss of the resolved root.
The reviewer built an isolated copy at /private/tmp/zcap-pr156-revisit-adversarial. Unmodified
head passes 15 existing root tests plus the custom-root probe. Returning null after the awaited
resolver lookup when explicitRoot is non-null leaves all 15 existing tests passing but makes
the custom-root probe fail: the forged revocation returns true. Main agent inspected the probe
and independently reran the mutant: 15 pass, 1 fails at the rejection assertion. Current head
rejects this attack; this is a coverage gap, not a current implementation vulnerability.

Requested a registered custom victim root, attacker-signed valid borrowed-ID delegation, explicit
attacker root, rejection/no-record assertions, a positive control and mutation verification.
No new implementation bypass or scalability regression found. No production/test files changed.

Posted https://github.com/moisesja/zcap-dotnet/pull/156#issuecomment-6457917779.
Connector comment write returned integration 403; authenticated gh CLI successfully posted it.
