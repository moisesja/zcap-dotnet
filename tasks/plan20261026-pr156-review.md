# PR #156 review

User intent: inspect the newly opened PR, assess correctness, tests, commit clarity,
scope and critical-path risks, then post a specific, candid GitHub review.

Review target: `091a0a096b5e2637ad35dee662c373914d813d92` against
`c09631d96777e105ce49f9f2ea5d9ce0ffe6d327`. No implementation changes requested.

- [x] Identify PR and read title and description; verify local revision.
- [x] Inspect complete diff and surrounding authorization/endpoint code.
- [x] Independently probe security assumptions with one adversarial reviewer.
- [x] Run relevant tests and inspect CI/commit history.
- [x] Refute or substantiate concerns; post a concrete GitHub review.
- [x] Record results and report the review URL.

## Validation and findings

- `dotnet test ZcapLd.sln --no-restore`: 496 Core and 32 ASP.NET tests passed.
- GitHub CI for the reviewed SHA: ci-core, ci-aspnet and ci-interop succeeded.
- One descriptive commit; 13 changed files, mostly regression coverage and documentation.
- Reviewed the adversarial reviewer's scratch console probe and independently ran it:
  `dotnet run --project /tmp/zcap-pr156-core-review/review.csproj --no-restore`.
- A registered root B revoked with B's genuine signature and unrelated explicit root A
  returns true, contradicting the new explicit-root API documentation. Root-only
  chains ignore the supplied root pin. This behavior predates the PR.
- A genuine delegated revocation with an explicit root and a failing configured root
  resolver now fails closed: document this extra resolver dependency and test it.
- A forged delegation bearing another verifier's unknown custom root ID can poison a
  shared revocation store: the victim root verifies before the write and fails after.
  This is a pre-existing collision limitation, broader than the new documentation's
  sibling/delegated-ID wording. Request accurate deployment scope and tracked follow-up.
- No new bypass found for a root known to the revocation verifier; the reported
  URL-decoding fix and known-root anchoring are supported by the tests and inspection.
- The adversarial reviewer ran the same probes against an isolated base checkout:
  mismatched explicit-root acceptance and custom-root collisions reproduce on both;
  explicit-root delegated revocation with a failing resolver succeeds on base and
  fails on PR head.
- Posted both concerns, reproduction details, requested fixes/documentation/tests,
  and validation results in https://github.com/moisesja/zcap-dotnet/pull/156#issuecomment-6430620841.
  The connector denied both review and comment writes (integration 403); the authenticated
  GitHub CLI successfully posted the requested conversation comment. No formal approval
  or request-changes review state was submitted.
