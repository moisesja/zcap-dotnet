# Release ZcapLd.Core and ZcapLd.AspNetCore 6.0.0

The owner asked to deploy v6.0.0 with Option 3 for #161 (document the replay behaviour, leave the
code). The plan was approved, including merging to `main` and pushing the release tags (publishing
to NuGet is irreversible for a version number). Branch: `release-6.0.0`.

## Decisions

- Version 6.0.0 for both packages (already set in `Directory.Build.props`), released from `main`
  after PR #163. #154 and #119 are features and do not block; neither does #161.
- #161: no behaviour change in `src/`, only comments and XML docs. The issue stays open for Option 1
  (bind the request to the copy). The behaviour is pinned by tests, and the docs follow the tests.
- Native AOT and file-based apps are stated as a known limitation (#154), confirmed on 6.0.0 first.
- Publish through the tag-triggered workflows (`core-v6.0.0`, `aspnet-v6.0.0`) on the release merge
  commit. No GitHub Release, matching previous releases.
- No adversarial agents: production logic does not change.

## Steps

- [x] Branch `release-6.0.0` from `origin/main` (d51a765).
- [x] Pin tests for the replay behaviour (`VerificationServiceRevocationScopeTests`, section l).
- [x] Option 3 docs: `VerificationService` comments, `IVerificationService` remarks, `architecture.md`,
      `docs/REVOCATION-INTEGRATION.md`, `AGENTS.md`.
- [x] Stale statements: `Directory.Build.props` comment, supported-profile target version.
- [x] Confirm the AOT limitation on 6.0.0; state it in the CHANGELOG, README and Core package README.
- [x] Date CHANGELOG 6.0.0.
- [ ] Preflight on the branch: clean Release build, full tests, pack, verify packages.
- [ ] PR → CI green → merge commit.
- [ ] Tag `core-v6.0.0` and `aspnet-v6.0.0` on the merge commit and push.
- [ ] Watch both release workflows; verify nuget.org and a scratch consumer.
- [ ] Comment on #161 with the decision and corrections.

## Results

- Pin tests pass, which confirms four behaviours: a replay with a fuller copy records the co-signer
  and returns false; a replay with a copy whose chain does not authorize the revoker records nothing;
  a verifier that trusts the chain records the replay, one that does not refuses it; a request whose
  signed `invocationTarget` differs from the capability's is accepted.
- `docs/REVOCATION-INTEGRATION.md` claimed authorization rests on `invocationTarget`. It does not;
  corrected.
- File-based app against a local 6.0.0 pack fails on the first delegation with the
  reflection-disabled `InvalidOperationException` from `CanonicalIri.SignedForm` (#157), not with the
  generic "could not be inspected safely" message recorded for 5.0.0.
- Console consumer against the same local pack: delegation chain `Valid`, delegated invocation
  `Valid` through `CompositeDidResolver`, non-controller invocation `UnauthorizedController`, signed
  revocation true, invocation afterwards `Revoked`.
