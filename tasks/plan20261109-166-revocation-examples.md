# Issue #166: make the revocation examples show the working flow

Branch: `166-revocation-examples-flow`, created from `origin/main` @ 4f0cc8e.

## Context

#166 found that the examples don't fully show how signed revocation works:

1. `examples/ZcapLd.RevocationEndpointsDemo` rejects every valid revocation with `403` as shipped. Its
   `InMemoryRootCapabilityResolver` is registered empty and nothing seeds it (reproduced over Kestrel:
   a delegated and a root revocation, both validly signed, both `403`).
2. A `403` from the demo gives no reason: denials log at `Debug`, and the demo has no settings to raise it.
3. The demo README's sample request is missing four proof fields the verifier requires (`created`,
   `capability`, `capabilityAction`, `invocationTarget`); the `/` page's `bodyShape` has the same gap.
4. The demo has no client, so a valid request can't be produced without writing C#.
5. The demo never shows a revocation taking effect: there is no protected resource.
6. The console example checks revocation with the bool API, so it never shows `Revoked`.
7. The console example shows only the success path.
8. CI builds neither example and never runs `tests/ZcapLd.AspNetCore.Tests` (48 tests, green locally),
   in `ci-aspnet.yml` or `release-aspnet-nuget.yml`.

## Human decisions (2026-11-09)

- Asked "do the examples fully reflect how this works?", then had #166 opened "with as much detail
  as possible", then said: **"Plan for it."**
- Closed #119 as won't fix: **"Digital Bazaar support will no longer happen."** Closed #161 as won't
  fix. Several docs still describe #119 and #161 as pending work (see D4).
- 2026-11-09, later: the user instructed the orchestrator to "re-use the plan" and was unavailable to
  answer questions, so the orchestrator adopted the recommended option for every open decision
  autonomously: **D1-A** (walkthrough mode in the demo), **D2** (outcome name in the `403` body only in
  `Development`), **D3** (self-checking `Check` helper with a non-zero exit code), **D4** (fix the stale
  #119/#161 docs in this PR as a separate commit). The user also instructed: push and open the PR
  without asking, run an external review loop on the PR, and merge once it is approved and CI is green.
  That overrides step 10's "ask before pushing or opening the PR".

## Open decisions (adopted as recommended, see Human decisions)

- **D1. How the demo gets a root and a client.**
  - **(A, recommended) A walkthrough mode in the demo:**
    `dotnet run --project examples/ZcapLd.RevocationEndpointsDemo -- --walkthrough`.
    - Startup code creates demo keys and a root, and registers the root with the server's resolver.
      This is trusted code, standing in for "the resource owner provisions its root", never request input.
    - The walkthrough then drives the real HTTP endpoints against the running host.
    - It's one command, with no key files, no configuration to keep in step, and no change to Core.
      The integration test reuses the same code.
  - (B) A separate client project plus a root seeded from configuration. The client's DID has to match
    the server's configuration (key files, or a published demo key), and building a root on the server
    needs a signer-free root factory in Core: `CapabilityService` needs an `ISigningService` even for
    unsigned roots, and the demo registers no `IDidSigner`.
- **D2. What a denial tells the caller.** The protected resource returns `403`.
  - (Recommended) Include the `VerificationOutcome` name in the body only when the environment is
    `Development`.
  - Never include it, so the walkthrough just prints `403`.
- **D3. A console example that checks itself.**
  - (Recommended) A small `Check(label, expected, actual)` helper that prints the result and sets a
    non-zero exit code on a mismatch, so CI can run the example.
  - Print only (today's behaviour), with CI just building it.
- **D4. Docs left stale by closing #119 and #161.**
  - (Recommended) Fix them in this PR as a separate commit. It's six small wording changes.
  - Fix them in a separate PR.

## Design

### Console example (`examples/ZcapLd.Examples/Program.cs`)

The existing owner → agent → assistant chain stays. Each step prints a detailed outcome:

1. **Unauthorized signer.** The assistant (controls only `leaf`) signs a revocation of `delegated`, its
   parent: `RevokeCapabilityAsync` returns `false`, and `delegated` stays `Valid`.
2. **Mid-chain delegator.** The agent delegates a second leaf, `helper`, then revokes it: `helper` is
   `Revoked` and `delegated` stays `Valid`. The agent can revoke only what it delegated.
3. **Ancestor revocation (existing).** The owner revokes `delegated`; then
   `VerifyCapabilityChainDetailedAsync(leaf)` is `Revoked`, replacing the bool at line 54, and an
   invocation with `leaf` is refused as `Revoked`.

**Dropped from #166's list: "replay refused".** Re-sending a revocation that already succeeded is refused
because the chain is now revoked (`AuthorizeRevocationAsync` fails first), not by the nonce check. An
example would show the wrong reason. Nonce replay stays covered by the tests. (Lesson 2026-10-27: a
deny-test must reach the guard it names.)

### Demo (`examples/ZcapLd.RevocationEndpointsDemo`)

- **`DemoKeyring`** (demo-only `IDidSigner`): in-memory Ed25519 keys behind real `did:key` DIDs, which
  the demo's `DidKeyResolver` resolves. It's marked loudly as not for production. The examples project's
  `InMemoryDidProvider` can't be reused: it has no real-`did:key` generator.
- **Protected resource:** `POST /documents/report`. The body is a DI-secured application document
  (`ISigningService.SignCapabilityInvocationAsync`).
  - It's verified with `VerifyCapabilityInvocationDetailedAsync(doc, "read", [ReportTarget])`, where
    `ReportTarget` is a constant resource identifier such as `https://demo.example/documents/report`,
    independent of the listening URL.
  - It returns `200` with a small payload, or `403` (D2).
- **Walkthrough (D1-A):** provisioning (keys and a root registered with the resolver) is kept separate
  from the steps. The steps:
  1. The agent reads → `200`.
  2. A stranger tries to revoke the agent's capability → `403`.
  3. The owner revokes it → `200`.
  4. The agent reads again → `403` (`Revoked`).

  Each step prints its request and status. `Program.cs` runs it after `app.StartAsync()` when
  `--walkthrough` is passed; otherwise it serves as today.
- **Logging:** `appsettings.Development.json` raises `ZcapLd` to `Debug`, with a comment explaining
  why the library keeps denials at `Debug`. Add `Properties/launchSettings.json` (Development,
  `http://localhost:5099`) so `dotnet run` picks it up; check `.gitignore` doesn't exclude it.
- **`/` page:** fix `bodyShape` to the real request shape.
- **README:** the walkthrough first; the real request shape (finding 3), with the freshness window
  (five minutes); how the demo gets its root and why a resource server never takes one from a request;
  `curl` kept as "what the walkthrough sends".

### Tests

- A new `RevocationWalkthroughTests` boots the demo with `WebApplicationFactory<Program>`. It replaces
  only the SQLite store (no file); it does **not** replace the root resolver. It runs the same
  provisioning and steps and asserts `200 / 403 / 200 / 403 Revoked`.
- Prove it by ablation: with provisioning removed, the test must fail at step 1. Rebuild the test
  project for the ablation, not `--no-build` (lesson 2026-06-05).

### CI

- `ci-aspnet.yml`: restore, build and test `tests/ZcapLd.AspNetCore.Tests` (which builds the demo).
  Add the path triggers `tests/ZcapLd.AspNetCore.Tests/**` and `examples/ZcapLd.RevocationEndpointsDemo/**`.
- `release-aspnet-nuget.yml`: run `tests/ZcapLd.AspNetCore.Tests` before packing.
- `ci-core.yml`: build and run `examples/ZcapLd.Examples`. With D3, a mismatch fails the job.

### Docs left stale by closing #119 and #161 (D4)

Change "tracked in" / "remains separate work" to "not planned" in:

- `README.md:371`
- `AGENTS.md:79-81` (edit `AGENTS.md`; `CLAUDE.md` is a symlink)
- `architecture.md:226` and the "Concurrency and limits" paragraph
- `docs/REVOCATION-INTEGRATION.md:291-292`
- `docs/ZCAP-LD-ROADMAP.md:17`, `docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md:80`,
  `docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md:87`

The CHANGELOG history stays as written. Code comments that cite #161 as the reason for the behaviour
(`VerificationService.cs:2541`, `IVerificationService.cs:223`) stay too: they explain, they don't promise.

## Steps

0. [x] Branch from `origin/main` (4f0cc8e); `origin/main` == local `main`.
1. [x] Sign-off on D1–D4 (recommended options adopted autonomously, see Human decisions).
2. [x] Console example: the D3 helper, the three steps above, detailed outcomes. Run it and read the
   output, not just the build (lesson 2026-06-03).
3. [x] Demo: `DemoKeyring`, protected resource, provisioning and walkthrough, logging and launch
   settings, `/` page fix.
4. [x] Demo README rewrite.
5. [x] `RevocationWalkthroughTests`, plus the ablation proof.
6. [x] CI: `ci-aspnet.yml`, `release-aspnet-nuget.yml`, `ci-core.yml`. Lint with `actionlint` if available.
7. [x] D4 docs commit.
8. [x] Verify: `dotnet build ZcapLd.sln`, `dotnet test ZcapLd.sln` (including the ASP.NET tests), run the
   console example, and run the demo walkthrough over Kestrel. Confirm no `revocations-demo.db` or other
   untracked artifacts are left in the repo.
9. [x] Adversarial review (AGENTS.md §2): a red-team subagent on the demo changes, treating them as code
   people will copy. Check root provisioning, what denials disclose, key handling, the protected
   endpoint's expected action and target, and the body cap. Report findings in detail, fix, re-verify.
10. [x] Results below; pushed and PR opened without asking (per the later instruction). `tasks/lessons.md` is
    updated only if the review corrects something.

## Out of scope

- Library behaviour: no change in `src/`.
- Revocation across replicas or independent verifiers (deployment concerns, documented).
- Anything relating to the Digital Bazaar transport (#119, closed).

## Results

Implemented on 2026-11-09 by sub-agents under the orchestrator, then verified by the orchestrator.

- **Console example** (`examples/ZcapLd.Examples/Program.cs`): a `Check<T>(label, expected, actual)` helper
  prints every outcome and returns exit code 1 on a mismatch. Every line now checks a `VerificationOutcome`
  (the exact-only verifier reports `AttenuationViolation`, not a bool). New steps: a descendant's revocation of
  its parent is refused (`False`, parent stays `Valid`); the agent revokes the `helper` it delegated
  (`Revoked`) while its own grant stays `Valid`; the owner revokes `delegated`, and `leaf`'s chain and a fresh
  invocation are both `Revoked`. Output: 18 checks, all pass, exit 0. Ablation: one wrong expectation printed
  `FAIL ... (expected Valid)` and exited 1.
- **Demo**: `DemoKeyring` (`IDidSigner` only; resolution stays `DidKeyResolver`), `DemoResource` constants,
  `RevocationWalkthrough` (`ProvisionAsync(IServiceProvider)` registers the root with the host's
  `InMemoryRootCapabilityResolver`; `RunAsync(HttpClient, Provisioned, TextWriter)` runs the four steps and
  prints every request), `POST /documents/report` (1 MB cap, `JsonObject` via `ZcapJsonOptions.Default`,
  `VerifyCapabilityInvocationDetailedAsync(doc, "read", ReportTarget)`, outcome name in the 403 body only
  in Development), `--walkthrough` stripped from the host args, `appsettings.Development.json`,
  `Properties/launchSettings.json`, corrected `/` page and README. Root pinning was left out: `UriEncoding`
  is internal and the resolver holds one root; the handler comment points multi-root servers at
  `expectedRootCapabilityIds`. Kestrel run: 200 / 403 (Debug log: "Verification method not authorized by
  controller ... for CapabilityDelegation") / 200 / 403 `{"outcome":"Revoked"}`, exit 0.
- **Tests**: `RevocationWalkthroughTests` (replaces only the store; does not replace the resolver):
  the walkthrough asserts 200/403/200/403, step 4 `Revoked`; a second test without root registration gets
  403 `CouldNotVerify` (the unobtainable-root outcome). Ablation: with `roots.Register(root)` removed and
  the test project rebuilt, the walkthrough test failed at index 0 (403 instead of 200). Suite: Core 783,
  AspNetCore 50, all green.
- **CI**: `ci-core.yml` builds and runs the console example; `ci-aspnet.yml` and
  `release-aspnet-nuget.yml` build and run `tests/ZcapLd.AspNetCore.Tests` (which builds the demo), with
  the new path triggers. YAML parsed with ruby; `actionlint` unavailable.
- **D4**: seven docs now say #119/#161 are not planned (closed as won't fix); separate commit.
- **Adversarial review**: no Critical/High/Medium findings. Low: `dotnet run` always forces `Development`
  through launchSettings (documented in the README with `--no-launch-profile`); README 200-body shape
  understated the null fields (fixed). Info: all `BadHttpRequestException` map to 413 (matches the library
  endpoint); the SQLite file grows across walkthrough runs (harmless, gitignored).
- No change under `src/`. The stale ignored `revocations-demo.db` from an earlier run was deleted.
- **PR #167 review round 1 (P2, confirmed):** duplicate JSON properties in the body of `POST /documents/report`
  produced an HTTP 500: `DeserializeAsync<JsonObject>` reports the duplicate as `ArgumentException`, which the
  handler did not catch. Fixed by catching `ArgumentException` in the deserialization block (400). Regression
  tests `ReadReport_WithDuplicateJsonProperties_Returns400` (top-level and nested, Development and Production,
  built from raw strings) were red before the fix and green after; `ReadReport_WithMalformedBody_...` pins
  400 for a non-object and the empty Production 403. The library's revocation endpoint was probed with the
  same bodies and already returns 400 (typed target). Lesson recorded in `tasks/lessons.md`.
