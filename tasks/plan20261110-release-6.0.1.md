# Prepare ZcapLd.Core and ZcapLd.AspNetCore 6.0.1

The owner asked: **"Make a version bump to 6.0.1 and prepare for release."** Branch: `release-6.0.1`,
created from `origin/main` @ b7daa14 with `--no-track`, so a plain push can never land on `main` (the
6.0.0 release branch tracked `origin/main`, and a push from it moved `main` with no PR).

## Scope

Prepare, do not publish. Tagging `core-v6.0.1` / `aspnet-v6.0.1` publishes to nuget.org, which is
irreversible for a version number, so tags wait for an explicit go-ahead after the PR merges.

## What 6.0.1 contains (since 6.0.0, published 2026-11-02)

- #154 (PR #168): native AOT, trimming and .NET 10 file-based app support through source-generated
  JSON; additive typed caveat registration overloads; `IsAotCompatible` on both packages.
- #166 (PR #167): examples, tests and CI only; no package change.

## Decisions

- **Version 6.0.1, as the owner asked.** Concern raised: #154 adds public API
  (`CaveatTypeRegistry.Register<TCaveat>(string, JsonTypeInfo<TCaveat>)`,
  `AddZcapCaveatType<TCaveat>(services, type, JsonTypeInfo<TCaveat>)`), and the CHANGELOG states the
  project follows Semantic Versioning, which puts additive API in a minor release (6.1.0, the target
  #154 itself named). Proceeding with 6.0.1 per the owner's request; the PR repeats the concern so it
  can be changed before tagging, which is the last reversible point.
- Historical "since 6.0.0" / "byte-identical to 6.0.0" statements stay. Only current-version
  statements move to 6.0.1.
- The AOT docs gain "since 6.0.1", because the repository README is read by 6.0.0 users too.
- No adversarial agents: no production logic changes in this PR.

## Steps

- [x] Branch `release-6.0.1` from `origin/main` (b7daa14), untracked.
- [x] `Directory.Build.props`: `ZcapLdVersion` 6.0.1 and its comment.
- [x] CHANGELOG: `[Unreleased]` becomes `[6.0.1] - 2026-11-10` with a short summary; fresh empty
      `[Unreleased]` above it.
- [x] Current-version statements: `AGENTS.md` packages line, `docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md`
      implementation target, `docs/CAVEAT-PROFILE.md` status line (typed registration since 6.0.1).
- [x] "Since 6.0.1" on the AOT sections of `README.md` and both package READMEs.
- [x] Preflight (docs/NUGET-RELEASE.md): clean Release build, full tests, pack both packages, check
      the nupkg versions and `dotnet nuget verify`; native AOT publish of the sample and the
      file-based app; interop harness.
- [ ] Commit, push, open the PR. No tags.
- [ ] After merge (owner's go-ahead): tag the merge commit `core-v6.0.1`, wait for nuget.org, then
      `aspnet-v6.0.1`; verify on nuget.org with a scratch consumer.

## Results

Preflight on the branch (macOS arm64, SDK 10.0.100), before the commit:

| Check | Result |
| --- | --- |
| `dotnet build ZcapLd.sln -c Release --no-incremental` after `dotnet clean` | 0 warnings, 0 errors |
| `dotnet test ZcapLd.sln -c Release` | Core 889/889, AspNetCore 89/89 |
| `dotnet pack` both packages | `ZcapLd.Core.6.0.1` and `ZcapLd.AspNetCore.6.0.1` (+ snupkg); the adapter depends on `ZcapLd.Core` 6.0.1 |
| Packed assemblies | FileVersion 6.0.1.0, ProductVersion 6.0.1+commit |
| `dotnet nuget verify` | NU3004 "not signed", expected for a local pack (nuget.org signs on upload) |
| Native AOT publish of `examples/ZcapLd.AotSample` (osx-arm64) | 10 IL warnings, all Newtonsoft.Json (documented); binary: all 18 checks passed |
| `dotnet run examples/ZcapLd.AotFileBasedApp/app.cs` | reflection disabled; all 12 checks passed |
| `examples/ZcapLd.Examples` | all 18 checks passed, exit 0 |
| `bash interop/run-interop.sh` | all 12 checks and all 118 profile checks passed |
