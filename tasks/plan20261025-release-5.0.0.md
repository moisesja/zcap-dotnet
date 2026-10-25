# Release ZcapLd.Core and ZcapLd.AspNetCore 5.0.0

The user asked to release the library; the plan was approved, including pushing the release
tags (publishing to NuGet is irreversible for a version number). Branch: `release-5.0.0`.

## Decisions

- Version 5.0.0 for both packages (already set in `Directory.Build.props`; major because
  #149 removes public caveat APIs). Released from `main` after PR #151 (#148) merged.
- Release-prep content limited to dating the CHANGELOG and adding a short multi-method DID
  resolution note (#148) to the Core package README, since the nuget.org page is fixed per
  version.
- Publish through the existing tag-triggered workflows (`core-v5.0.0`, `aspnet-v5.0.0`) on
  the release merge commit, as for 4.2.0. No GitHub Release, matching previous releases.

## Steps

- [x] Branch `release-5.0.0` from `origin/main` (b783970).
- [x] Date CHANGELOG 5.0.0; add #148 note to `src/ZcapLd.Core/PACKAGE_README.md`.
- [x] Preflight on the branch: clean Release build, full tests, pack, verify packages.
- [x] PR → CI green → merge commit.
- [x] Tag `core-v5.0.0` and `aspnet-v5.0.0` on the merge commit and push.
- [x] Watch both release workflows; verify nuget.org and a scratch consumer.

## Results

Pre-branch preflight on b783970: 488 Core + 11 ASP.NET pass (Release); both packages pack as
5.0.0 with AssemblyVersion/FileVersion 5.0.0.0 and the expected dependencies; no vulnerable
packages.
Branch preflight (with the release-prep edits): 488 Core + 11 ASP.NET pass (Release, clean,
`--no-incremental`); both packages 5.0.0, AssemblyVersion/FileVersion 5.0.0.0; the packed Core
README carries the multi-method note; dependencies unchanged; no vulnerable packages.

## Release outcome (2026-10-25)

- PR #152 merged as 23a38b4 after core, aspnet and interop CI passed. Annotated tags
  `core-v5.0.0` and `aspnet-v5.0.0` point at 23a38b4.
- `release-core-nuget` and `release-aspnet-nuget` succeeded; logs show "Your package was
  pushed" for both `.nupkg` and both `.snupkg`. nuget.org indexed both 5.0.0 packages about
  seven minutes later.
- Packages downloaded from nuget.org: version 5.0.0, source commit 23a38b4, expected
  dependencies, Core README carries the multi-method note, NuGet.org repository signature valid.
- Consumer smoke test (plain `net10.0` console project, isolated package cache, restored from
  nuget.org): delegation chain `Valid`, delegated invocation `Valid` through
  `CompositeDidResolver`, non-controller invocation `UnauthorizedController`.

### Finding: not usable where reflection-based JSON is disabled (pre-existing)

The same smoke test as a .NET 10 file-based app (`dotnet run smoke.cs`) fails on the first
delegation with "Capability/proof JSON could not be inspected safely." File-based apps default
to native-AOT settings, including `System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault
= false`, so `ZcapJsonOptions.Default` serialization throws `InvalidOperationException`
("Reflection-based serialization has been disabled…"). ZcapLd.Core 4.2.0 throws the same
exception, and the library does not declare `IsAotCompatible`/`IsTrimmable`, so this is a
pre-existing limitation, not a 5.0.0 regression. 5.0.0 does make the diagnosis worse:
`CapabilityProfile.GetRejectionReason` catches the `InvalidOperationException` and reports the
generic inspection message. Disposition pending the owner's decision (track or fix).
