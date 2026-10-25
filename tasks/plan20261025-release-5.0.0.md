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
- [ ] PR → CI green → merge commit.
- [ ] Tag `core-v5.0.0` and `aspnet-v5.0.0` on the merge commit and push.
- [ ] Watch both release workflows; verify nuget.org and a scratch consumer.

## Results

Pre-branch preflight on b783970: 488 Core + 11 ASP.NET pass (Release); both packages pack as
5.0.0 with AssemblyVersion/FileVersion 5.0.0.0 and the expected dependencies; no vulnerable
packages.
Branch preflight (with the release-prep edits): 488 Core + 11 ASP.NET pass (Release, clean,
`--no-incremental`); both packages 5.0.0, AssemblyVersion/FileVersion 5.0.0.0; the packed Core
README carries the multi-method note; dependencies unchanged; no vulnerable packages.
