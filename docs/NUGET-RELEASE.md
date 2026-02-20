# NuGet Release Runbook

This project publishes `ZcapLd.Core` to NuGet.org via GitHub Actions.

## One-Time Setup

1. Create a NuGet.org API key with push permissions for `ZcapLd.Core`.
2. In GitHub repository settings, add secret:
   - `NUGET_API_KEY`
3. Ensure default branch is `main`.

## CI Validation

Workflow: `.github/workflows/ci.yml`

Runs on:

- Push to `main`
- Pull requests targeting `main`
- Manual dispatch

Steps:

1. Restore
2. Build (Release)
3. Test
4. Pack
5. Upload package artifacts

## Publish Workflow

Workflow: `.github/workflows/release-nuget.yml`

### Tag-Based Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow resolves version `0.1.0`, runs build/test/pack, and publishes `.nupkg` and `.snupkg`.

### Manual Release

Run `release-nuget` from GitHub Actions UI with `version` input (e.g., `0.1.1`).

## Local Preflight

```bash
dotnet test ZcapLd.sln
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
```

## Versioning

- Repository uses SemVer tags: `vMAJOR.MINOR.PATCH`
- `csproj` holds default development version
- Release workflow overrides package version from tag/input

## Troubleshooting

- `NUGET_API_KEY secret is not configured`: add secret in repository settings.
- `skip duplicate` messages are non-fatal when re-running same version.
- If package metadata validation fails, inspect generated artifact with:

```bash
dotnet nuget verify artifacts/*.nupkg
```
