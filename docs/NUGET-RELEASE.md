# NuGet Release Runbook

This monorepo publishes two packages to NuGet.org:

- `ZcapLd.Core`
- `ZcapLd.AspNetCore` (optional endpoint adapter)

Related developer docs:

- `docs/REVOCATION-INTEGRATION.md` (endpoint setup, transport options, persistence strategies)
- `docs/MONOREPO-PIPELINES.md` (CI/CD package boundaries)

## One-Time Setup

1. Create NuGet.org API keys with push permissions.
2. In GitHub repository settings, configure secrets:
   - `NUGET_API_KEY_CORE` (preferred for core releases)
   - `NUGET_API_KEY_ASPNET` (preferred for ASP.NET adapter releases)
   - `NUGET_API_KEY` (optional shared fallback)
3. Ensure default branch is `main`.

## CI Workflows

- Core CI: `.github/workflows/ci-core.yml`
- ASP.NET adapter CI: `.github/workflows/ci-aspnet.yml`

Both run on push/PR with path filters and can be run manually.

## Release Workflows

### Core Package Release

- Workflow: `.github/workflows/release-core-nuget.yml`
- Trigger tag format: `core-vMAJOR.MINOR.PATCH`

Example:

```bash
git tag core-v0.2.0
git push origin core-v0.2.0
```

### ASP.NET Adapter Release

- Workflow: `.github/workflows/release-aspnet-nuget.yml`
- Trigger tag format: `aspnet-vMAJOR.MINOR.PATCH`

Example:

```bash
git tag aspnet-v0.2.0
git push origin aspnet-v0.2.0
```

### Manual Releases

Both release workflows support `workflow_dispatch` with a required `version` input.

## Local Preflight

```bash
dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release
```

## Versioning Strategy

- `ZcapLd.Core` and `ZcapLd.AspNetCore` are version-synchronized via `ZcapLdVersion`
  in `Directory.Build.props`.
- Release workflows override package versions from tag/input at pack time.
- Use the same semantic version for both package release workflows.

## Troubleshooting

- `Neither NUGET_API_KEY_* nor NUGET_API_KEY is configured`: configure package-specific secret (or shared fallback).
- `skip duplicate` on push is non-fatal when retrying the same version.
- Inspect package integrity with:

```bash
dotnet nuget verify artifacts/**/*.nupkg
```
