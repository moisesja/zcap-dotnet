# NuGet Release Runbook

This monorepo publishes two packages to NuGet.org:

- `ZcapLd.Core`
- `ZcapLd.AspNetCore` (optional endpoint adapter)

Related developer docs:

- `docs/REVOCATION-INTEGRATION.md` (endpoint setup, transport options, persistence strategies)
- `docs/MONOREPO-PIPELINES.md` (CI/CD package boundaries)

## One-Time Setup

Publishing uses [nuget.org Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing).
Each release run exchanges a GitHub OIDC token for a NuGet API key valid for one hour, so the
repository stores no key.

1. On nuget.org, open your username menu, choose **Trusted Publishing**, and add one policy per
   release workflow, owned by `moisesja`:

   | Repository Owner | Repository | Workflow File | Environment |
   | --- | --- | --- | --- |
   | `moisesja` | `zcap-dotnet` | `release-core-nuget.yml` | empty |
   | `moisesja` | `zcap-dotnet` | `release-aspnet-nuget.yml` | empty |

2. Ensure default branch is `main`.

Renaming a release workflow file requires updating its policy.

## CI Workflows

- Core CI: `.github/workflows/ci-core.yml`
- ASP.NET adapter CI: `.github/workflows/ci-aspnet.yml`

Both run on push/PR with path filters and can be run manually.

## Release Workflows

Each workflow builds, tests and packs in one job and publishes in a second. Only the publish job
has `id-token: write`, and it runs no repository or dependency code, because that permission covers
every step in a job. Keep it that way.

A tag-triggered run uses the workflow file from the tag's commit, so a fix to a release workflow
does not apply to an existing tag, and rerunning a failed run repeats the old workflow.

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
dotnet clean ZcapLd.sln -c Release
dotnet build ZcapLd.sln -c Release --no-incremental
dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj -c Release --no-build
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release --no-build
dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release --no-build
```

## Versioning Strategy

- `ZcapLd.Core` and `ZcapLd.AspNetCore` are version-synchronized via `ZcapLdVersion`
  in `Directory.Build.props`.
- Package projects set `PackageVersion`, `AssemblyVersion`, and `FileVersion` explicitly
  from the effective package version.
- Release workflows propagate the same version metadata to all build steps
  (including test project builds) before packing.
- CI/release workflows run `dotnet clean` and `dotnet build --no-incremental`
  before `dotnet pack --no-build` to prevent stale assemblies from being packaged.
- Use the same semantic version for both package release workflows.

## Troubleshooting

- `NuGet login (Trusted Publishing)` fails: check the policy's owner, repository and workflow file
  name on nuget.org. Nothing has been uploaded at that point, so the job can be rerun once fixed.
- `skip duplicate` on push is non-fatal when retrying the same version.
- Inspect package integrity with:

```bash
dotnet nuget verify artifacts/**/*.nupkg
```
