# Contributing

Thanks for contributing to `zcap-dotnet`.

## Prerequisites

- .NET SDK 10.x
- Git

## Local Setup

```bash
git clone git@github.com:moisesja/zcap-dotnet.git
cd zcap-dotnet
dotnet restore
dotnet build ZcapLd.sln
```

## Test Before PR

```bash
dotnet test ZcapLd.sln
```

Optional package validation:

```bash
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
```

## Contribution Scope

Good contributions include:

- Spec compliance improvements
- Security hardening
- Bug fixes and regression tests
- Documentation and examples
- CI/CD improvements

## Coding Guidelines

- Keep changes minimal and focused.
- Add/adjust tests for behavioral changes.
- Preserve public API compatibility unless explicitly discussed.
- Prefer explicit error handling for verification/security logic.

## Pull Request Checklist

- [ ] Code builds locally
- [ ] Tests pass locally (`dotnet test ZcapLd.sln`)
- [ ] New/changed behavior is covered by tests
- [ ] Relevant docs updated (`README.md`, `architecture.md`, etc.)
- [ ] No unrelated file churn

## Commit Guidance

Use clear commit messages describing intent and impact.

Examples:

- `fix: enforce capability chain root-id validation`
- `docs: add NuGet release workflow instructions`
- `test: cover delegated caveat inheritance path`

## Release Process (Maintainers)

1. Merge PRs into `main`.
2. Ensure CI is green.
3. Tag release: `v<major>.<minor>.<patch>` (for example `v0.1.0`).
4. Push tag to GitHub.
5. GitHub Actions publish workflow pushes package to NuGet using `NUGET_API_KEY` secret.

## Security Reporting

For security-sensitive issues, open a private security advisory or contact maintainers directly before publishing a public issue.
