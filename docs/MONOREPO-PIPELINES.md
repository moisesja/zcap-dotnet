# Monorepo Package Management

This repository hosts two NuGet packages in one codebase:

- `src/ZcapLd.Core` -> `ZcapLd.Core`
- `src/ZcapLd.AspNetCore` -> `ZcapLd.AspNetCore`

`ZcapLd.AspNetCore` is an adapter layer over the core package and depends on `ZcapLd.Core`.

Related revocation integration guidance: `docs/REVOCATION-INTEGRATION.md`.

## CI/CD Layout

## CI (validation)

- `.github/workflows/ci-core.yml`
  - Scope: `ZcapLd.Core` + core tests + examples
  - Triggered by path filters for core-related files
- `.github/workflows/ci-aspnet.yml`
  - Scope: ASP.NET adapter + dependency validation against core
  - Triggered by adapter paths and shared core paths

## CD (publishing)

- `.github/workflows/release-core-nuget.yml`
  - Trigger tag: `core-v*.*.*`
  - Publishes `ZcapLd.Core`
- `.github/workflows/release-aspnet-nuget.yml`
  - Trigger tag: `aspnet-v*.*.*`
  - Publishes `ZcapLd.AspNetCore`

## Recommended Operating Model

1. Keep a single trunk (`main`) for both packages.
2. Use path-based PR ownership/review routing:
   - Core maintainers own `src/ZcapLd.Core` and core tests.
   - Adapter maintainers own `src/ZcapLd.AspNetCore`.
3. Use package-scoped tags for release intent:
   - `core-vX.Y.Z`
   - `aspnet-vX.Y.Z`
4. Run both CI workflows on shared interface changes (`src/ZcapLd.Core`), since the adapter depends on core contracts.
5. Prefer package-specific API keys:
   - `NUGET_API_KEY_CORE`
   - `NUGET_API_KEY_ASPNET`

## Dependency Considerations

- The adapter package references core abstractions. Release the core package first when a new core API is required by adapter changes.
- When releasing adapter with new core dependency expectations, ensure the referenced core version is already available on NuGet.org.
