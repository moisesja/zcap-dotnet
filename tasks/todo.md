# Developer Docs Revocation Guide Update - 2026-02-21 (Codex)

## Scope

Update developer-facing documentation to include clear revocation integration guidance:

- How to set up revocation endpoints with `ZcapLd.AspNetCore`
- How to expose revocation without the ASP.NET adapter
- How to configure different persistence strategies for revocation registries

## Plan

- [x] Add a dedicated revocation integration guide under `docs/`
- [x] Update root `README.md` with links and quick-start snippets for the three revocation documentation sections
- [x] Update `architecture.md` with explicit endpoint exposure patterns and persistence strategy guidance
- [x] Update package docs (`src/ZcapLd.Core/PACKAGE_README.md`, `src/ZcapLd.AspNetCore/PACKAGE_README.md`) with the new revocation sections
- [x] Update `CONTRIBUTING.md` and release docs references to remain consistent with monorepo dual-package workflows
- [x] Verify documentation consistency and capture completion notes

## Verification Log

- [x] `rg -n "ci\\.yml|release-nuget\\.yml|git tag v|v<major>|NUGET_API_KEY\\b|revocacion|revocation integration|REVOCATION-INTEGRATION" ...`: validated updated references and new guide links across developer docs

## Review

- Added `docs/REVOCATION-INTEGRATION.md` with explicit sections on ASP.NET endpoint setup, non-ASP.NET exposure patterns, and persistence strategy configuration.
- Updated developer-facing docs (`README.md`, `architecture.md`, package readmes, `CONTRIBUTING.md`) to include and reference the new revocation integration guidance.
- Aligned contributor release guidance with monorepo package-scoped release tags and package-specific NuGet API key conventions.

---

# Revocation Extensibility + ASP.NET Adapter Plan - 2026-02-20 (Codex)

## Scope

Implement persistent, pluggable revocation support in `ZcapLd.Core`, add optional ASP.NET endpoint rails in a new adapter package, and split monorepo CI/CD so each package has independent pipelines.

## Plan

- [x] Add revocation core abstractions and default in-memory implementation in `src/ZcapLd.Core`
- [x] Integrate revocation checks into verification flows and route existing revocation API methods through the new service
- [x] Add/adjust tests to cover revocation persistence and verification behavior
- [x] Create `src/ZcapLd.AspNetCore` package with endpoint mapping and DI registration extensions
- [x] Add monorepo package docs and update root docs/readme for dual-package usage
- [x] Split GitHub Actions into per-package CI and CD workflows (core vs ASP.NET adapter)
- [x] Run full build/test/pack validation and capture results

## Verification Log

- [x] `dotnet test ZcapLd.sln`: `Failed: 0, Passed: 162, Total: 162`
- [x] `dotnet build src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj`: `Build succeeded`
- [x] `dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release -o artifacts/core`: generated `.nupkg` and `.snupkg`
- [x] `dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release -o artifacts/aspnet`: generated `.nupkg` and `.snupkg`

## Review

- Implemented pluggable revocation storage contracts (`IRevocationStore`, `IRevocationService`) with a default in-memory backend and expiry-aware revocation lookups.
- Wired revocation checks into capability proof/chain/invocation verification paths to actively deny revoked capabilities.
- Added optional ASP.NET adapter package with DI rails and minimal API endpoints for revocation submit/status workflows.
- Migrated repository CI/CD to monorepo package pipelines with path filters and package-specific tag-based NuGet release workflows.

---

# OSS NuGet Readiness Plan - 2026-02-20 (Codex)

## Scope

Prepare `zcap-dotnet` for open-source NuGet distribution, including package metadata, contributor/developer docs, and CI/CD automation.

## Plan

- [x] Add NuGet package metadata and packaging settings to `src/ZcapLd.Core/ZcapLd.Core.csproj`
- [x] Add package-specific readme for NuGet and ensure it is packed
- [x] Create `architecture.md` for developer architecture overview and data flow
- [x] Create `contributors.md` and `CONTRIBUTING.md` with contributor workflow
- [x] Update root `README.md` for OSS + NuGet publish/readme accuracy
- [x] Add GitHub Actions CI pipeline for restore/build/test/pack
- [x] Add GitHub Actions publish pipeline for tagged releases to NuGet.org
- [x] Validate with `dotnet test` and `dotnet pack` locally

## Verification Log

- [x] `dotnet test ZcapLd.sln`: `Failed: 0, Passed: 157, Total: 157`
- [x] `dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release`: generated `.nupkg` and `.snupkg` in `artifacts/`

## Review

- Added NuGet-ready package metadata, SourceLink, symbols, and packaged readme/license support.
- Added OSS documentation set for architecture, contribution flow, contributors list, and NuGet release runbook.
- Added GitHub Actions CI and release-to-NuGet workflows, plus Dependabot configuration.
- Updated examples and README to match strict root capability semantics and delegated restriction behavior.

---

# Remediation Plan - 2026-02-20 (Codex)

## Scope

Stabilize the post-remediation codebase and make behavior consistent with the repository's normative compliance model.

## Plan

- [x] Baseline current failures (`dotnet test ZcapLd.sln`) and identify mismatches between implementation and compliance expectations
- [x] Fix verification chain/proof behavior for local embedded-chain validation (`MUST-18`) and chain-limit behavior (`MUST-13`)
- [x] Keep strict root-capability semantics and align legacy tests to delegated-capability restrictions where required
- [x] Update compliance tests with root-incompatible setups (`MUST-12`, `MUST-20`, `SHOULD-05`) to equivalent delegated scenarios
- [x] Run full tests, resolve residual failures, and capture final review notes in this file

## Verification Log

- [x] `dotnet test ZcapLd.sln` (baseline captured): `Failed: 14, Passed: 143, Total: 157`
- [x] `dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj --filter FullyQualifiedName~Compliance`: `Failed: 3, Passed: 26, Total: 29` (post-first remediation checkpoint)
- [x] `dotnet test ZcapLd.sln` (final): `Failed: 0, Passed: 157, Total: 157`

## Review

- Verification service now distinguishes strict standalone delegation-proof checks from chain-context checks, enabling local embedded-chain validation while keeping malformed standalone first-level proofs rejected.
- Chain-length violations now return `false` from verification flows instead of throwing.
- Legacy tests that modeled root `allowedAction`/`caveat` behavior were migrated to delegated-capability scenarios, matching strict root semantics.
- Normative tests `MUST-12`, `MUST-20`, and `SHOULD-05` now assert equivalent delegated scenarios that are compatible with strict root capability shape.

---

# ZCAP-LD Compliance + Security Audit Plan

**Date**: 2026-02-20  
**Scope**: Entire repository (`src`, `tests`, `examples`, `docs`, `README`) against live ZCAP-LD spec and cryptosuite requirements.

## Plan

- [x] Pull and review the live ZCAP-LD specification
- [x] Pull and review Ed25519/Data Integrity cryptosuite requirements
- [x] Review all source code in `src/ZcapLd.Core`
- [x] Review all tests in `tests/ZcapLd.Core.Tests`
- [x] Validate documentation claims vs actual runtime behavior
- [x] Run full test suite and reproduce critical failures
- [x] Build compliance findings matrix
- [x] Build security findings matrix
- [x] Write remediation priorities

## Verification Log

- [x] `dotnet test ZcapLd.sln`
: Result: `Failed: 3, Passed: 93, Total: 96`, then `Test Run Aborted` due host crash.
- [x] `dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj --filter FullyQualifiedName~ResolvePublicKey_WithInvalidDid_ShouldThrow`
: Result: stack overflow in `VerificationService.ResolvePublicKeyAsync` recursion path.

## Review

- [x] Detailed report written to `tasks/SECURITY-COMPLIANCE-REVIEW-2026-02-20.md`
- [x] Compliance verdict recorded
- [x] Security verdict recorded
- [x] Highest-risk issues prioritized

### Summary Verdict

- `100% spec compliance`: **NOT achieved**
- `Security posture`: **High risk; exploitable issues present**

### Highest-Risk Findings (P0/P1)

- `S-01`: stack-overflow denial of service in DID resolution recursion (`src/ZcapLd.Core/Services/VerificationService.cs`)
- `S-02`: delegated capability forgery risk from missing parent-controller authorization enforcement (`src/ZcapLd.Core/Services/VerificationService.cs`)
- `C-03`: capability chain format produced by delegator is non-compliant (missing embedded parent object) (`src/ZcapLd.Core/Services/CapabilityService.cs`)
- `C-05`: invocation proof generation omits required invocation proof fields (`src/ZcapLd.Core/Services/SigningService.cs`)
- `C-07`: proof generation/verification does not follow Ed25519Signature2020 canonicalization + proof-configuration algorithm (`src/ZcapLd.Core/Cryptography/JsonCanonicalizer.cs`)

## Compliance Test Suite Task (tests-only, no remediation)

- [x] Confirm task scope with user: add tests only, do not fix implementation
- [x] Use normative MUST/SHOULD list from `docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md` section 10
- [x] Add explicit compliance unit tests for each MUST/SHOULD requirement
- [x] Add explicit compliance integration tests for each MUST/SHOULD requirement
- [x] Ensure each test includes requirement ID traceability
- [x] Run the compliance suite to confirm compile/execution (failing assertions allowed)
- [x] Document test suite location and execution command
❌ No implementation found
❌ Critical for security

### Invocation (0% complete)
❌ No verification logic
❌ No method support

### Caveats (20% complete)
✅ Basic model structure
✅ Two example implementations
❌ No evaluation logic
❌ No inheritance logic

### Testing (10% complete)
✅ Basic test structure
❌ Only trivial tests
❌ No spec compliance tests
❌ No integration tests

---

## Overall Status: 15-20% Complete

**Blockers**: Core cryptography, proof creation, chain verification
**Next Steps**: Phase 1 (Core Cryptography) must be completed first
**Timeline**: 4-5 weeks to minimal compliance, 6-8 weeks to production-ready

---
