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
