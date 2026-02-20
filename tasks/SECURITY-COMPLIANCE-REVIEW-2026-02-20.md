# Security and Compliance Review - 2026-02-20

## Scope

- Repository: `zcap-dotnet`
- Code reviewed: all files under `src/`, `tests/`, `examples/`, `README.md`, `docs/`
- Spec baseline:
  - ZCAP-LD: https://w3c-ccg.github.io/zcap-spec/
  - Eddsa Data Integrity Cryptosuite: https://www.w3.org/TR/vc-di-eddsa/

## Method

- Reviewed implementation line-by-line.
- Mapped implementation behavior to normative `MUST` and `SHOULD` requirements in the spec.
- Ran tests to validate runtime behavior.
- Performed a threat-oriented security review (forgery, replay, DoS, key handling, authorization).

## Runtime Evidence

- `dotnet test ZcapLd.sln`
: `Failed: 3, Passed: 93, Total: 96`, then test host crash.
- `dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj --filter FullyQualifiedName~ResolvePublicKey_WithInvalidDid_ShouldThrow`
: stack overflow from recursive DID resolution path.

## Compliance Verdict

- **Not 100% compliant with ZCAP-LD.**
- Several normative requirements are either not implemented or implemented incompatibly.

## Compliance Findings

### C-01 (High) Root capability includes non-root fields

- Spec basis: root capabilities are constrained and must not include additional capability fields.
- Evidence:
  - `src/ZcapLd.Core/Models/Capability.cs:37`
  - `src/ZcapLd.Core/Models/Capability.cs:55`
  - `src/ZcapLd.Core/Services/CapabilityService.cs:54`
  - `src/ZcapLd.Core/Services/CapabilityService.cs:55`
- Issue:
  - Root capabilities created by `CreateRootCapabilityAsync` include `allowedAction` and `caveat`, and may serialize nullable non-root fields unless callers force ignore-null serializer options.

### C-02 (Medium) `controller` does not support array form

- Spec basis: controller can be a URI or an array of URIs.
- Evidence:
  - `src/ZcapLd.Core/Models/Capability.cs:26`
- Issue:
  - Model constrains controller to a single string only.

### C-03 (High) Delegation `capabilityChain` is generated in non-compliant shape

- Spec basis: chain must include root ID first, intermediate IDs, and embed immediate parent object as last element (when parent is delegated).
- Evidence:
  - `src/ZcapLd.Core/Services/CapabilityService.cs:286`
  - `src/ZcapLd.Core/Services/SigningService.cs:176`
- Issue:
  - Current chain builders produce ID-only chains and omit required embedded parent capability object.

### C-04 (High) Chain verification expects embedded parent object but generated chain does not provide it

- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:275`
  - `src/ZcapLd.Core/Services/VerificationService.cs:288`
  - `src/ZcapLd.Core/Services/CapabilityService.cs:286`
- Issue:
  - Verification assumes a chain shape that delegator currently does not emit, causing valid workflows to fail.

### C-05 (High) Invocation proof generation omits required invocation proof fields

- Spec basis: invocation proof must bind capability and invocation context fields.
- Evidence:
  - `src/ZcapLd.Core/Services/SigningService.cs:131`
  - `src/ZcapLd.Core/Models/Proof.cs:50`
  - `src/ZcapLd.Core/Models/Proof.cs:57`
  - `src/ZcapLd.Core/Models/Proof.cs:64`
- Issue:
  - `SignInvocationAsync` does not populate `proof.capability`, `proof.invocationTarget`, `proof.capabilityAction`.

### C-06 (High) Invocation verification does not validate invocation-proof-bound capability metadata

- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:109`
  - `src/ZcapLd.Core/Services/VerificationService.cs:123`
- Issue:
  - Verification checks signature over top-level invocation fields but does not require consistency with proof-level capability binding fields.

### C-07 (High) Signature algorithm path diverges from Ed25519Signature2020/Data Integrity suite requirements

- Spec basis: cryptosuites define canonicalization and proof-configuration handling.
- Evidence:
  - `src/ZcapLd.Core/Cryptography/JsonCanonicalizer.cs:8`
  - `src/ZcapLd.Core/Cryptography/Ed25519Signer.cs:93`
  - `src/ZcapLd.Core/Services/SigningService.cs:72`
- Issue:
  - Implementation uses simplified JSON canonicalization and signs only the document payload, not cryptosuite-defined transformed data + proof configuration.

### C-08 (Medium) Proof model does not support `proof` as array

- Spec basis: proof can be object or array.
- Evidence:
  - `src/ZcapLd.Core/Models/Capability.cs:62`
- Issue:
  - Model allows only single proof object.

### C-09 (Medium) Invocation model omits optional anti-replay `id`

- Spec basis: invocation identifiers are recommended for replay resistance.
- Evidence:
  - `src/ZcapLd.Core/Models/Invocation.cs:8`
- Issue:
  - Invocation model has no `id` field.

### C-10 (Medium) Context handling may reject interoperable documents

- Evidence:
  - `src/ZcapLd.Core/Services/CapabilityService.cs:161`
- Issue:
  - Root validation requires context to be `string` only; ecosystem examples commonly serialize JSON-LD context as arrays.

### C-11 (Medium) `allowedAction` shape constrained to array only

- Spec basis: action can appear as string or array.
- Evidence:
  - `src/ZcapLd.Core/Models/Capability.cs:38`
- Issue:
  - Model requires array and may reject single-string inputs.

### C-12 (Medium) Documentation claims full compliance contradicted by runtime behavior

- Evidence:
  - `README.md:18`
  - `README.md:265`
  - `tasks/todo.md:1` (historical prior state)
- Issue:
  - Current behavior and failing tests do not support “full compliance” claims.

## Security Verdict

- **High risk** for production usage without hardening.
- Critical exploitable paths identified.

## Security Findings

### S-01 (Critical) Stack-overflow denial of service in DID resolution

- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:245`
  - `src/ZcapLd.Core/Services/VerificationService.cs:246`
- Reproduction:
  - `dotnet test ... --filter ...ResolvePublicKey_WithInvalidDid_ShouldThrow`
  - Observed: stack overflow and test host crash.
- Impact:
  - Untrusted DID input can crash verifier process.

### S-02 (Critical) Delegation forgery risk: no parent-controller authorization check during chain verification

- Spec basis: delegated capability must be signed by key authorized by parent controller.
- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:170`
  - `src/ZcapLd.Core/Services/VerificationService.cs:366`
- Issue:
  - Signature validity is checked, but signer's key authorization against parent controller is not enforced in delegation verification loop.

### S-03 (High) Proof metadata is not cryptographically bound

- Evidence:
  - `src/ZcapLd.Core/Services/SigningService.cs:72`
  - `src/ZcapLd.Core/Services/SigningService.cs:80`
  - `src/ZcapLd.Core/Services/VerificationService.cs:65`
- Issue:
  - Created time, proof purpose, and verification method are not part of signed bytes under current algorithm.
- Impact:
  - Proof fields can be modified without invalidating signature under this implementation model.

### S-04 (High) Replay resistance missing for invocations

- Evidence:
  - `src/ZcapLd.Core/Models/Invocation.cs:13`
  - `src/ZcapLd.Core/Services/VerificationService.cs:80`
- Issue:
  - No nonce/challenge or freshness window enforcement for invocation proofs.
- Impact:
  - Captured invocation proofs can be replayed.

### S-05 (High) Caveat bypass risk for externally supplied chains

- Evidence:
  - `src/ZcapLd.Core/Services/CaveatProcessor.cs:89`
  - `src/ZcapLd.Core/Services/VerificationService.cs:134`
- Issue:
  - Invocation checks leaf caveats only; verifier assumes inherited caveats are already copied into leaf.
- Impact:
  - If a chain omits inherited caveats in leaf serialization, restrictions can be bypassed.

### S-06 (High) Key store is plaintext in-memory with no hardening

- Evidence:
  - `src/ZcapLd.Core/Services/SigningService.cs:12`
  - `src/ZcapLd.Core/Services/SigningService.cs:31`
- Issue:
  - Private keys are held as raw byte arrays in process memory, no secure storage, no zeroization.

### S-07 (Medium) Key store is not thread-safe

- Evidence:
  - `src/ZcapLd.Core/Services/SigningService.cs:12`
  - `src/ZcapLd.Core/Services/SigningService.cs:19`
  - `src/ZcapLd.Core/Services/SigningService.cs:53`
- Issue:
  - Concurrent access can race because `Dictionary` is unsynchronized.

### S-08 (Medium) URI prefix authorization is purely string-based

- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:332`
  - `src/ZcapLd.Core/Services/VerificationService.cs:342`
- Issue:
  - No URI normalization/canonicalization before comparison.
- Impact:
  - Potential path/query encoding edge cases can cause incorrect authorization.

### S-09 (Medium) Broad exception swallowing reduces incident visibility

- Evidence:
  - `src/ZcapLd.Core/Services/VerificationService.cs:71`
  - `src/ZcapLd.Core/Services/VerificationService.cs:137`
  - `src/ZcapLd.Core/Services/VerificationService.cs:193`
- Issue:
  - Security-critical failures are converted to generic `false` results without telemetry context.

### S-10 (Medium) DID resolution trust model incomplete

- Evidence:
  - `src/ZcapLd.Core/Services/SigningService.cs:146`
  - `src/ZcapLd.Core/Services/VerificationService.cs:241`
- Issue:
  - No DID document resolution and verification relationship checks.

### S-11 (Medium) Inconsistent chain handling can create false negatives and brittle behavior

- Evidence:
  - `src/ZcapLd.Core/Services/CapabilityService.cs:286`
  - `src/ZcapLd.Core/Services/VerificationService.cs:272`
- Issue:
  - Verifier assumptions and emitted chain format differ, weakening reliability and increasing bypass risk through alternate serializers.

### S-12 (Low) README security/compliance posture is overstated

- Evidence:
  - `README.md:18`
  - `README.md:263`
- Issue:
  - Users may deploy with false assumptions about compliance/security maturity.

## Priority Remediation Order

1. Fix `ResolvePublicKeyAsync` recursion/DoS path and add non-recursive DID parsing + explicit failure paths.
2. Enforce delegation signer authorization relative to parent controller chain.
3. Implement spec-correct capabilityChain construction and verification semantics.
4. Bind proof metadata cryptographically using a standards-compliant Data Integrity flow.
5. Enforce replay protection for invocations (challenge/nonce/freshness).
6. Harden key management (secure storage abstraction, thread-safe access, key lifetime controls).
7. Update README and docs to match actual status and supported guarantees.

## Conclusion

- The codebase has meaningful building blocks but does **not** currently satisfy a strict “100% compliant and secure” bar for ZCAP-LD.
- Production use is not recommended until critical findings (S-01, S-02, C-03, C-05, C-07) are remediated and verified by tests.
