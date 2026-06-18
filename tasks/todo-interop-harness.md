# Live cross-stack RDFC golden-vector harness

Goal: prove **end-to-end** that zcap-dotnet's RDFC-1.0 path interoperates with
`@digitalbazaar/zcap` v9 for **capability delegation proofs** (the canonicalization
blocker, #1 in the interop report). Invocation interop is OUT OF SCOPE here
(separate envelope blocker #2).

## Success criteria
1. **Outbound (dotnet→db):** a zcap-dotnet RDFC-signed *delegated capability*
   verifies under `@digitalbazaar/zcap` (`jsigs.verify` + `CapabilityDelegation`
   purpose + Ed25519Signature2020 + did:key documentLoader) → `verified: true`.
2. **Inbound (db→dotnet):** a `@digitalbazaar/zcap`-produced delegated capability
   verifies under zcap-dotnet `VerificationService` configured `"RDFC-1.0"`.
3. A negative control (tampered `allowedAction`) is REJECTED on both sides.
4. One command runs the whole round-trip and prints PASS/FAIL per direction.
5. Committed sample vectors under `interop/vectors/` as golden references.

## Plan
- [ ] `interop/js/` Node project: pinned deps, shared documentLoader (zcap/v1 +
      ed25519-2020 contexts + did:key + registered root), `gen.mjs`, `verify.mjs`.
      Self-test JS→JS first to prove the recipe. (subagent)
- [ ] `interop/ZcapLd.Interop/` .NET console (standalone, NOT in ZcapLd.sln):
      - `gen` → deterministic root + delegated (RDFC, Ed25519, did:key) → vectors/
      - `verify <delegated> <root>` → VerificationService RDFC → exit 0/1
      - deterministic keys from fixed 32-byte seeds (KeyGen.FromPrivateKey)
- [ ] `interop/run-interop.sh` orchestration: dotnet gen → js verify; js gen →
      dotnet verify; negative controls.
- [ ] Run, iterate until all four directions + controls pass.
- [ ] Update interop report §7 (live round-trip now done) + README pointer.

## Review (2026-06-18) — DONE ✅

All success criteria met. `interop/run-interop.sh` runs **6 checks, all pass**:
1. Outbound single-level: dotnet RDFC → `@digitalbazaar/zcap` 9.0.1 verify — PASS
2. Inbound single-level: db → zcap-dotnet RDFC verify — PASS
3. Negative outbound (tampered allowedAction) — FAIL (rejected) ✅
4. Negative inbound (tampered allowedAction) — FAIL (rejected) ✅
5. Multi-level outbound: dotnet `[rootId,{parent}]` → db — PASS
6. Multi-level inbound: db 2-level → dotnet — PASS

Deliverables: `interop/ZcapLd.Interop/` (.NET CLI, standalone, not in sln),
`interop/js/` (real @digitalbazaar/zcap harness), `interop/run-interop.sh`,
`interop/README.md`. Vectors git-ignored (reproducible outputs). Report §7 +
up-front caveat updated to reflect the live proof. Invocation interop remains
out of scope (structural envelope blocker #2).

Key empirical finding: zcap-dotnet's RDFC-1.0 path is byte-compatible with
`jsonld-signatures` (proof-hash-first `SHA-256(RDFC(proofOptions))||SHA-256(RDFC(doc))`).
The JCS default is NOT interop — RDFC-1.0 is the interop mode.

## CI wrapper (2026-06-18) — DONE ✅

- `tests/ZcapLd.Interop.Tests/` — `[SkippableFact]` xUnit test that shells
  `run-interop.sh`, asserts exit 0 + "ALL 6 CHECKS PASSED", skips when
  bash/node/npm/dotnet absent. NOT in ZcapLd.sln (core CI stays Node-free).
  Uses `Xunit.SkippableFact` (xunit 2.9.3 has no `Assert.Skip`).
- `.github/workflows/ci-interop.yml` — ubuntu, setup-dotnet 10.0.x +
  setup-node 22, `npm ci`, then `dotnet test` the wrapper. Path-filtered to
  interop/**, src/ZcapLd.Core/**, tests/ZcapLd.Interop.Tests/**, the workflow.
- Verified locally: wrapper runs the full harness and passes (all 6 OK).

## Key compat invariants to honor
- did:key controllers must be GENUINE (`did:key:z6Mk…` derived from the real
  Ed25519 public key), not synthetic — JS resolves them via did-method-key.
- verificationMethod = `did:key:z6Mk…#z6Mk…` (fragment form).
- root id = `urn:zcap:root:{encodeURIComponent(target)}`; use a plain http(s)
  target (no `! ' ( ) *`) so encoding divergence (blocker #4) is not in play.
- delegated `@context` = `[zcap/v1, ed25519-2020/v1]`; proofPurpose
  `capabilityDelegation`; first-level chain = `[rootId]`.
- fresh timestamps at run time (expires = now+30d) so digitalbazaar's expiration
  check passes; also emit a fixed-timestamp golden vector for byte-stability.
