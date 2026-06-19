# Path-A invocation interop (#117) — DI capabilityInvocation

Branch: `117-path-a-invocation-interop` (stacked on `verify-path-spec-closeouts` / PR #118).
Approach: **ADDITIVE** — a new digitalbazaar-compatible DI invocation mode alongside the existing
self-contained `Invocation` envelope. The envelope stays for in-stack use AND revocation (which
signs an invocation and is zcap-private control-plane — not a db-interop concern). Do NOT rip it out.

## Design (harness-first; the JS harness defines the byte-exact target)
- db signs an **application document** + attaches a `capabilityInvocation` **proof**; the invocation
  metadata (`capability`/`capabilityAction`/`invocationTarget`) lives ONLY in the proof. Signed bytes
  = SHA256(canon(proofOptions)) || SHA256(canon(applicationDocument)).
- Production signing input is built by `LegacyProofCrypto` → DataProofs (NOT ProofSigningPayloadBuilder,
  which is the test oracle). DataProofs derives proof-options `@context` from the DOCUMENT's `@context`.
  So the application document must carry `@context = [zcap/v1, ed25519-2020/v1]` (suite ctx from
  `ZcapSuiteCatalog.GetByKeyType(...).ContextUrl`). `LegacyProofCrypto.BuildDocumentElement` already
  leaves an existing `@context` as-is.
- `created` precision is NOT a verification issue: db re-canonicalizes the as-presented doc, so any
  valid xsd:dateTime verifies. (Second-precision only matters for byte-identical vectors, not interop.)

## Steps
- [ ] (subagent) Build db-native DI invocation harness in interop/js (invoke-gen/invoke-verify +
      lib.mjs); self-test JS→JS PASS + tamper FAIL; REPORT exact wire shape + CapabilityInvocation
      verify recipe (expectedTarget/expectedAction/expectedRootCapability).
- [ ] .NET PATH-A SIGN: new `SigningService.SignCapabilityInvocationAsync(appDoc, capability,
      capabilityAction, invocationTarget, signerDid, createdOverride?)` → secured document (appDoc +
      proof). Match the harness's app-doc shape byte-for-byte. Root = capability id string; delegated =
      full embedded zcap. Iterate against `interop/js/invoke-verify.mjs` until PASS.
- [ ] .NET PATH-A VERIFY: `VerifyCapabilityInvocationAsync(securedDocument, ...)` — extract proof,
      recompute signature, verify authorization (resolve capability/chain, action allowed, target
      match, chain valid, revocation, replay). Test reverse: JS-gen invocation → .NET verify PASS.
- [ ] .NET unit tests (round-trip, tamper, root + delegated).
- [ ] Wire invocation cases into `interop/run-interop.sh` (both directions + tamper).
- [ ] Docs (README/ARCHITECTURE/CHANGELOG), update #117, PR.

## Acceptance
`interop/run-interop.sh` round-trips a DI invocation BOTH directions (dotnet→db, db→dotnet) + tamper
reject, alongside the existing delegation cases. Existing envelope invocation + revocation untouched.

## Review (2026-06-19) — DONE ✅
All steps done. `interop/run-interop.sh` = **12/12** (6 delegation + 6 invocation: root + delegated,
both directions, + 2 tamper negatives). Suite: **460 Core + 33 AspNetCore green**.
- SIGN: `SigningService.SignCapabilityInvocationAsync(...)` → secured `{appDoc, proof}` (metadata only
  in proof; appDoc `@context=[zcap/v1, ed25519-2020/v1]` + `id` + absolute-IRI `type`). Reuses
  `LegacyProofCrypto` (same RDFC hash-concat as delegation).
- VERIFY: `VerificationService.VerifyCapabilityInvocationAsync(JsonObject[, root])` — signature over the
  app doc, then chain/attenuation/caveats/controller/freshness/replay (reuses existing helpers).
- CLI: `gen-invocation` / `verify-invocation`. JS: `invoke-gen.mjs` / `invoke-verify.mjs` / lib.mjs.
- Tests: `DataIntegrityInvocationTests` (root + delegated round-trip, tamper, action-not-allowed).
- Additive: legacy `Invocation` envelope + revocation untouched. Path B (HTTP Sig) deferred → #119.

## Adversarial security review (2026-06-19) — found + fixed 2 real issues
Red-team workflow (16 agents) against the new verifier found, execution-confirmed:
- **CRITICAL (forgery):** no application-document `@context` validation → RDFC drops the unbound
  zcap/v1 auth terms → attacker rewrites `capabilityAction`/`invocationTarget` post-signing, still Valid.
  FIX: validate doc `@context` (array, `[0]==zcap/v1`, includes suite ctx) before trusting the signature
  (mirrors chain R-CTX-2). New `AsArrayContextNode` helper.
- **HIGH (confused-deputy):** no relying-party `expected*` gate. FIX: `VerifyCapabilityInvocation*` now
  REQUIRE `expectedAction` + `expectedTargets` (optional `expectedRootCapabilityIds`), fail closed on
  mismatch; removed the no-expectation overloads; added the safe method to `IVerificationService`.
- **LOW** (nonce/result not bound to action) — addressed by the expected* gate.
- 6 attack classes held (signature binding, chain forgery, controller-auth, replay, etc.).
Regression tests added: stripped-`@context` forgery, expected-target/action/root mismatch (all reject).
Suite 464 Core + 33 AspNetCore green; interop 12/12.
