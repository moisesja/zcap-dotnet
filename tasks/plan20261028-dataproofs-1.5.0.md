# Plan — adopt DataProofs 1.5.0 and NetDid 4.0.0 (PR #160 follow-up)

Branch: `157-secure-opt-in-custom-caveats` (PR #160, open). The user reported on 2026-10-28 that
dataproofs-dotnet and net-did "have been upgraded and published". Intent: move zcap onto those
releases. DataProofs 1.5.0 closes dataproofs-dotnet#36, the fail-closed canonicalization issue filed
from #157.

## What the releases change for zcap

- **DataProofs 1.5.0** refuses RDFC input it would drop or respell (`JsonLdDataLossException`):
  - undefined terms;
  - malformed, relative or respelled IRIs;
  - Legacy proofs whose proof options the document's contexts do not define.

  Accepted input canonicalizes to the same bytes as before.
- **NetDid 4.0.0** has a major version for did:webvh witness files, which zcap does not use. It needs
  Microsoft.Extensions 10.0.14, so the Microsoft pins move with it (NU1605).

## Measured fallout (DataProofs 1.5.0 + NetDid 4.0.0, no code changes)

86 Core and 19 ASP.NET tests fail; all of them are `JsonLdDataLossException`.

1. **Every signed revocation fails to sign.** None of these are defined by any context:
   - the proof purpose `capabilityRevocation`: zcap/v1 does not define it, and the suite's
     `proofPurpose` is `@type: @vocab`;
   - the `revocationReason` and `revocationMetadata` proof extensions.

   1.4.0 silently left all three unsigned. This was documented as "purpose not signed, reason
   informational".
2. Adversarial tests forge lossy documents with `RawProofSigner` through the strict canonicalizer:
   undefined caveat terms, malformed or respelled IRIs, dot-segment targets. They can no longer
   produce a signature.
3. Both golden vectors use a capability with `@context: zcap/v1` only. Under that context the proof's
   `type`, `created`, `proofPurpose` and `verificationMethod` were never signed. 1.5.0 refuses it.
   `CapabilityService` always emits `[zcap/v1, suite]`, so issued capabilities are unaffected.
4. The DI "stripped zcap context" forgery test signs through `SigningService`, which now refuses.
5. `CanonicalIri.IsSignedTarget` tolerated one rewrite: `https://host?q` was signed as
   `https://host/?q`. 1.5.0 refuses it, so that branch is dead.

## Decisions

- **Bump to latest stable:**
  - DataProofs ×3 to 1.5.0;
  - NetDid.Core and Method.Key to 4.0.0 (the interop csproj too);
  - Microsoft.Extensions.Logging.Abstractions, AspNetCore.Mvc.Testing and Data.Sqlite to 10.0.14;
  - SourceLink to 10.0.403.

  NetCrypto 1.7.1 and NetCid 1.6.0 are already the latest.
- **Revocation context.** `urn:zcap-dotnet:revocation-context:v1` is served from memory and never
  fetched. It defines:
  - `capabilityRevocation` → `urn:zcap-dotnet:revocation:v1#capabilityRevocation`, distinct from
    every DID verification relationship, so no other purpose signs alike;
  - `revocationReason` as a string;
  - `revocationMetadata` as `@json`.

  `LegacyProofCrypto` and the oracle inject it, after zcap/v1 and the suite context, only for a
  context-less document whose proof purpose is `capabilityRevocation`. Envelope invocation bytes are
  unchanged, and the invocation golden hash stays. The wire is unchanged: revocations stay
  context-less. Effect: the revocation purpose, reason and metadata are now signed. They remain
  informational for authorization.
- **Tests model a lenient attacker.** A test-only `LenientRdfcCanonicalizer` reproduces DataProofs
  ≤ 1.4.0, which is dotNetRDF without the data-loss checks. `RawProofSigner` signs with it by
  default. A lossy document thus still gets a signature that a lenient processor would accept, and
  the tests keep proving that zcap's own guards reject it. A new test pins that the production
  canonicalizer refuses the same inputs (second layer).
- **Golden vectors** use the production context `[zcap/v1, ed25519-2020/v1]`. The new values are
  cross-checked: DataProofs 1.4.0 produces identical bytes for that input, so the wire is unchanged
  for real capabilities.
- **CanonicalIri:** `IsSignedTarget` becomes exact equality. The checks stay as the first,
  specifically-reported layer.
- **Kept:** every zcap guard (closed caveat key set, contexts, ids). DataProofs is now a second
  layer, not a replacement.

## Steps

- [x] Bump pins; build (4 pre-existing warnings, unchanged)
- [x] Revocation context (loader, `LegacyProofCrypto`, oracle) + tests (tampered reason/purpose now break the signature)
- [x] `CanonicalIri.IsSignedTarget` simplification + test for `https://host?q`
- [x] `LenientRdfcCanonicalizer`, `RawProofSigner`, DI stripped-context test, golden vectors (cross-checked on 1.4.0)
- [x] Production canonicalizer refuses lossy inputs (layer test)
- [x] Docs: CHANGELOG, CAVEAT-PROFILE, architecture, AGENTS, READMEs where relevant
- [x] Verify: build, all tests, example, interop, Release packs; ablation of the revocation-context guard
- [x] Adversarial review of the revocation-context change (findings fixed below)
- [ ] Commit and push to PR #160

## Results

- Commit e14c28e. Clean build: the same 4 pre-existing warnings. Tests: 657 Core and 37 ASP.NET
  pass (7 new: the revocation golden, 4 lossy-input layer cases, lenient/production byte parity,
  and a query-without-path target).
- Golden values: capability payload `34C3D9D9…`, proofValue `z3zjEx6a…`. The same values come out
  with DataProofs 1.4.0 swapped back in. Revocation payload `71BB1368…`. The invocation golden is
  unchanged.
- Interop: 12/12 plus 118 profile checks against `@digitalbazaar/zcap`. The example runs
  (EpsilonBudget, revocation). Release packs build.
- Ablations:
  - removing the revocation context fails 58 Core and 19 ASP.NET tests;
  - loosening `IsSignedTarget` fails 6 tests.
- Probe: an undefined extension member (`"note"`) added to a signed capability used to verify; it now
  returns `InvalidSignature`, and signing throws `ProofGenerationException`. Noted in the CHANGELOG.

### Adversarial review of e14c28e

An isolated red-team agent found nothing new in e14c28e itself:

- Cross-purpose replay between revocation, invocation and delegation is refuted, because the
  purpose IRI is signed.
- A wire `@context` on a revocation request is discarded.
- No DataProofs exception escapes a verify API.

It did find one critical pre-existing bypass and three smaller issues:

1. **CRITICAL, pre-existing.** I reproduced it on the released ZcapLd.Core 5.0.0 and on main.
   - **The attack:** a delegatee rewrites its own `allowedAction` as `"@nest": {…}`, as an
     `@included` node with its own id, or under the full IRI key. The triples are identical, so the
     delegator's signature still verifies. The model sees no `allowedAction`, so every action is
     allowed under a root that has none.
   - **Scope:** the envelope and Data Integrity APIs, at any depth. The same trick also hid
     `expires` from standalone proof verification.
   - **Fix:** `CapabilityProfile` refuses `:` keys and keywords other than `@context` in every
     profile; before, only a verifier with a caveat registry refused them. `revocationMetadata` is
     exempt, because it is a JSON literal. `RestatedTermTests` covers this.
2. **Revocation `reason`/`metadata` could be erased** by rewriting them as `["…"]`,
   `{"@value": …}` or `@nest`. The verifier now refuses any shape other than a string reason and
   an object of strings for metadata.
3. **Two binding tests asserted only `IsValid == false`** and passed thanks to DataProofs alone.
   They now assert `MalformedCapability`.
4. **The docs overstated "RDFC only".** DataProofs' legacy verifier also tries the JCS variant.
   This is pre-existing and not a forgery, because JCS signs bytes verbatim. CHANGELOG, AGENTS and
   test comments are corrected. Follow-up candidate: verify the RDFC variant only.

Not fixed: a malformed modeled proof member (`"domain": 123`) returns `CouldNotVerify` instead
of `MalformedCapability`. It is pre-existing, low severity and fails closed; follow-up candidate.

Verification after the fixes:

- **Ablations:** removing the keyword rule fails 7 tests; removing the shape check fails the
  array-erasure case.
- **The red team's PoCs:** all 9 exploit PoCs are now blocked, and the 4 refutation PoCs still
  pass.
- **Tests and interop:** 668 Core and 37 ASP.NET tests pass, and interop passes 12/12 plus 118
  profile checks.
