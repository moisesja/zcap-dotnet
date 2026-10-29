# Issue #158: scope revocation records by delegator (mirror the Digital Bazaar JS stack)

Branch: `158-scope-revocation-records`, created from `origin/main` @ 37aacbc.

## Context

`VerificationService.RevokeCapabilityAsync` stored a record under the bare capability id, and every
chain check looked a link up by that id. Delegated ids are chosen by whoever signs the delegation. So
anyone with a valid chain under any trusted root could mint a delegated capability that carries a
victim's id, revoke it, and thereby revoke the victim's capability: within one root, across roots on
one verifier, and for custom roots that another verifier sharing the store trusts. #156 anchored root
ids only. The impact is forced revocation (denial) across tenants. 6.0.0 is unreleased, so this
breaking change lands in 6.0.0.

## Human decisions (2026-10-29)

Asked for the grounding before choosing: "what does the spec say? what does the JavaScript
implementation do?"

- **Spec (ZCAP v0.4.0)** defines no record key or scope. Normatively, revocations are "submitted to
  the verifier's revocation endpoint for the associated invocation target", and the verifier "MUST
  store revoked zcaps until they expire". The endpoint is only in the non-normative Wishlist:
  `POST {rootInvocationTarget}/zcaps/revocations/{id}`, from any controller in the chain. There is
  no status GET.
- **JS stack**: `@digitalbazaar/zcap` exposes each verified link's `delegator` (the controller of the
  signing verification method) to an `inspectCapabilityChain` hook; `ezcap-express`
  `authorizeZcapRevocation` lets any chain controller revoke, refuses roots, and records the delegator
  of the revoked zcap; `bedrock-zcap-storage` keeps a unique index on `(meta.delegator,
  capability.id)` and checks every delegated link by `(id, delegator)`.
- **Chosen:** key records by **(delegator, capability id)**, like Bedrock. **Remove** the anonymous
  status GET; the spec and Bedrock have only the POST.
- Rejected: exact-route and route-prefix scoping (sound, but beyond both the spec and the JS stack).

## Design

`RevocationScope` (new, `Models/`): `Delegated(delegator)` for a delegated capability (delegator =
DID of the verification method that signed the link's verified delegation proof), `Root` for a
trusted root (#155), `Unscoped` for 5.x records and operator writes through
`IRevocationService.RevokeAsync` (honored on every link; never written by the signed path).

Store key: SHA-256 over an RFC 8785 object; opaque, fixed width, no bare id is ever a key.

Soundness: a forged copy carrying the victim's id is signed by the attacker, so its record is
`(attacker, id)`, which no honest link looks up. Forging `(D, id)` needs D's key, and D can already
revoke. Residuals (match JS; documented): a delegator reusing a child id; a holder re-routing under a
chain they already hold; proof sets naming different chains revoke only the accepted route;
verifiers sharing a store but disagreeing on a root id.

API (breaking): `RevocationRecord`/`RevocationRequest` gain `Scope`; `IRevocationStore` becomes
`UpsertAsync` / batch `GetAsync(keys)` / `DeleteAsync(key)`; `IRevocationService` gets scoped
`GetRevocationAsync`/`IsRevokedAsync` and batch `FindRevocationAsync`;
`IVerificationService.IsCapabilityRevokedAsync(id, scope)`. `RevocationService` refuses unrequested
keys, deletes expired records by exact key, and reads back after upsert.

Verifier: revocation is looked up after each link's proof verifies (as JS runs its hook), in one
batch per chain; the bare-id `ChainSearch.Revoked` memo is removed (a junk proof could poison it).
Standalone path checks the leaf's delegators, the root, the embedded parent's delegators, and
`Unscoped` for middle ancestors. Revocation write records `Root` or `Delegated(delegator of the
accepted leaf proof)` plus co-signers of the same chain.

ASP.NET: remove `MapGet`. Demo: new `revocation_records` table keyed by `revocation_key`, with a
one-time migration of legacy `revocation_registry` rows to `Unscoped`.

## Steps

1. [x] Models, interfaces, `InMemoryRevocationStore`, `RevocationService`.
2. [x] Verifier changes.
3. [x] ASP.NET GET removal; demo store, migration, README.
4. [x] Migrate existing call sites and tests.
5. [x] New tests (scope tests a–i, `RevocationScopeTests`, store contract tests, SQLite migration).
6. [x] Ablation per deny test.
7. [x] Docs (CHANGELOG, architecture.md, REVOCATION-INTEGRATION.md, spec requirements, READMEs,
   PACKAGE_READMEs, AGENTS.md, XML docs).
8. [x] Build (warnings vs baseline: 4), tests, run examples and demo.
9. [ ] Commit; adversarial agents on the committed diff; fix confirmed findings.
10. [ ] Follow-up issue (signed revocation binds only the id); lessons; results below. Ask before
    pushing or opening a PR.

## Results

- **Design change found while implementing:** the plan accepted that the standalone proof path
  could see only unscoped records for intermediate ancestors (a #63 narrowing). It does not need
  to: in the spec-exact shape every embedded parent carries its own delegation proof, which embeds
  *its* parent, so `StandaloneRevocationLookups` descends the nested embeddings and looks every
  ancestor up under the delegator its proof names. The pre-existing
  `VerifyCapabilityProof_WithRevokedIntermediateAncestor_ShouldReturnFalse` stays green unchanged.
- **Verifier:** revocation moves after link verification (`VerifyBuiltChainAsync` step 5), one
  `FindRevocationAsync` per chain; the bare-id `ChainSearch.Revoked` memo is gone;
  `IsRevokerAuthorizedAsync` became `AuthorizeRevocationAsync` returning a `RevocationGrant`
  (root id + scopes), with co-signers of the accepted chain recorded; `IsControllerAuthorizedAsync`'s
  refused-controller memo now records refusals only.
- **Service hardening:** unrequested or inconsistently keyed records throw (fail closed), expired
  records are deleted by exact key, and every write is read back before the replay nonce is consumed.
- **Tests:** 772 pass (725 Core + 47 ASP.NET; was 689 + 33). New: `RevocationScopeTests` (keys,
  equality, text/JSON, validation), `VerificationServiceRevocationScopeTests` (a: issue repro
  cross-root; b: custom root across two verifiers sharing a store; c: sibling; d: forged parent +
  leaf; e: genuine revocation by owner/delegator/holder seen on chain, standalone, envelope and DI
  paths with the record naming the link's delegator and root; f: forged/genuine in either order;
  g: unscoped honoured, signed path never writes it; h: co-signed leaf; i: lossy store fails closed
  with the nonce unconsumed, by-id store yields `CouldNotVerify`), `RevocationServiceTests`
  (isolation, unscoped, batch order, unrequested-record and dropped-scope guards, exact-key expiry
  eviction = plan item j), `RevocationStoreContractTests` over InMemory and SQLite plus the legacy
  migration and the primary-key check. Endpoint tests converted to POST-only with scoped assertions
  and a GET → 405 check on both hosts.
- **Ablation (each in isolation, sources checksummed back):** A1 key ignores delegator → 10 red
  (a–d, f, by-id store, scope/service isolation); A2 no co-signer recording → h red; A3 no store
  key check → by-id tests red; A4 no read-back → lossy/dropped-scope red; A5 no standalone descent
  → intermediate-ancestor test red; A6 chain lookups unscoped → every genuine-revocation path red.
- **Build/run:** warnings identical to baseline (4, pre-existing); interop CLI builds;
  `examples/ZcapLd.Examples` prints `Descendant rejected after revocation: True`; the demo on a copy
  of the real 5.x `revocations-demo.db` migrated `revocation_registry` → `revocation_records`
  (1 row, scope `unscoped`), GET → 405, unsigned POST → 403 (id match) / 400 (mismatch).
- **Open:** a signed revocation binds only the capability id, so a captured request replayed within
  the freshness window with another verified copy writes another record (bounded by the revoker's
  own authority). Tracked as a follow-up issue (step 10).
