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
9. [x] Commit; adversarial agents on the committed diff; fix confirmed findings.
10. [x] Follow-up issue (#161: signed revocation binds only the id); lessons; results below. Ask before
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
- **Red team (two agents on commit 1182b28, each with executed probes in its own worktree):** no
  write-side forgery, cross-tenant write, "already revoked" block or un-revoke survived; every forged
  record landed in the forger's own scope. Fixed before merge (second commit):
  - *F1 (medium):* the standalone sweep ran outside the method's `try` and the nested descent
    deserialized embedded parents, so crafted JSON (a whitespace nested id, `"expires": 123`) threw out
    of `VerifyCapabilityProofDetailedAsync`. The sweep now runs inside the `try`, validates every nested
    id, and treats an unparsable embedding as a proof that does not fit.
  - *F2 (medium):* the sweep trusted the presented, unverified embedded parent to name each ancestor's
    delegator, so a delegator whose own capability was revoked could re-sign a child around a
    proof-less copy of it and pass the standalone path (the 5.x id sweep caught this). The sweep is now
    a route walk mirroring the chain walk's acceptance rules: a nested proof must name the chain's
    prefix and embed the right parent; an embedded parent with no fitting proof fails closed as
    `MalformedCapability`; lookups are de-duplicated and the 256 cap fails closed. Three regression
    tests; ablations A7 (no-fitting-proof not fail-closed) and A8 (no nested descent) each go red.
  - *Low:* explicit-root overload comment and XML warning (the root argument is a caller-vouched trust
    anchor); demo migration no longer crash-loops on a bad legacy row and probes inside an IMMEDIATE
    transaction (test added); store contract documents read-your-writes and delete-during-read;
    `IsCapabilityRevokedAsync(id, Unscoped)` footgun documented; co-signed-parent and self-asserted-root
    consequences documented on `RevokeCapabilityAsync` and in architecture.md.
  - Final: 776 tests (728 Core + 48 ASP.NET), warnings identical to baseline.
- **PR #162 review round 1 (owner, 2026-10-29), both findings valid and fixed (third commit):**
  - *[P2] The standalone sweep trusted an unauthenticated ancestor scope.* My route walk validated
    the ancestry's shape and then read the embedded parent's `verificationMethod` as its delegator;
    the parent's controller swapped that method on a copy of the revoked parent and the sweep
    queried the wrong scope. Fix: `WalkRouteAsync` verifies each embedded ancestor's fitting proof as
    a chain link (`VerifySingleDelegationProofAsync`: signature, parent-controller authorization,
    attenuation, expiry; created/caveat policy off) against the next ancestor up to the resolved or
    explicit root before trusting its delegator; a parent with no proof that fits and verifies fails
    the candidate with that proof's reason (`InvalidSignature` for the swap). Below the first level
    the standalone path now needs a root resolver or explicit root.
  - *[P2] An unusable extra proof vetoed a valid proof.* The early `return MalformedCapability`
    rejected the whole capability. Fix: the standalone core evaluates each delegation proof as its
    own candidate (link first, then its authenticated ancestry and revocation sweep); the first to
    pass wins; otherwise a `Revoked` found on a verified route is reported, else the last failure.
    `VerifyDelegationProofAsync` is removed (its loop is now the core).
  - Tests: the owner's two reproductions (`…SwappedVerificationMethod…`, `…UnusableExtraProof…` in
    both orders, the latter also re-checking `Revoked` after revoking the parent). One existing
    caveat test moved from `CaveatEnforcementRequired` to `InvalidSignature` for a tampered embedded
    parent (the chain path already said so); one of my earlier tests relaxed to "not valid" because
    the leaf-link shape check now runs first. Ablations A9 (no ancestor authentication), A10 (first
    failure vetoes), A11 (no `Revoked` precedence) each go red. 779 tests; warnings unchanged.
- **Open (#161):** a signed revocation binds only the capability id, so a captured request replayed
  within the freshness window with another verified copy writes further records before the nonce
  denies it (bounded by the revoker's own authority; the review extended a revocation to a co-signer's
  scope this way). Options recorded in the issue.
