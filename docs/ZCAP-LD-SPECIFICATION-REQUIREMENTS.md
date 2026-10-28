# ZCAP v0.4.0 requirements and supported profile

Source: [Authorization Capabilities v0.4.0](https://w3c-ccg.github.io/zcap-spec/v0.4.0/).
Implementation target: zcap-dotnet 5.0.0, .NET 10. This document describes the
supported profile and its verification evidence; it does not claim a percentage
of complete specification compliance.

## Specification history and caveat ambiguity

The published v0.3.0 already contains the URL Path- or Query-based Attenuation
note removing vocabulary-based caveats and limiting additional contexts to
proof vocabulary. These were not newly introduced v0.4 requirements. The
[upstream changelog](https://github.com/w3c-ccg/zcap-spec/blob/main/CHANGELOG.md)
classifies v0.4 changes as non-normative, including modernized proof examples.

The text still contains a Caveats section and illustrative `ValidWhileTrue`
objects. Given that inconsistency, this library explicitly supports native
attenuation and rejects vocabulary `caveat` fields. This is a security/profile
choice, not a claim that the document unambiguously mandates rejecting all such
fields. A private vocabulary would not establish enforcement by other stacks.

## Data model and proof requirements

| Area | Specification requirement / library behavior | Evidence |
| --- | --- | --- |
| Root | String `@context` = `https://w3id.org/zcap/v1`; URN ID; controller; absolute invocation target. No delegation proof, parent, expiry, actions or caveat. Unknown root fields can additionally be rejected by policy. | `VerificationServiceTests`, `NormativeUnitComplianceTests` |
| Delegated | Context array beginning with zcap/v1; URI ID and parent reference; controller; target; expiry; delegation proof. Invocations and chain verification require delegated expiry. | `NormativeIntegrationComplianceTests`, `WireFormatTests` |
| Controllers | URI string or array. Resolve verification relationships for delegation/invocation rather than relying only on DID string equality. | `MultiControllerAuthorizationTests`, `ControllerDocumentAuthorizationTests` |
| Proof sets | One proof object or an array; at least one valid delegation proof. Unsupported caveats are screened across all proof-set members. | `MultiProofVerificationTests`, `CapabilityProfileTests` |
| Ancestors | `[rootId]` at first hop; deeper chains use `[rootId, ...ancestorIds, {immediateParent}]`. Reject duplicate IDs and inconsistent embedding. | `DelegatedInvocationComplianceTests`, `VerificationServiceTests` |
| Root resolution | Explicit trusted root or `IRootCapabilityResolver`. Root is never embedded as a delegated ancestor. | `CapabilityChainShapeTests` |
| Chain bound | Limit work while walking chains; maximum length 10. | `VerificationServiceTests` |
| Cryptography | RDFC-1.0 with Ed25519Signature2020 or EcdsaSecp256r1Signature2019, via DataProofs/NetCrypto. Hash proof options first, document second. | `ProofGoldenVectorTests`, `CanonicalizationGoldenVectorTests`, `interop/run-interop.sh` |

The v0.4 examples use `DataIntegrityProof` / `eddsa-jcs-2022`; examples alone do
not require a cryptosuite migration. This library retains its explicitly tested
RDFC/legacy-suite profile. P-256 is supported locally but is not covered by the
stock Ed25519 JavaScript harness.

## Attenuation

A child cannot expand allowed actions or extend its parent's expiration. A
restricted parent requires a non-empty subset of actions on the child. Native
`expires` replaces the removed `ExpirationCaveat`.

`VerificationPolicy.AllowTargetAttenuation` defaults to false. Exact targets are
accepted; differing parent/child or capability/invocation targets are rejected.
When enabled, the child/invocation target must extend the base target with `/` or
`?` if it has no query, or `&` if it already has a query. Matching is ordinal.
The library additionally rejects literal `..` path segments in the suffix.

`DelegateCapabilityAsync(..., invocationTarget: ...)` permits an explicitly chosen
narrower target and rejects widening before signing. Issuing a narrow capability
does not oblige a verifier to enable attenuation. Tests cover both policy values,
creation, standalone proof/chain verification, root/delegated invocations, and the
suffix boundaries (`CapabilityProfileTests`, interop profile matrix).

A resource API must enforce the semantic restriction represented by the target.
A later duplicate query parameter must not overwrite an earlier restriction.
Routing, proxies and authorization must agree on URL interpretation. Usage limits
require application state and atomic accounting; a query string alone does not
implement a counter.

## Invocation and relying-party expectations

Root invocation references the root ID. Delegated invocation embeds the full
capability. The DI application-document API requires expected action and target,
and optionally expected root IDs; mismatches fail closed. The application
context must include zcap/v1 and the proof suite context before the signature is
trusted. The convenience `Invocation` envelope is a separate in-stack format.

Freshness, controller authorization, signature validity, native restrictions,
revocation and nonce replay checks apply. Invocation `created` must be parseable,
within the nonce window, and no more than the configured skew in the future.
Delegation proofs are durable and have no lower freshness bound.

Evidence: `DataIntegrityInvocationTests`, `DelegatedInvocationComplianceTests`,
`VerificationServiceFreshnessTests`, `VerificationServiceReplayTests` and interop
checks 7–12. HTTP-signature transport is not implemented by this library (#119).

## Unsupported caveats and security regression contract (#149)

Any capability-level `caveat` key is rejected, regardless of type or value,
including null/empty/unknown values and extension data. Checks include embedded
ancestors, secondary proofs, explicit/resolved roots, and every capability
representation in an envelope invocation or signed revocation request. Signing and creation reject the same
unsupported profile. Arbitrary application-document properties are not treated
as capability policy.

Equivalent keys `https://w3id.org/security#caveat` and `sec:caveat` are also rejected.
The bounded scan includes capability/proof extension JSON: `@nest`, `@graph`,
`@included` and objects sharing the capability ID can otherwise add the same RDF
predicate. Keys that are JSON-LD keywords (other than `@context`) or IRIs are refused
in every profile, because they can restate `allowedAction` or `expires` where the
verifier's model does not read them. Capability and proof contexts are limited to zcap/v1 and supported suite
contexts; inline aliases and unrelated offline vocabularies are refused even by
signing and standalone proof verification. This is a deliberate profile restriction.
Reserved caveat/context keys inside proof extensions are screened at signing too.

`UsageCount.maxUses` and `ValidWhileTrue.uri` were not covered by the old RDFC
signature. Changing either could leave verification valid. `Expiration.expires`
was covered because the context defines `expires`; that did not prove integrity
of other caveat types. `CapabilityProfileTests` constructs legacy signed fixtures
below the issuance gate so verifier regressions cannot be masked by signer rejection.

## Opt-in caveat extension profile (#157)

The contract above describes the standard profile (no `CaveatTypeRegistry`), and it is unchanged.
A verifier configured with a registry admits `caveat` only as specified in
[the caveat profile](CAVEAT-PROFILE.md). This is an extension outside ZCAP v0.4. Its rules and
their tests:

| Requirement | Tests |
| --- | --- |
| Type and every parameter value are signed; post-signing edits fail, including the embedded ancestor | `CaveatTamperingTests` |
| Inputs RDFC would drop are rejected (undeclared parameter, unregistered type, missing type context, non-canonical number, null, aliases, nested placement) | `CaveatIntegrityTests` |
| Children restate and narrow every inherited caveat, even when signed by the real parent controller | `CaveatAttenuationTests` |
| Only invocation authorizes; chain/proof APIs return `CaveatEnforcementRequired`; missing handler is `UnsupportedCaveat` before the nonce is used | `CaveatIssuanceAndProfileTests`, `CaveatIntegrityTests` |
| Handlers run after replay checks, atomically debit hierarchical budgets, release on later denial | `CaveatEnforcementTests` |
| Published deterministic fixtures and RDFC literal = RFC 8785 number domain | `CaveatProfileFixtureTests` |
| Registration rules (names, reserved terms, extension data, frozen registry) | `CaveatTypeRegistryTests`, ASP.NET `CaveatDependencyInjectionTests` |

Fields the verifier keys on must be signed in every profile: envelope `created` is signed under
the suite context, ids must be normalized absolute IRIs, and a proof-set link verifies only with
the proof that signed its parent's chain (`SignedBindingTests`).

## Revocation and optional verifier policies

Signed revocation requests prove key possession and authorize a controller of
the capability or an ancestor. Every link is checked for revocation. Store records
until expiry and share authoritative state across verifier replicas. Distribution
to independently operated or unknown verifiers requires an explicit deployment
protocol; it is not supplied by the spec's endpoint model. Records are keyed by bare
capability id and are not yet scoped to their authorizing root, so only roots the
revoking verifier trusts are protected from forced revocation; see
[Revocation scope](../architecture.md#revocation-scope-known-limitation).

The verifier offers opt-in expiration ceilings (three months by default), required
delegation `created`, and unknown-root-field rejection. Expiration ceiling and
delegation-time policy carve-outs for revocation remain separate from the always-on
unsupported-caveat rejection. See `VerificationServicePolicyTests`,
`VerificationServiceDelegationFreshnessTests` and the revocation tests.

## Compatibility criteria

The existing 12 JS/.NET interop assertions retain their expected results. The
extended matrix covers target attenuation with both settings in both directions
and distinct JS vocabulary-validation, authentic restriction and signature-tampering
cases. JS accepts correctly signed recognized caveat nodes without enforcing their
meaning; .NET refuses them. Tests of a peer implementation
are evidence for these cases, not proof of complete v0.4 compliance or distributed
revocation interoperability. See [the compatibility report](ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md).
