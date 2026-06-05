# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0] - Unreleased

### Breaking Changes

- **Behaviour — replay protection ON by default**: the convenience `VerificationService` constructors (2-, 3-, and 4-arg) now default to a fresh `InMemoryNonceStore` instead of `NullNonceStore` (Issue #62; security rationale under **Fixed**). A 2.x consumer that relied on the previous (insecure) `NullNonceStore` default sees changed behaviour: same-process replays are now rejected. **Concretely, any caller that re-submits the same `Invocation` instance (same `Id`) twice — retries, idempotency layers, logging/replay middleware, and tests — now sees the _second_ `VerifyInvocationAsync` / `RevokeCapabilityAsync` call return `false`; mint a fresh `Invocation.Id` per request.** Because `InMemoryNonceStore` is process-local and ephemeral, multi-node or stateless verifiers MUST inject a shared `INonceStore` (a cross-node replay still passes a _different_ node, and a process restart clears the seen set). To restore the old behaviour, pass `NullNonceStore.Instance` explicitly to the `INonceStore` constructor overload.
- **API — `Capability.Proof`** changes type from `Proof?` to `ProofSet?`. Reads that treated it as a single proof need `.Primary` (or `.FirstDelegationProof()`); assigning a single `Proof` continues to compile via implicit conversion. The signing APIs still produce a single proof by default, so single-proof capabilities are unchanged on the wire (`proof` stays a bare object — no one-element-array wrap).
- **API — `Capability.Controller`** changes type from `string` to `ControllerSet`. Reads that previously treated it as a string need `.Primary` (the single/first controller) or `.Values`; assignments from a `string` or `string[]` continue to compile via implicit conversion. `ICapabilityService.CreateRootCapabilityAsync` / `DelegateCapabilityAsync` now take `ControllerSet` (string callers unaffected).
- **API + wire — revocation requires proof-of-possession** and has no unauthenticated path (Issue #60 + revocation hardening; detailed under **Fixed**). On `IVerificationService`, **both** string-keyed overloads — the original `RevokeCapabilityAsync(string, string)` and the interim authorizing `RevokeCapabilityAsync(Capability, string)` — are **removed** in favour of `RevokeCapabilityAsync(Capability, Invocation)`; `ISigningService` gains `SignRevocationAsync(...)`. The `ZcapLd.AspNetCore` POST `/zcaps/revocations/{id}` body changes from `{ revokerDid, … }` to `{ capability, signedRevocation }`; the endpoint now resolves `IVerificationService` (so the host must call `AddZcapServices()`, not `AddZcapRevocationSupport()` alone) and returns **403** for an unauthenticated/unauthorized request. The `RevokeCapabilityHttpRequest` contract is replaced by `SignedRevocationHttpRequest`. External `IVerificationService` implementors must update. In-policy under SemVer (already a major 3.0.0 bump).
- **API + wire — delegated DI invocation carries the full delegated zcap (Issue #51).** `Invocation.Capability` changes type from `string` to `InvocationCapability`, and `Proof.Capability` from `object?` to `InvocationCapability?`. Per W3C ZCAP-LD v0.3 (*Invoking a Delegated ZCAP*), a delegated capability-invocation DI proof MUST express the **full delegated zcap object** in `capability`, not just its id; a **root** invocation still references the root by id string. Verification is now **strict**: a delegated invocation that supplies only the delegated zcap id is rejected. Construct delegated invocations with `InvocationCapability.FromCapability(delegated)`; root invocations and revocation requests keep the id string (`Capability = root.Id` still compiles via the implicit `string` conversion). Reads of `invocation.Capability` / `proof.Capability` as a `string` need `.CapabilityId`. In-policy under SemVer (already a major 3.0.0 bump).

### Added

- `controller` may now be a single URI string **or** an array of URI strings on both root and delegated zcaps, per W3C ZCAP-LD v0.3 (Issue #47). Authorization succeeds when a proof's verification method matches **any** controller in the set.
- `ControllerSet` (in `ZcapLd.Core.Models`) — immutable value type modeling one or many controllers. Exposes `Values`, `Count`, `IsEmpty`, `IsArrayForm`, `Primary`, `Contains`, and `ContainsVerificationMethod`. Implicit conversions from `string` and `string[]` keep single-controller call sites ergonomic (`Controller = "did:..."` still compiles). Carries a `[JsonConverter]` that **preserves the on-wire shape** (a single controller stays a bare string; an array stays an array, even a single-element one) so JCS canonical bytes round-trip byte-stably for cross-language verifiers.
- `ControllerSetJsonConverter` (internal) — reads/writes both wire shapes and rejects malformed controller values (empty array, non-string entry, empty/whitespace string) with `JsonException`.
- `CapabilityService.DelegateCapabilityAsync` gains an optional `signerDid` parameter so any one of a multi-controller parent's controllers can sign the delegation (defaults to the parent's first controller; validated against the parent's controller set).
- `VerificationService` accepts an optional `IVerificationRelationshipResolver` (NetDid.Core 1.3.1) on its full constructor for document-based controller authorization (Issue #65). When omitted, it uses the supplied `IDidResolver` if that resolver also implements `IVerificationRelationshipResolver`, else a `did:key`-backed default. `ZcapLd.AspNetCore.AddZcapServices` picks up any registered `IVerificationRelationshipResolver` (e.g. a multi-method one wired by NetDid's `AddNetDid`).
- `DidKeyResolver` now also implements `IVerificationRelationshipResolver`, resolving a `did:key` controller's document and checking `capabilityInvocation` / `capabilityDelegation` — so the default verifier wiring is relationship-correct for `did:key` with no extra configuration. A custom `IDidResolver` can do the same to authorize its own DID method.
- A delegated zcap's `proof` may now be a single DI proof object **or** an array of proof objects, per W3C ZCAP-LD v0.3 (Issue #48). Verification succeeds when **at least one** proof is a valid, parent-authorized `capabilityDelegation` proof; non-delegation proofs are ignored and a delegation proof that fails to verify does not abort evaluation of the others.
- `ProofSet` (in `ZcapLd.Core.Models`) — immutable value type modeling one or many proofs. Exposes `Values`, `Count`, `IsArrayForm`, `Primary`, `DelegationProofs()`, `FirstDelegationProof()`, and `FirstDelegationProofWithChain()`. Implicit conversions from a single `Proof` or a `Proof[]` keep call sites ergonomic (`capability.Proof = signedProof;` and `capability.Proof = new[] { a, b };` both compile). Carries a `[JsonConverter]` that **preserves the on-wire shape** (a single proof stays a bare object; an array stays an array).
- `ProofSetJsonConverter` (internal) — reads/writes both wire shapes and rejects an empty proof array / non-object entry with `JsonException`. Each `Proof` round-trips through normal STJ, so `[JsonExtensionData]` (e.g. `domain`, `nonce`) is preserved.
- **Signed (proof-of-possession) revocation** — `IVerificationService.RevokeCapabilityAsync(Capability, Invocation)` and `ISigningService.SignRevocationAsync(capabilityId, signerDid, invocationTarget, reason?, metadata?)` (Issue #60 + revocation hardening). The revoker proves control by signing a `capabilityRevocation`-purpose request (`capabilityAction = "revoke"`) bound to the capability id; the verifier **authenticates** the signature against the key resolved from `proof.verificationMethod`, then **authorizes** that method against the capability's cryptographically verified delegation chain (the capability's own controller or any up-chain delegator). A signed `reason`/`metadata` rides in the proof's extension data and is recorded on the revocation. This is the **only** revocation entrypoint — see the removal note under **Breaking Changes**.
- `InvocationCapability` (in `ZcapLd.Core.Models`) — immutable union of the two spec-defined `capability` wire shapes: a root zcap **id string** or the **full embedded delegated zcap object** (Issue #51). Exposes `Id`, `EmbeddedCapability`, `IsRootReference`, `CapabilityId`, and `FromId` / `FromCapability`; an implicit conversion from `string` keeps root invocation / revocation call sites ergonomic. Carries a `[JsonConverter]` that **preserves the on-wire shape** (root → bare string, delegated → embedded object) so the embedded delegated zcap participates in the signed JCS payload and round-trips byte-stably for cross-language verifiers.
- `InvocationCapabilityJsonConverter` (internal) — reads/writes both wire shapes through the shared `ZcapJsonOptions.Default` (so the embedded zcap's caveats / proof / `capabilityChain` round-trip) and rejects malformed `capability` values (a non-string/object token, or an embedded object without an `id`) with `JsonException`.
- `ICapabilityService.CreateInvocation(capability, capabilityAction, invocationTarget?)` and `CreateRootInvocation(rootCapabilityId, capabilityAction, invocationTarget)` — ergonomic factories that build an **unsigned** `Invocation` with the spec-correct `capability` shape so callers don't choose between `InvocationCapability.FromId(...)` and `FromCapability(...)` themselves (Issue #51): `CreateInvocation` references a **root** capability by id and embeds a **delegated** capability's full zcap (auto-detected via `parentCapability`), defaulting the target to the capability's own `invocationTarget`; `CreateRootInvocation` references a root by id string when only the id is known. Sign the result with `ISigningService.SignInvocationAsync`. (Adds two members to the `ICapabilityService` interface — external implementors must add them; in-policy under the existing 3.0.0 major bump.)

### Changed

- See **Breaking Changes** above for the API/behaviour/wire breaks in this release (`Capability.Proof` → `ProofSet?`, `Capability.Controller` → `ControllerSet`, replay protection on by default, proof-of-possession revocation).
- Single-controller capabilities are unchanged on the wire — `controller` still serializes as a bare string, so existing signatures and pinned JCS bytes are preserved.
- New `CrossLanguageJcsInteropTests` pins lock the multi-controller shape: an array-form `controller` produces sign-time bytes byte-equal to what a peer verifier JCS-canonicalizes over the array-shaped wire body, and a single controller still emits a bare string (no one-element-array collapse).
- Dependency updates: `NetDid.Core` / `NetDid.Method.Key` 1.1.2 → **1.3.1** (1.3.1 adds the `IVerificationRelationshipResolver` primitive consumed for Issue #65), `Microsoft.SourceLink.GitHub` 10.0.201 → 10.0.300. Test/example tooling: `Microsoft.NET.Test.Sdk` 18.4.0 → 18.6.0, `FluentAssertions` 8.9.0 → 8.10.0, `coverlet.collector` 6.0.0 → 10.0.1, `Microsoft.Data.Sqlite` 10.0.6 → 10.0.8, `Microsoft.AspNetCore.Mvc.Testing` 10.0.0 → 10.0.8. All other packages were already on the latest stable.
- P-256 signing/verification now explicitly requests IEEE P1363 from NetDid's format-aware overloads (`EcdsaSignatureFormat.IeeeP1363`). NetDid 1.3.0 changed the _default_ of its legacy ECDSA `Sign`/`Verify` overloads from P1363 to ASN.1 DER; the W3C `ecdsa-2019` / `EcdsaSecp256r1Signature2019` wire format requires P1363 (fixed-width `r‖s`, 64 bytes for P-256), so `CryptoSuite` pins the format to keep `proofValue` interoperable with peer Data Integrity stacks. Ed25519 (the default suite) is unaffected. Regression-guarded by `CryptoSuiteTests.P256_Sign_ProducesIeeeP1363WireFormat_NotDer`.

### Fixed

- Delegated capability-invocation DI proofs now carry the **full delegated zcap object** in `capability`, per W3C CCG ZCAP-LD v0.3 — *Invoking a Delegated ZCAP*: "When invoking using a DI proof, the `capability` property must express the full delegated zcap" (Issue #51). The invocation `capability` was modeled as a plain id `string` and verified by string-equality against the capability id, which supported only the root-style id reference and could not express the delegated DI shape the draft requires — so the verifier could not receive the delegated authority inline, and a strict peer implementation's delegated invocation could not be represented. `Invocation.Capability` / `Proof.Capability` now use `InvocationCapability` (see **Added**); the embedded delegated zcap participates in the signed canonical payload, and `VerifyInvocationAsync` strictly distinguishes the two shapes — a **root** invocation must reference the root by id, a **delegated** invocation must embed the full zcap whose id matches the verified capability (a bare-id delegated invocation is rejected). Signed revocation requests are unaffected (`capabilityRevocation` references the capability by id). Regression-guarded by the new `DelegatedInvocationComplianceTests` (model round-trips for both shapes + malformed rejection; signing puts the correct shape in `proof.capability`; verification accepts root-by-id and delegated-embedded, rejects delegated-by-id-only / embedded-id mismatch / an embedded zcap with an invalid delegation proof; pinned JCS canonical bytes for the embedded shape; sign-time bytes equal wire-time bytes).
- `VerificationService.VerifyCapabilityProofAsync` now enforces attenuation and child expiry against the embedded parent, and its contract is documented as a single-link soundness check rather than a full authorization gate (Issue #69). It verified the delegation signature and parent-controller authorization but did not check that the child stays within the parent (attenuation) or that the child has not expired, so a re-signed child that **expands** authority beyond its parent was accepted by the single-proof method while `VerifyCapabilityChainAsync` correctly rejected it. The shared single-delegation-proof verifier now rejects an over-broad or expired child after the proof signature verifies and before accepting the link. Regression-guarded by `VerificationServiceTests.VerifyCapabilityProof_OverbroadChild_ShouldReturnFalse`.
- Verification now binds the resolved key's type to the proof-selected crypto suite (Issue #68). The suite is chosen from the (attacker-controlled) `proof.Type`, but `resolvedKey.KeyType` was never compared against `suite.KeyType`. No forgery was enabled today (the proof type is part of the signed payload, and key importers reject cross-curve bytes), but the missing check was a defense-in-depth gap relying on downstream invariants. Both verify paths now reject early when `suite.KeyType != resolvedKey.KeyType` (via a shared `KeyTypeMatches` helper — one source of truth so the two paths can't drift), self-documenting the invariant and future-proofing against custom resolvers/suites; the resolver↔suite vocabulary contract this introduces is documented on `ICryptoSuite.KeyType` and `ResolvedKey.KeyType`. Regression-guarded by `VerificationServiceTests.VerifyInvocation_WhenResolvedKeyTypeMismatchesSuite_ReturnsFalse` (invocation path) and `…VerifyCapabilityProof_WhenResolvedKeyTypeMismatchesSuite_ReturnsFalse` (delegation path). Each test isolates the guard: its resolver returns the correct key bytes but a mismatched key type and forwards controller authorization to the honest resolver, so the binding is the only differing factor — verified failing when the guard is removed (the prior single test passed regardless, because its resolver did not forward authorization and the verifier failed on an unrelated gate).
- `DidKeyResolver.ResolvePublicKeyAsync` now honours the verification-method `#fragment` instead of always returning the first method (Issue #67). It stripped the fragment and returned `VerificationMethod.FirstOrDefault()`, so for an Ed25519 `did:key` — which resolves to **two** methods (the Ed25519 signing key at index 0 and a derived X25519 key-agreement key at index 1) — resolving the X25519 fragment returned the Ed25519 key, a latent contract violation that worked only by ordering coincidence. When the input carries a `#fragment`, the resolver now selects the method whose `Id` equals the full URI and throws `CapabilityValidationException` if none matches, rather than substituting the first; a bare DID still resolves to the primary method. An empty (trailing-`#`) or malformed multi-`#` fragment likewise fails closed. Regression-guarded by `NetDidIntegrationTests.ResolvePublicKeyAsync_X25519KeyAgreementFragment_ReturnsX25519KeyNotEd25519`, `…_UnknownFragment_Throws`, `…_EmptyFragment_Throws`, and `…_MultipleHashFragment_Throws`.
- `ICapabilityService.CreateRootCapabilityAsync` no longer forces callers to pass an `allowedActions` array the implementation discards (Issue #66). The interface declared `string[] allowedActions` (required) while the implementation declared `string[]? allowedActions = null` and never reads it for roots (roots carry no `allowedAction` per spec), so a consumer bound to the interface had to pass a throwaway value to express "no enumerated actions". The interface signature now matches the implementation (`string[]? allowedActions = null`) and documents that the parameter is ignored for roots. Non-breaking: callers passing an array still compile. (Companion `expires`/`caveats` documentation is Issue #72.)
- **Controller authorization now resolves the controller's DID document (Issue #65, M8) — both halves closed.** The array-`controller` half (a spec-permitted array threw `JsonException` on deserialize; authorization was string-equality only) was resolved by the `ControllerSet` work (Issue #47). This release closes the remaining, architectural half: `VerificationService` no longer authorizes a proof's verification method by DID-string match. It now delegates to an `IVerificationRelationshipResolver` (shipped upstream in **NetDid.Core 1.3.1**, net-did#71) that resolves the **controller's** DID document and confirms the verification method appears in the correct verification relationship — `capabilityInvocation` for invocations, `capabilityDelegation` for delegations. **All three control-authorization surfaces** are migrated: invocation, delegation, **and revocation** (`IsRevokerAuthorizedAsync` walks the cryptographically verified chain checking each link's `capabilityDelegation` relationship — the authority to delegate is the authority to revoke — replacing the prior string match and its `TODO`). This honors controllers whose authorized key lives under a **different** DID (cross-DID references) and the **per-purpose key separation** DID Core defines (a key authorized only for `capabilityInvocation` can no longer mint delegations, nor revoke) — neither of which the prior string match could express. The resolver is selected in order: an explicitly supplied one, else the configured `IDidResolver` when it also implements `IVerificationRelationshipResolver` (so `DidKeyResolver` self-provides for `did:key`), else a `did:key`-backed default. Decisions are fail-closed and severity-aware (Issue #64): an expected denial logs at Debug, and a controller that cannot be resolved (`AuthorizationDecision.ControllerNotResolvable`) is itself severity-classified — a malformed/unknown/unsupported controller DID is **attacker-drivable** (the controller comes from the presented capability) so it logs at **Debug** to avoid Warning-channel flooding, while an unexpected/transient resolution error logs at **Warning**; either way it is treated as not authorized. `did:key` is unchanged in practice (the key is the DID and is listed under every relationship). No forgery is enabled — the signature is always verified independently (and on the delegation-link path the signature is now checked _before_ any authorization resolver I/O). Guarded by `ControllerDocumentAuthorizationTests` (policy mapping/OR-semantics/fail-closed via a recording resolver; the built-in `did:key` default resolver exercised end-to-end; attacker-drivable→Debug and transient→Warning logging; plus end-to-end Break A — controller DID ≠ VM DID — and Break B — relationship discrimination — over the real `DefaultVerificationRelationshipResolver`) and the unchanged `SignedRevoke_*` revocation tests.
- `VerificationService` no longer silently discards the cause when it fails closed (Issue #64). All three public verify methods wrapped their body in a bare `catch { return false; }`, so a transient or configuration fault (a missing canonicalizer registration, an unsupported proof type, a DID-resolution network error) was reported identically to a tampered capability, with no logging anywhere in `ZcapLd.Core` — a misconfiguration silently denied **all** valid capabilities. The verifier now accepts an optional `ILogger<VerificationService>` (defaults to `NullLogger`) and every fail-closed `catch` now `catch (Exception ex)` and logs the cause before returning false (fail-closed is preserved). Logging is **severity-aware** (PR #84 review): expected, attacker-drivable validation/parse failures — a malformed or unbuildable capability, an unsupported proof type, an unresolvable/malformed `verificationMethod`, a malformed `proofValue` — log at **Debug**, so a hostile client posting bad wire data cannot flood the operator's Warning channel and mask a real misconfiguration; **Warning** is reserved for genuinely unexpected faults an operator must act on (a missing canonicalizer/crypto-suite registration, a transient DID-resolution/infrastructure error, or any non-library exception). This covers the three public verify methods **and** the revocation path: `IsRevokerAuthorizedAsync` now catches **every** fault from the chain walk (not just `CapabilityValidationException`), keeping the authorization decision local and failing closed as "not authorized" on any transient build/DID-resolution error (PR #84 review). `ZcapLd.AspNetCore`'s `AddZcapServices` wires the container's logger. Adds a lightweight `Microsoft.Extensions.Logging.Abstractions` dependency to `ZcapLd.Core`. (A structured result/typed-exception channel — distinguishing "invalid" from "couldn't check" — remains tracked as #70.)
- `VerificationService.VerifyCapabilityProofAsync` now honours **ancestor** revocation at **every depth**, not just the leaf and its immediate parent (Issue #63). The original fix checked the leaf (`capability.Id`) plus the immediate parent embedded in `proof.capabilityChain[^1]`, but stopped there — so a capability whose **root or an intermediate** ancestor had been revoked still passed the single-proof check while `VerifyCapabilityChainAsync` (which checks revocation for every link) correctly rejected it. A consumer treating the single-proof method as "is this still valid?" could therefore accept a capability with a revoked ancestor. Revocation is now centralized at the two entry points: the standalone path sweeps **every** ancestor id carried as an id string in the delegation proof's `capabilityChain` (root + all intermediates + immediate parent, de-duplicated), and the chain walk continues to revocation-check every resolved link — so both paths reject a revoked ancestor at any depth. The now-redundant per-proof depth-1 check was removed from the shared single-delegation-proof verifier, which is now purely signature + parent authorization. Regression-guarded by `VerificationServiceTests.VerifyCapabilityProof_WithRevokedImmediateParent_/WithRevokedRootAncestor_/WithRevokedIntermediateAncestor_ShouldReturnFalse`.
- Hardening shipped with the Issue #63 follow-up: (a) `RevokeCapabilityAsync` consumes the replay nonce **only after** the durable revocation write succeeds — a throwing/failed store write no longer burns the request id, so a legitimate retry with the same signed request is not mistaken for a replay (revocation is idempotent, so a replayed-after-eviction request harmlessly re-applies before the nonce check rejects it); (b) `CapabilityService.BuildCapabilityChain` de-duplicates ancestor ids so a directly-root-delegated parent no longer emits a repeated id (e.g. `[rootId, rootId, …]`); (c) `VerifyInvocationAsync` and the revocation authorization path build the delegation chain once and reuse it (a new internal `VerifyBuiltChainAsync`) instead of rebuilding it; (d) the `RevokeCapabilityAsync` XML doc now states that authorization requires a fully valid chain, so an expired capability or one with a revoked ancestor — already inert — cannot be explicitly re-revoked.
- Replay protection is now ON by default in the convenience `VerificationService` constructors (Issue #62). The 2-, 3-, and 4-argument constructors previously funnelled to `NullNonceStore.Instance`, whose `TryMarkAsUsedAsync` always reports "not seen", so the documented `new VerificationService(resolver, caveatProcessor)` path (the README Quick Start) gave **zero** replay protection — a captured valid invocation could be replayed indefinitely. The convenience constructors now default to `new InMemoryNonceStore()`; `NullNonceStore` is reachable only by deliberately passing it to the explicit `INonceStore` constructor. `InMemoryNonceStore` is process-local — supply a shared store for multi-node verifiers (documented on the constructor and in the README). Regression-guarded by `VerificationServiceReplayTests.VerifyInvocation_TwoArgConstructor_RejectsReplayByDefault`.
- Delegating a capability with an expiration more than three months out no longer throws at create time (Issue #61). The W3C ZCAP-LD 3-month expiration ceiling is a **verifier-side SHOULD measured at invocation time**, not a create-time MUST — but `CapabilityService.DelegateCapabilityAsync` enforced it as an unconditional hard `throw` inside `ValidateAttenuation`, blocking even the construction of a legitimately long-lived delegation the parent permits, with no opt-out (the limit was a non-configurable `const`). The create-time throw (and the now-unused `MaxExpirationMonths` const) are removed; attenuation (child ≤ parent expiry) is still enforced. The ceiling moves to the verify path behind a policy flag (Issue #73). The misnamed `SHOULD-04` compliance test (named a _verifier_ test but driving `DelegateCapabilityAsync`) now asserts that long-lived delegation succeeds at create time.
- Closed the **unauthenticated revocation hole** — revocation now requires proof-of-possession (Issue #60 + revocation hardening). A bare `revokerDid` **string** was previously accepted as both attribution _and_ authority: the original `RevokeCapabilityAsync(string, string)` stored a revocation with no checks at all, and even the interim authorizing `RevokeCapabilityAsync(Capability, string)` only string-matched the asserted DID against the chain's controllers — but controller DIDs are **public** (embedded in the chain), so anyone who could read a capability could revoke it by asserting a controller's DID. Worse, the `ZcapLd.AspNetCore` POST endpoint called `IRevocationService.RevokeAsync` **directly** from the request body, so any caller could revoke anything (denial-of-capability). Revocation is now a **cryptographically signed** request: `SignRevocationAsync` mints a `capabilityRevocation`-purpose, `revoke`-action invocation bound to the capability, and `RevokeCapabilityAsync(Capability, Invocation)` verifies the signature (**authentication** — possession of the key) before **authorizing** the verified verification method against the cryptographically verified delegation chain. It is fail-closed, records the authenticated revoker plus any signed `reason`/`metadata`, and deliberately does **not** evaluate caveats (revocation is a control-plane authority action). The HTTP endpoint requires the signed request and returns 403 otherwise. The distinct `capabilityRevocation` proof purpose makes a revocation's signed bytes disjoint from any normal invocation (no confused-deputy). Regression-guarded by the `SignedRevoke_*` unit tests and the new `ZcapLd.AspNetCore.Tests` HTTP integration tests (impersonation → 403, unauthorized-but-validly-signed → false, tampered signed-reason → false, typed-caveat round-trip → 200).
- `CapabilityService.ValidateCapabilityAsync` no longer rejects capabilities whose `allowedAction` contains values other than `read`/`write` (Issue #59). ZCAP-LD treats actions as an application-defined vocabulary — `read`/`write` are illustrative examples, not a closed allow-list — so the previous hard-coded check declared spec-conformant capabilities invalid, including ones this library mints (e.g. `delete`, `admin`, `share`) and cryptographically verifies via `VerifyCapabilityChainAsync`. The closed allow-list block is removed; the real constraints remain enforced elsewhere (attenuation child ⊆ parent at delegation/chain verification, and membership in `allowedAction` at invocation time). A deployment that genuinely wants vocabulary restriction should layer it as an injected policy. The `SHOULD-05` compliance test now asserts a custom action validates.
- `VerificationService.VerifyInvocationAsync` no longer rejects every invocation received as JSON (Issue #58). `Proof.Capability` is typed `object?`; after `System.Text.Json` deserialization it is a `JsonElement` (not a CLR `string`), so the proof/invocation consistency check read it with an `as string` cast that always yielded `null`, failing the check and rejecting all wire invocations — the canonical resource-server flow (receive JSON → deserialize → verify). It only ever passed in-process, where `SigningService` assigns a CLR `string`. The check now normalizes `Proof.Capability` via the existing `TryExtractStringValue` helper (handles both boxed `string` and `JsonElement` of kind `String`). Regression-guarded by `VerificationServiceTests.VerifyInvocation_AfterJsonRoundTrip_ShouldReturnTrue`.
- `CapabilityService.ValidateCapabilityAsync` now rejects root zcaps that carry any field outside the permitted set (Issue #49). Per W3C CCG ZCAP-LD v0.3, a root zcap contains exactly `@context`, `id`, `controller`, and `invocationTarget`, and "MUST NOT have any other fields." Root validation previously rejected only `proof`, `expires`, and `parentCapability`, so an externally-supplied root carrying `allowedAction`, `caveat`, or unknown extension fields (captured in `AdditionalProperties` via `[JsonExtensionData]`) passed validation. The root branch now also rejects non-null `AllowedAction`/`Caveat` and a non-empty `AdditionalProperties`; these must be absent (not empty), matching the strict shape `CreateRootCapabilityAsync` already emits. Delegated zcaps, which legitimately carry these fields, are unaffected.
- Concrete `Caveat` subclasses no longer emit duplicate `"Type"` / `"type"` keys on the wire (Issue #45). STJ on .NET 10 doesn't auto-inherit `[JsonPropertyName("type")]` from the abstract base override declaration; without an explicit attribute on the override, the runtime catalogues the override as a separate `JsonPropertyInfo` and emits the CLR name `"Type"` alongside the inherited `"type"`. Both keys landed on the wire, JCS preserved them both, and signature verification failed against any other Data Integrity implementation. Fix: re-apply `[JsonPropertyName("type")]` on `ExpirationCaveat`, `UsageCountCaveat`, and `ValidWhileTrueCaveat` overrides. Fourth and final layer of the cross-stack canonicalization contract from #34 / #36 / #37 / #39.

## [2.1.0] - Released

### Fixed

- Root capabilities and invocation proofs no longer emit empty/null optional fields on the wire (Issue #37). `allowedAction`, `caveat`, `parentCapability`, `expires`, `proof` (on root capabilities) and `capabilityChain` (on invocation proofs) are omitted when unset. Strict cross-language parsers (`zcap-py` and others) reject `"allowedAction": []` / `"capabilityChain": []` / `null` on optional fields when present, so emit-as-empty broke cross-stack interop. Companion to PR #34's flat-shape fix.
- `Caveat[]` polymorphic serialization preserves derived-class fields across the signing boundary (Issue #39). Previously, STJ used the static array element type for `Capability.Caveat`, silently dropping derived fields like `Expires`, `Uri`, or third-party budget counters at sign time. Sign-time JCS now produces byte-identical bytes to whatever a cross-language verifier (`zcap-py` and friends) computes over the wire body re-emitted via the runtime concrete type.

### Added

- `CaveatTypeRegistry` (in `ZcapLd.Core.Models`) with a `Default` singleton pre-populated with the in-library caveat types. Third-party caveat libraries register their derived types via `CaveatTypeRegistry.Default.Register<T>(discriminator)` so the polymorphic JSON converter can dispatch deserialization across packages.
- `ZcapJsonOptions.Default` (in `ZcapLd.Core.Cryptography`) — single source of truth for the `JsonSerializerOptions` shared by sign-time canonicalization and verifier-time chain deserialization (RFC 8785-compatible escaping, `WhenWritingNull`, the caveat converter).
- `AddZcapCaveatType<TCaveat>(string discriminator)` ASP.NET DI extension on `IServiceCollection`, mirroring the `AddZcapCryptoSuite<T>()` shape.
- `CaveatJsonConverter` — internal `JsonConverter<Caveat>` wired into `ZcapJsonOptions.Default`. `Write` dispatches to the runtime concrete type so derived fields are emitted; `Read` resolves the `type` discriminator against `CaveatTypeRegistry.Default` and deserializes via reflection, throwing `JsonException` with a registry-friendly hint when the discriminator is unknown.

### Changed

- **BREAKING (wire format)**: `Capability.AllowedAction` and `Capability.Caveat` are now nullable (`string[]?` / `Caveat[]?`). Previously defaulted to `Array.Empty<>()`, producing `[]` on the wire. JCS canonical bytes change for any root capability, so signatures over the old shape no longer verify.
- **BREAKING (wire format)**: `Proof.CapabilityChain` is now nullable (`object[]?`) and omitted on invocation proofs, which spec-correctly carry no chain.
- **BREAKING (wire format)**: capabilities with non-empty caveats now sign over the full caveat shape (including derived-class fields), not the discriminator-only stub. Signatures over the old shape no longer verify.
- **BREAKING (semantics)**: `UsageCountCaveat.CurrentUses` is now `[JsonIgnore]`. It's runtime state, not the signed policy — including it in the canonical bytes would invalidate the signature on every increment. Only `MaxUses` (the policy) is part of the wire body now.
- All five optional `Capability` fields (`AllowedAction`, `Expires`, `ParentCapability`, `Caveat`, `Proof`), `Invocation.Proof`, and `Proof.CapabilityChain` carry `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`.
- `CapabilityService.CreateRootCapabilityAsync` no longer assigns `Array.Empty<>()` / `null` to optional fields — they stay unset.
- `CapabilityService.InheritCaveats` returns `Caveat[]?` and yields `null` when neither parent nor child supplies caveats, so delegations with no caveats also stay clean on the wire.
- `SigningService.SignInvocationAsync` no longer sets `CapabilityChain = Array.Empty<object>()` on invocation proofs.
- `ProofSigningPayloadBuilder.ModelSerializerOptions` now resolves to `ZcapJsonOptions.Default`; `VerificationService` chain deserialization uses the same options. Sign-time and verifier-time JSON paths share one configuration.
- New `CrossLanguageJcsInteropTests` fixtures pin the new wire shape: root capability emits only `{@context, controller, id, invocationTarget}`; invocation proofs no longer contain `"capabilityChain"`; capabilities with `ExpirationCaveat` / `ValidWhileTrueCaveat` produce sign-time bytes byte-equal to whatever a cross-language verifier JCS-canonicalizes over the wire body.

## [1.2.0] - Released

### Added

- RDFC-1.0 (W3C RDF Dataset Canonicalization) support via dotNetRdf.Core v3.5.1 (Issue #29)
- `IDocumentCanonicalizer` interface for pluggable canonicalization methods
- `JcsDocumentCanonicalizer` (RFC 8785 JSON Canonicalization Scheme)
- `RdfcDocumentCanonicalizer` (RDFC-1.0 via dotNetRdf: JSON-LD → N-Quads)
- `IDocumentCanonicalizerProvider` / `DocumentCanonicalizerProvider` registry
- `ICryptoSuite.CanonicalizationMethod` default interface method (returns `"JCS"` for backward compatibility)
- `AddZcapRdfcCanonicalization()` ASP.NET Core DI extension to enable RDFC-1.0
- 24 new tests for canonicalization abstractions and RDFC-1.0 integration

### Changed

- `ProofSigningPayloadBuilder` supports suite-specific canonicalization: JCS (combined object) or RDFC-1.0 (separate document + proof options, SHA-256 hash concatenation per W3C Data Integrity spec)
- `SigningService` and `VerificationService` accept `IDocumentCanonicalizerProvider` to resolve per-suite canonicalizer
- `SignatureVerifier` accepts optional `IDocumentCanonicalizer` parameter
- `MultibaseCodec.CanonicalizeDocument()` removed (replaced by `IDocumentCanonicalizer`)

## [1.1.0] - Released

### Changed

- Replaced `Ed25519CryptoSuite`, `P256CryptoSuite`, `Ed25519Signer`, and `EcPointCompression` with single parameterized `CryptoSuite` class delegating to NetDid's `DefaultCryptoProvider` (Issue #23)
- `CryptoSuite.Ed25519()` and `CryptoSuite.P256()` static factory methods replace individual suite classes

### Removed

- `Ed25519Signer` static class (replaced by `DefaultCryptoProvider`)
- `EcPointCompression` internal class (replaced by NetDid's `DecompressEcPoint`)
- `Ed25519CryptoSuite` class (replaced by `CryptoSuite.Ed25519()`)
- `P256CryptoSuite` class (replaced by `CryptoSuite.P256()`)
- Direct `NSec.Cryptography` dependency (now transitive via NetDid.Core)

## [1.0.0] - Released

### Added

- DID resolution via [NetDid](https://www.nuget.org/packages/NetDid.Core) packages (`NetDid.Core`, `NetDid.Method.Key`)
- `DidKeyResolver` as adapter over NetDid's `DidKeyMethod`
- `MultibaseCodec` delegates to `NetCid.Multibase` (replaces `SimpleBase`)
- 12 new NetDid integration tests

### Removed

- `SimpleBase` dependency (replaced by NetCid transitive from NetDid)
- `ICryptoSuite.MulticodecPrefix` property (multicodec handled by NetDid)
- `ICryptoSuite.PublicKeyLength` property (unused in production)
- `ICryptoSuiteProvider.GetByMulticodecPrefix()` method (multicodec handled by NetDid)

### Changed

- `DidKeyResolver` no longer takes `ICryptoSuiteProvider` constructor parameter (**breaking**)
- `CryptoSuiteProvider` simplified: replaced `List<ICryptoSuite>` + lock with `ConcurrentDictionary` for key type lookup

## [0.3.3] - 2026-03-03

### Changed

- `InvocationContext` property injection (Issue #15)
- Updated GitHub Actions checkout to v6

## [0.3.2] - 2026-02-28

### Fixed

- `Context` property JSON deserialization (`object` typed properties become `JsonElement` after ASP.NET round-trip)

## [0.3.1] - 2026-02-28

### Fixed

- `Proof.CapabilityChain` JSON deserialization causing signature verification failures over HTTP (null fields in `JsonElement` bypass `WhenWritingNull` serialization option)

## [0.3.0] - 2026-02-28

### Changed

- Enhanced revocation processing and validation

## [0.2.1] - 2026-02-26

### Fixed

- Patch fixes

## [0.2.0] - 2026-02-24

### Changed

- Version stabilization

## [0.1.1] - 2026-02-23

### Added

- Revocation framework: `IRevocationService`, `IRevocationStore`, `InMemoryRevocationStore`
- ASP.NET revocation endpoints (`AddZcapRevocationSupport()`, `MapZcapRevocationEndpoints()`)
- ValidWhileTrue caveat support with `IValidWhileTrueHandler` interface
- `HttpValidWhileTrueHandler` in `ZcapLd.AspNetCore`

## [0.1.0] - 2026-02-20

### Added

- Initial release
- Capability creation, delegation, and chain verification
- Invocation signing and verification
- Caveat processing (expiration, usage count)
- Ed25519 and P-256 crypto suites via `ICryptoSuite` / `ICryptoSuiteProvider`
- Replay protection via `INonceStore` (`InMemoryNonceStore`, `NullNonceStore`)
- DID resolution via `DidKeyResolver` with `did:key` support
- ASP.NET Core integration package (`ZcapLd.AspNetCore`)
- 245 tests, security compliance audit
