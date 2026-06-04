# #65 (downstream) — controller-document authorization via net-did 1.3.1

Branch: `65-controller-doc-authorization` (off `65-controller-array-regression` / PR #85).
Upstream: net-did#71 shipped in 1.3.1 (`IVerificationRelationshipResolver`).

## Goal
Resolve the remaining, architectural part of #65: make `IsControllerAuthorized`
document-aware (relationship-correct) for non-`did:key` controllers, while keeping
`did:key` (string-match) working and fully backward compatible.

## Design
- Consume net-did 1.3.1's `IVerificationRelationshipResolver` (tri-state
  `AuthorizationDecision`: Authorized / NotAuthorized / ControllerNotResolvable).
- Inject it as an **optional** dependency of `VerificationService` (null = current
  string-match behavior). Consistent with `DidKeyResolver(DidKeyMethod)` already taking a
  NetDid type publicly.
- ZCAP policy stays in zcap: proof-purpose → relationship (invocation→CapabilityInvocation,
  delegation→CapabilityDelegation), OR-semantics over the ControllerSet, fail-closed +
  #64 severity-aware logging.

## Tasks
- [x] Bump NetDid.Core / NetDid.Method.Key 1.3.0 → 1.3.1; restore; baseline build green.
- [ ] `VerificationService`: add optional `IVerificationRelationshipResolver` (field + full ctor param).
- [ ] `IsControllerAuthorized` → async, relationship-aware, tri-state + logging, string-match fallback.
- [ ] Update 2 call sites (delegation → CapabilityDelegation; invocation → CapabilityInvocation).
- [ ] Replace the "documented limitation" `<remarks>` with the implemented behavior.
- [ ] AspNetCore `AddZcapServices`: pick up a registered `IVerificationRelationshipResolver` (opt-in).
- [ ] Tests: policy (fake resolver) + end-to-end (real DefaultVerificationRelationshipResolver
      + fake NetDid IDidResolver) covering Break A (controller≠VM-DID), Break B (relationship
      discrimination), ControllerNotResolvable → fail closed, multi-controller OR, did:key regression.
- [ ] Docs: CHANGELOG (#65 → Fixed + dep bump), ARCHITECTURE.md, spec checklist line 794.
- [ ] Full `dotnet test` green.

## Review (completed)

Implemented per the approved plan (`~/.claude/plans/structured-squishing-crayon.md`), with one
mid-implementation design correction.

- **Deps:** `NetDid.Core`/`NetDid.Method.Key` → 1.3.1; `Microsoft.AspNetCore.Mvc.Testing` → 10.0.8.
  All other packages already latest stable (`dotnet list package --outdated`).
- **Authorization:** `VerificationService.IsControllerAuthorizedAsync` resolves the controller's DID
  document via `IVerificationRelationshipResolver`, mapping invocation→`CapabilityInvocation` and
  delegation→`CapabilityDelegation`, OR across the `ControllerSet`, fail-closed + #64 severity-aware logging.
- **Design correction (not in original plan):** a single `did:key`-`DidKeyMethod` default resolver
  fails-closed on the suite's synthetic `did:key:z6Mk…` fixtures (real `DidKeyMethod` can't decode them).
  Resolved by resolver self-detection: `relationshipResolver ?? (didResolver as IVerificationRelationshipResolver)
  ?? default`. `DidKeyResolver` self-provides the real document path; both `InMemoryDidProvider`s
  (tests + examples) implement the interface with did:key-equivalent semantics. No per-test churn.
- **Tests:** `ControllerDocumentAuthorizationTests` (7) — policy via a recording resolver + end-to-end
  Break A/B over the real `DefaultVerificationRelationshipResolver`.
- **Verification:** `dotnet test ZcapLd.sln` → **397 passed, 0 failed** (391 Core + 6 AspNetCore);
  `examples/ZcapLd.Examples` runtime output matches all expected outcomes (multi-controller, chains,
  caveats, RDFC, ValidWhileTrue).
- **Docs:** CHANGELOG (#65 → Fixed + Added entries + dep note), ARCHITECTURE (resolver/verification),
  spec checklist line 794 ticked, lessons captured.

### Follow-up (not in scope, optional)
- The downstream consumer story for non-`did:key` (e.g. did:web) relies on the consumer wiring a
  method-appropriate `IVerificationRelationshipResolver` (or `AddNetDid`). A worked did:web example
  could be added later.
