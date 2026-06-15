# Agent & Contributor Instructions

This file provides instructions for AI agents and human contributors working in this codebase.

## Project Overview

W3C's ZCAP-LD (Authorization Capabilities for Linked Data) specification defines an object-capability model where authority is granted by possessing a signed "capability" document, rather than by identity or ACLs. A ZCAP-LD capability is a JSON-LD object containing fields like id, invocationTarget, and a cryptographic proof. It can delegate authority by linking to a parent capability (parentCapability) and attaching restrictions called caveats. This model "shifts the burden of identification…to directly work with individuals' actual capabilities" – in other words, "if you have a valid 'capability', you have the authorization" (akin to holding a car key). Our goal is to build a .NET 10 library (for use in-process or via gRPC) that can create, sign, delegate, invoke, and verify ZCAP-LD capabilities for digital wallet agents. Below are the key requirements and design points.

## Key Requirements and Design

- Data Model (Capabilities): Implement C# classes to represent ZCAP-LD capabilities. A root capability (initial authority) and a delegated capability (child) share common fields. Each capability JSON-LD object should include properties such as id (a URI, e.g. urn:uuid:…), optional parentCapability (URI of parent ZCAP), controller (the DID of the authority issuing it), invocationTarget (the target resource URI), allowedAction (e.g. "read", "write"), optional expires (a timestamp), optional caveat list (restrictions), and a nested proof object. For example, the spec shows a delegated capability JSON with those fields and an @context (e.g. https://w3id.org/zcap/v1). In C#, use properties and JSON serialization attributes ([JsonProperty] etc.) to match these names.

- Linked Data Proofs (Signing): Capabilities must be cryptographically signed using a linked-data proof. Implement code to generate a proof in the style of ZCAP-LD: include fields like type (signature type, e.g. "Ed25519Signature2018" or "Ed25519Signature2020"), created (timestamp), proofPurpose ("capabilityDelegation" when delegating), verificationMethod (the DID key URI), a capabilityChain array, and a signature value (e.g. JWS or base58 string). For a delegation proof, capabilityChain should list the root capability ID and intermediate ancestors (parent fully embedded as object). Use .NET crypto libraries (e.g. System.Security.Cryptography.Ed25519 or RSA) or JSON-LD libraries to canonicalize the capability JSON and produce the signature. The proof format must match the spec examples (e.g. Ed25519Signature2020 with proofValue).

- Capability Delegation (Chains): Support chaining of capabilities. When delegating, build a chain where each delegated capability includes a proof signed by its parent’s controller. The spec requires that the delegation chain is an ordered array: the first element is the root capability’s ID, intermediate ancestors by ID, and the parent capability is embedded and signed. In practice, your code should assemble this chain and include it in the proof. On verification, check each link: ensure each child’s proof is valid using the parent’s public key, and that no chain is too long (limit e.g. 10) to prevent attacks. Store or pass the full chain in invocations so the verifier need not fetch external data.

- Invocation and Verification: Implement invocation processing: when an AI agent invokes an action, it will present the capability and a proof with proofPurpose: "capabilityInvocation". The invocation JSON must include the root capability ID (capability) and requested action (capabilityAction). Verify that the proof’s signature key matches the controller of the root capability and that the requested action is among the capability’s allowedAction. Also check the invocationTarget URI matches (or is a valid prefix of) the capability’s target. According to the spec, the key used to sign must be authorized by the root zcap controller. If valid, allow the action; otherwise deny.

- Caveat Support: Implement handling of caveats (restrictions). The spec notes that each capability may add restrictions via a caveat property, and that child capabilities inherit all caveats of their parents. For example, one could add a time-based caveat (e.g. ValidUntil) or an action-limiting caveat. At minimum, design a Caveat class or interface so common types (timestamp checks, count limits, etc.) can be enforced at invocation time. When verifying a delegated capability, ensure that all caveats from the root through to the leaf are evaluated and honored. (For a minimal implementation, you can start by supporting a simple expiration or true/false caveat and expand later.)

- Digital Identity Integration: In practice, capabilities will be issued by entities (e.g. users or services) with DIDs and keypairs. Your code should plan for implementors to provide their own DID managing library to fetch a DID document, extract the public key (verificationMethod) for signature verification, or to sign data with a private key. For example, you may call a crypto library to get the public key for a DID used in controller or verificationMethod. In code, this may be abstracted as functions like ResolvePublicKey(did) and SignWithPrivateKey(data, did).

- Architecture (In-Process vs gRPC): Since signing uses private keys, implementing this logic in-process (within the same application or service) is simplest. However, you may optionally expose the functionality over gRPC or HTTP for remote agents. For a library, ensure that signing and verification functions are thread-safe and do not persist private keys beyond needed scope. If exposing via gRPC, design service methods like CreateCapability(), DelegateCapability(), VerifyInvocation().

- WASM/Interop Support: (Optional) .NET 10 supports building WebAssembly via WASI. The spec use-case hints at cross-environment usage (e.g. Python or JS agents). Consider structuring code for AOT compilation: avoid heavy native dependencies, and test with .NET 10's wasi-experimental workload. This would allow consuming the library as a Wasm module in other languages. For now, focus on core functionality; WASM/Trinity integration can be added later.

## Project Structure

```
zcap-dotnet/
├── ZcapLd.sln
├── src/
│   ├── ZcapLd.Core/                    # Core library (NuGet package)
│   │   ├── Cryptography/               # ICryptoSuite, CryptoSuiteProvider, CryptoSuite,
│   │   │                               #   IDocumentCanonicalizer, JcsDocumentCanonicalizer,
│   │   │                               #   RdfcDocumentCanonicalizer, DocumentCanonicalizerProvider,
│   │   │                               #   MultibaseCodec, JsonCanonicalizer, LegacyProofCrypto,
│   │   │                               #   RdfcContextDocumentLoader, ProofSigningPayloadBuilder
│   │   ├── Models/                     # Capability, Proof, Invocation, Caveat, ValidWhileTrueCaveat,
│   │   │                               #   InvocationContext, ResolvedKey, SignatureResult,
│   │   │                               #   RevocationRecord, RevocationRequest
│   │   ├── Services/                   # ICapabilityService, ISigningService, IVerificationService,
│   │   │                               #   ICaveatProcessor, IDidResolver, IDidSigner, IRevocationService,
│   │   │                               #   IRevocationStore, INonceStore, IValidWhileTrueHandler,
│   │   │                               #   IRootCapabilityResolver (+ InMemoryRootCapabilityResolver) + implementations
│   │   └── Exceptions/                 # ZcapLdExceptions
│   └── ZcapLd.AspNetCore/             # ASP.NET adapter (NuGet package)
│       ├── DependencyInjection/        # AddZcapServices(), AddZcapDidSigner<T>(), AddZcapRevocationSupport(),
│       │                               #   AddZcapReplayProtection(), AddZcapCryptoSuite<T>(),
│       │                               #   AddZcapDidResolver<T>(), AddZcapValidWhileTrueSupport(),
│       │                               #   AddZcapCaveatType<T>(), AddZcapRootCapabilityResolver<T>()
│       ├── Endpoints/                  # MapZcapRevocationEndpoints()
│       ├── Services/                   # HttpValidWhileTrueHandler
│       └── Contracts/                  # RevokeCapabilityHttpRequest, RevocationStatusHttpResponse
├── tests/ZcapLd.Core.Tests/           # xUnit + FluentAssertions
│   ├── Cryptography/                   # Ed25519, P256, JsonCanonicalizer, MultibaseCodec, etc.
│   ├── Services/                       # CapabilityService, VerificationService, Revocation, Replay, etc.
│   ├── Models/                         # Capability serialization tests
│   ├── Integration/                    # End-to-end workflow tests
│   ├── Compliance/                     # Normative unit + integration spec compliance tests
│   └── Helpers/                        # InMemoryDidProvider (test-only IDidSigner + IDidResolver)
├── examples/
│   ├── ZcapLd.Examples/               # Console examples (8 scenarios)
│   └── ZcapLd.RevocationEndpointsDemo/ # ASP.NET revocation demo (SQLite + ValidWhileTrue)
├── docs/                               # Implementation, security, revocation, release docs
├── tasks/                              # Historical evaluations, task tracking
├── .github/workflows/                  # CI/CD pipelines
├── ARCHITECTURE.md                     # Architecture and service boundaries
├── CONTRIBUTING.md                     # Contributor guide
└── README.md                          # Project overview and quick start
```

## Development Commands

```bash
dotnet restore                                                         # Restore NuGet packages
dotnet build ZcapLd.sln                                                # Build entire solution
dotnet test ZcapLd.sln                                                 # Run all tests
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release             # Pack core library
dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release  # Pack ASP.NET adapter
dotnet run --project examples/ZcapLd.Examples                          # Run console examples
```

## Architecture Notes

- **Target framework**: .NET 10 (`net10.0`)
- **Specification**: W3C ZCAP-LD v0.3 (CG-DRAFT), 95%+ compliance (283 tests)
- **Composable stack (4.0.0, #108)**: raw cryptography, RDFC-1.0, and JCS are delegated to the shared foundation — **NetCrypto** (sign/verify, key model; reached via **NetDid 2.0.0**, which now builds on NetCrypto), **DataProofsDotnet.Rdfc** (RDFC-1.0/JSON-LD), and **NetCid** (multibase + RFC 8785 JCS). zcap owns no hand-rolled crypto/canonicalization — only ZCAP-specific glue and thin adapters. Source-breaking vs 3.x (consumers recompile; `NetDid.Core.Crypto.*` → `NetCrypto.*`) but **wire-compatible** (Ed25519Signature2020 proof bytes unchanged — Phase 0 golden vectors enforce this in `tests/.../Compliance/ProofGoldenVectorTests` + `CanonicalizationGoldenVectorTests`)
- **Crypto suites (Stage C, #108)**: sign/verify is delegated to DataProofs' **legacy cryptosuites** (`Ed25519Signature2020` / `EcdsaSecp256r1Signature2019`, byte-compatible with zcap's 2020-era wire) via the `LegacyProofCrypto` engine; `ICryptoSuite`/`CryptoSuite` are now suite **metadata** records (proof type, key type, context URL, canonicalization method) the engine + #68 binding consume. zcap owns no proof-signing/verification crypto — only the metadata, the chain/policy layer, and the `ProofSigningPayloadBuilder` clone helpers + test oracle
- **Key management**: No default `IDidSigner` — consumers must provide their own (HSM/KMS/Key Vault)
- **DID resolution**: `DidKeyResolver` (wraps NetDid's `DidKeyMethod`), `CompositeDidResolver` (multi-method routing); returns `ResolvedKey(byte[] PublicKeyBytes, string KeyType)`
- **DID packages**: [NetDid.Core](https://www.nuget.org/packages/NetDid.Core) **2.0.0** + [NetDid.Method.Key](https://www.nuget.org/packages/NetDid.Method.Key) **2.0.0** for W3C-compliant did:key creation/resolution (crypto via NetCrypto); cryptographic primitives via [NetCrypto](https://www.nuget.org/packages/NetCrypto); multibase + JCS via [NetCid](https://www.nuget.org/packages/NetCid); RDFC-1.0 via [DataProofsDotnet.Rdfc](https://www.nuget.org/packages/DataProofsDotnet.Rdfc)
- **Signing**: `SigningService` delegates to `IDidSigner`; resolves verification methods via `IDidResolver` and context URLs via `ICryptoSuiteProvider`
- **Verification**: `VerificationService` dispatches to correct `ICryptoSuite` by proof type; enforces chain validity, attenuation, caveats, revocation, and replay protection
- **Structured results (#70)**: each verify method has a `...DetailedAsync` sibling returning `VerificationResult` (`VerificationOutcome` enum + optional message); the `Task<bool>` methods are thin wrappers over `.IsValid`. `CouldNotVerify` is the explicit "couldn't check" (config/transient fault) outcome vs a provably-invalid capability (the M7/#64 distinction surfaced at the API). Denials are logged on **all** paths via a single Debug-severity boundary choke point (`LogDenial`), not just the exception path. Internal verify helpers (`VerifyCapabilityProofCoreAsync`, `VerifyDelegationProofAsync`, `VerifySingleDelegationProofAsync`, `VerifyInvocationCoreAsync`, `VerifyCapabilityChainCoreAsync`, `VerifyBuiltChainAsync`) now return `VerificationResult`; revocation stays `bool` (control-plane, out of scope)
- **Spec-exact `capabilityChain` (#50)**: root referenced by id only (never embedded); first-level chain is exactly `[rootId]`; deeper chains are `[rootId, …ancestorIds, {immediateParent}]`. The verifier rejects non-spec shapes (embedded root, duplicate ids, parent both id+embedded, wrong/missing embedded parent)
- **Root resolution (#50)**: spec-exact chains reference the root by id, so the verifier obtains it via an explicit-root verify/revoke overload, else an `IRootCapabilityResolver` (`InMemoryRootCapabilityResolver` for dev; an `IDidResolver` that also implements it is auto-detected), else fails closed. **Breaking (3.0.0)**: wire format no longer embeds the root, so pre-3.0.0 capabilities must be re-delegated
- **Invocation `capability` shape (#51)**: `InvocationCapability` (union of root-id **string** | full embedded delegated **zcap object**) backs both `Invocation.Capability` and the invocation `Proof.Capability`, with `InvocationCapabilityJsonConverter` preserving the wire shape. Per ZCAP-LD v0.3 a delegated DI invocation MUST embed the full delegated zcap (`InvocationCapability.FromCapability(delegated)`); a root invocation uses the id string (implicit `string` conversion). Verification is **strict**: a delegated invocation supplying only an id string is rejected. Revocation requests still reference the capability by id string. **Breaking**: `Invocation.Capability` is no longer `string`; `Proof.Capability` is no longer `object?`
- **Revocation**: `IRevocationService` / `IRevocationStore` abstractions; `InMemoryRevocationStore` for dev; ASP.NET endpoints via `ZcapLd.AspNetCore`
- **Replay protection**: `INonceStore` interface; `InMemoryNonceStore` (default), `NullNonceStore` (opt-out)
- **Proof `created` freshness (#71)**: both the invocation (`VerifyInvocationCoreAsync`) and signed-revocation (`RevokeCapabilityInternalAsync`) paths reject a proof whose signed `created` is missing/unparseable, future-dated beyond a configurable clock skew (`_freshnessClockSkew`, default `DefaultFreshnessClockSkew` = 1 min, set via the `freshnessClockSkew` ctor param), or older than `_nonceWindow` — via the shared `GetFreshProofCreatedUtc` helper (staleness bound reuses the nonce window, so anything still evictable is already too stale; widening `nonceWindow` widens both replay window and acceptable signing age). Bounds replay independently of nonce-store eviction (and even under `NullNonceStore`). The invocation path feeds the validated `created` into `InvocationContext.InvocationTime` (caveats evaluate against signed time). Detailed reason: `VerificationOutcome.StaleProof`. Test seam: determinism overloads `SignInvocationAsync(.., createdOverride)` / `SignRevocationAsync(.., createdOverride)` on the concrete `SigningService` (not on `ISigningService`). **Delegation-proof** `created` freshness is a separate concern (durable proofs, no staleness bound) — see #99 below
- **Delegation-proof `created` soundness (#99)**: a delegation proof's `created` is now checked in `VerifySingleDelegationProofAsync` (the single funnel every path shares — standalone, chain, invocation, revocation-auth) via the `CheckDelegationProofCreated` helper, ordered **before** the signature gate (mirrors #71, keeps the negative paths observable without a valid signature). Unlike #71 this is **durable** — there is deliberately **no staleness lower-bound** (a zcap delegated months ago must verify until it `expires`), so it does NOT call `GetFreshProofCreatedUtc`. Checks: future-dated beyond `_freshnessClockSkew` → **always** rejected; present-but-unparseable → **always** rejected (reads the raw `Proof.Created` string and parses defensively, so the reason is `InvalidProofTime`, not the catch's `InvalidDelegation`); missing/empty → rejected **only** under the opt-in `VerificationPolicy.RequireDelegationProofCreated` (default `false`, since pre-existing/cross-stack delegations may legitimately omit `created`). The **`created <= expires`** rule the issue floated was deliberately **dropped** — it is redundant (every `created > expires` case is already caught by the existing `Expired` check or the future-dated check) and false-reject-prone at the clock-skew boundary; the parent/child window-consistency SHOULD was deferred. Threaded via `applyCreatedCheck` on `VerifyDelegationProofAsync`/`VerifySingleDelegationProofAsync`/`VerifyBuiltChainAsync`; the revocation-auth path passes `applyCreatedCheck: false` so a malformed-`created` delegation stays **revocable** (mirrors #73). Detailed reason: `VerificationOutcome.InvalidProofTime` (distinct from `StaleProof`/`Expired`). Test seam: `SignCapabilityAsync(.., createdOverride)` determinism overload on the concrete `SigningService` (not on `ISigningService`).
- **Verifier expiration ceiling (#73)**: the W3C ZCAP-LD verifier-side SHOULD ("an *invoked* delegated zcap's `expires` is not >3 months in the future") is implemented as an **opt-in** `VerificationPolicy` (`ZcapLd.Core.Services`): `EnforceMaxDelegationExpiration` (default `false`) + `MaxDelegationExpirationMonths` (default `3`). Supplied via the full `VerificationService` ctor (`policy:` param) or DI (`services.AddSingleton(new VerificationPolicy{…})` before `AddZcapServices`). Enforced per delegated link in `VerifyBuiltChainAsync` (covers the invocation + chain-verify paths; **every** non-root link, not just the invoked leaf — storage burden applies to every retained zcap, and under attenuation ancestors live longest) measured at `DateTime.UtcNow`. A delegated link with **no `expires`** is also rejected under the policy (unbounded = strictly worse; closes the omit-`expires` bypass an adversarial review caught). The revocation-auth path passes `applyExpirationCeiling: false` so a long-lived delegation stays **revocable** (refusing to authorize its removal would be backwards). Off by default (it is a SHOULD; would reject legitimately long-lived delegations). Detailed reason: `VerificationOutcome.ExpirationTooFarInFuture` (distinct from `Expired`, the past-expiry MUST). The companion create-time hard throw was removed in #61 — this is the spec-correct home. NOT applied to the standalone `VerifyCapabilityProofAsync` single-link check
- **Canonicalization**: `IDocumentCanonicalizer` interface with `JcsDocumentCanonicalizer` (RFC 8785 — `JsonCanonicalizer` delegates to `NetCid.JcsCanonicalizer` after a null-object-member strip) and `RdfcDocumentCanonicalizer` (W3C RDFC-1.0 — a thin adapter over `DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer`, serving zcap's embedded contexts via `RdfcContextDocumentLoader`); suite-specific via `ICryptoSuite.CanonicalizationMethod`
- **ValidWhileTrue**: `ValidWhileTrueCaveat` model + `IValidWhileTrueHandler` interface in Core; `HttpValidWhileTrueHandler` in AspNetCore; `AddZcapValidWhileTrueSupport()` for DI; fail-closed when no handler configured
- **Caveat polymorphic serialization**: `CaveatTypeRegistry.Default` (in-library types pre-registered) + `CaveatJsonConverter` wired into `ZcapJsonOptions.Default` — single source of truth for sign-time + verifier-time JSON. Custom caveats must call `CaveatTypeRegistry.Default.Register<T>(disc)` (or `AddZcapCaveatType<T>(disc)`) before any signing/verification call, otherwise cross-language wire bodies fail to deserialize.
- **ASP.NET integration**: `AddZcapServices()` registers all core services; `AddZcapDidSigner<T>()` for signer; `AddZcapRootCapabilityResolver<T>()` for root resolution (delegated verify/revoke); `AddZcapRevocationSupport()` and `MapZcapRevocationEndpoints()` for revocation; `AddZcapValidWhileTrueSupport()` for remote revocation checking; `AddZcapCaveatType<T>(disc)` for third-party caveats; `AddZcapRdfcCanonicalization()` to enable RDFC-1.0

## Workflow Orchestration

### 0. Branching Policy — BLOCKING, FIRST ACTION, NO EXCEPTIONS

> **STOP. Before reading code, before planning, before any edit: create a branch.**
> Working on `main` is a hard violation of this contract. If you have already
> started editing on `main`, stop now, move the work via `git checkout -b <branch>`
> (uncommitted changes carry over), and continue from the branch.

- **Trigger**: any work that touches code, tests, configs, or docs in response to a GitHub issue, bug report, feature request, or user-driven change.
- **First action**, before any other tool call:
  ```bash
  git checkout -b <issue-number>-<short-kebab-slug>
  # e.g. git checkout -b 37-omit-empty-optional-fields-on-root
  ```
- **No exceptions** for "small" fixes, "one-line" edits, or "just a doc tweak." If it produces a diff, it goes on a branch.
- Verify with `git branch --show-current` before the first edit. If it returns `main`, you are not yet allowed to edit.

### 1. Plan Mode Fault

- Enter plan mode for ANY non-trivial task defined as a task that takes 3 steps or more or that requires architectural decisions.
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity
- A workflow (see §2a) usually _follows_ a plan rather than replacing it — plan
  the approach first, then orchestrate the fan-out as an execution phase

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- Always use adverserial agents to attempt to exploit the code that is being generated. The adverserial agents must report in detail about any findings
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 2a. Workflow Orchestration (Multi-Agent)

- **Opt-in only**: launch a Workflow ONLY when the user explicitly asks (says
  "workflow", "fan out", "orchestrate with subagents") or runs a skill that
  calls it. Otherwise use a single subagent, or describe the workflow and its
  rough token cost and let the user decide. Never auto-launch — workflows can
  spawn dozens of agents and consume a large token budget.
- **High-value workflows in this repo**:
  - _Security review_ — fan out review dimensions (chain validation, caveat
    inheritance, attenuation, replay/nonce, revocation), then spawn N skeptics
    per finding to refute it; keep only findings that survive a majority vote.
  - _Spec-compliance sweep_ — one agent per normative requirement cluster →
    verify implementation + `tests/Compliance/` coverage → completeness critic
    flags untested MUST/SHOULD.
  - _Cross-package migration_ — discover call sites across Core / AspNetCore /
    examples / tests → transform each in worktree isolation → verify it builds.
  - _Test-gap analysis_ — multi-modal sweep by requirement, public API surface,
    and error path.
- **Default to `pipeline()` over barriers**: verify each finding as its review
  lands; only use a barrier when a stage genuinely needs all prior results
  (e.g. dedup before expensive verification).
- **Always adversarially verify security findings** — a plausible-but-wrong
  auth-bypass claim is worse than none.

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done

- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this,"
- Run tests, check logs, demonstrate correctness
- For security-sensitive changes, prefer adversarial multi-agent verification
  (see §2a) — spawn skeptics to refute findings rather than trusting one pass

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing

- **Branch first** — see Section 0 above. Non-negotiable.
- When given a bug report: plan and report.
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

# Task Management

0. **Branch First**: Run `git checkout -b <issue-number>-<slug>` before any other action. See Workflow Orchestration §0.
1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to 'tasks/todo.m,
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections
7. **Keep Documentation Relevant**: Update all relevant documentation including README.md, architecture.md.

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
