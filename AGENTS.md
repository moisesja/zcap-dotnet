# Agent & Contributor Instructions

This file describes the current codebase and contributor workflow. For implementation
details, see [architecture.md](architecture.md) and
[the supported-profile requirements](docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md).

## Project Overview

zcap-dotnet is a .NET 10 library for creating, delegating, invoking and verifying
ZCAP-LD capabilities. Authority is conveyed by a signed delegation chain and a
controller-authorized invocation. The supported profile targets the ZCAP v0.4.0
Community Group draft; interoperability claims are limited to the tested cases.

## Key Requirements and Design

- **Root capabilities** are unsigned trust anchors containing `@context`, `id`,
  `controller` and `invocationTarget`. Resolve them through an explicit-root overload
  or `IRootCapabilityResolver`; never trust a root supplied by an untrusted invoker.
- **Delegated capabilities** carry a parent ID, controller, target, expiration and
  delegation proof, with optional allowed actions. Controllers can be a URI or array.
  A child cannot widen actions or extend the parent's expiration.
- **Native restrictions** use `expires`, `allowedAction` and target narrowing. Without a
  `CaveatTypeRegistry`, reject `caveat`, `https://w3id.org/security#caveat` and
  `sec:caveat`, including null/empty values, ancestors and extension JSON. In every profile,
  capability/proof JSON may not use `:` keys or keywords other than `@context`: `@nest`,
  `@included` or a full-IRI key restates a signed term the model does not read, which let a holder
  drop its own `allowedAction`. Capability/proof contexts are limited to zcap/v1, supported suite
  contexts and registered caveat contexts; inline aliases and unrelated vocabularies are rejected.
- **Custom caveats (#157)** are an opt-in, non-interoperable extension profile
  ([docs/CAVEAT-PROFILE.md](docs/CAVEAT-PROFILE.md)). They are the only sanctioned caveat
  path. Every parameter must be signed through the generated per-type context, and every
  input RDFC would drop (undeclared parameters, unregistered types, missing type context,
  non-canonical numbers, null) must be rejected. A `Caveat` validates and attenuates but never
  authorizes. Only resource-owned `ICaveatHandler`s at invocation authorize, after every other
  check including replay. Chain/proof APIs return `CaveatEnforcementRequired`. Children must
  restate and narrow parent caveats. Do not add an `IsSatisfied` callback, an invocation
  context property bag, unsigned caveat parameters or capability-supplied URLs.
- **Target policy** defaults to exact matching. With
  `VerificationPolicy.AllowTargetAttenuation = true`, a suffix must begin with
  `/` or `?` before a query, or `&` after one. Matching is ordinal and rejects literal
  `..` path segments. `DelegateCapabilityAsync(..., invocationTarget: ...)` allows
  explicit narrowing at creation; verifier acceptance is separately configured.
  Resource APIs must enforce query meaning and safe routing/normalization.
- **Proofs** use RDFC-1.0 with `Ed25519Signature2020` or
  `EcdsaSecp256r1Signature2019`. Use the shared DataProofs/NetCrypto foundation;
  do not implement crypto or canonicalization inside zcap. Modernized v0.4 examples
  do not mandate a suite migration. Golden vectors pin supported proof bytes.
- **Chains** are exactly `[rootId]` for the first delegation and
  `[rootId, ...ancestorIds, {immediateParent}]` for deeper links. Each delegation
  requires parent-controller authorization. Validate every link before granting
  access, and bound chain traversal to a maximum length of 10.
- **Invocations** require the invoked capability's controller relationship, requested
  action, matching/attenuated target, valid chain, freshness, revocation and replay
  checks. A root invocation references its ID; a delegated invocation embeds the
  complete delegated capability. The DI application-document API requires relying
  party expected action/targets and optionally pins root IDs.
- **Identity and keys** are application-owned. Consumers provide `IDidSigner`;
  `IDidResolver` resolves key material, and `IVerificationRelationshipResolver`
  authorizes keys through controller documents. `CompositeDidResolver` routes both by the
  controller's DID method and fails closed (`methodNotSupported` / `internalError`) instead
  of inferring authority from key resolution; an explicit relationship resolver takes
  precedence. Never persist private keys in Core.
- **Revocation and replay** use pluggable stores shared across verifier replicas.
  Revocation requests must prove possession of an authorized key. A root revocation is
  authorized against the trusted resolved root, never the request's copy; whether an id is a
  root is decided by the resolver/explicit root, not by the request's shape. An explicit root
  admits only itself or chains ending at it. Records are scoped (#158): `Delegated(delegator)`
  for a delegated capability (the DID of the verification method that signed its delegation
  proof, as `bedrock-zcap-storage` keys them), `Root` for a root, `Unscoped` only for migrated
  5.x and operator records. Look a link up after its proof verifies, under that proof's
  delegator; never key, memoize or delete revocation by bare id; never let the signed path
  write `Unscoped` (architecture.md, "Revocation scope"). Distribution to
  independent verifiers is a deployment responsibility. HTTP-signature invocation
  transport (#119), gRPC hosting and WASM remain separate work.

## Project Structure

```
zcap-dotnet/
├── ZcapLd.sln
├── src/
│   ├── ZcapLd.Core/
│   │   ├── Cryptography/   # ZcapSuiteCatalog, LegacyProofCrypto, RdfcDocumentCanonicalizer,
│   │   │                   # RdfcContextDocumentLoader, ProofSigningPayloadBuilder, converters
│   │   ├── Models/         # Capability, ControllerSet, Proof, ProofSet, Invocation,
│   │   │                   # InvocationCapability, VerificationResult, revocation/key models
│   │   ├── Services/       # CapabilityService, SigningService, VerificationService,
│   │   │                   # CapabilityProfile, InvocationTargetPolicy, VerificationPolicy,
│   │   │                   # signer/resolver/root/revocation/nonce interfaces and implementations
│   │   └── Exceptions/
│   └── ZcapLd.AspNetCore/
│       ├── DependencyInjection/ # AddZcapServices, signer/resolver/root/revocation/replay helpers
│       ├── Endpoints/           # MapZcapRevocationEndpoints
│       └── Contracts/           # SignedRevocationHttpRequest, RevocationStatusHttpResponse
├── tests/
│   ├── ZcapLd.Core.Tests/        # Cryptography, models, services, integration, compliance, helpers
│   ├── ZcapLd.AspNetCore.Tests/  # HTTP signed-revocation integration
│   └── ZcapLd.Interop.Tests/     # Live harness wrapper; separate from solution tests
├── interop/                     # .NET CLI, pinned JS peer, target/profile matrix
├── examples/
│   ├── ZcapLd.Examples/          # Native restrictions, invocation formats and revocation
│   └── ZcapLd.RevocationEndpointsDemo/ # ASP.NET signed revocation with SQLite
├── docs/
├── tasks/
├── .github/workflows/
├── architecture.md
├── CONTRIBUTING.md
└── README.md
```

## Development Commands

```bash
dotnet restore
dotnet build ZcapLd.sln
dotnet test ZcapLd.sln
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release
dotnet run --project examples/ZcapLd.Examples
bash interop/run-interop.sh
```

## Architecture Notes

- **Framework and packages**: .NET 10, ZcapLd.Core and ZcapLd.AspNetCore 6.0.0.
  Exact dependency pins live in the project files. NetCrypto handles cryptographic
  primitives, NetDid handles DID resolution, DataProofs handles legacy proof suites
  and RDFC, and NetCid handles multibase and RFC 8785. Do not claim a spec compliance percentage.
- **Signing bytes**: `SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))`.
  `LegacyProofCrypto` owns production dispatch; `ProofSigningPayloadBuilder` supplies
  clone helpers and the test oracle. Signing self-verifies against the resolved key.
  `ZcapSuiteCatalog` is the closed suite metadata source, not a plugin registry.
  Context-less documents (envelope invocations, signed revocations) are canonicalized under
  zcap/v1 plus the proof's suite context, so `created`/`proofPurpose` are signed (#157). Revocations
  also get `urn:zcap-dotnet:revocation-context:v1`, which defines their purpose, reason and metadata.
  DataProofs ≥ 1.5.0 refuses undefined terms and dropped or respelled IRIs. That is a second layer
  only for RDFC: its legacy verifier also accepts the JCS variant, which signs bytes verbatim.
  Adversarial tests forge with `LenientRdfcCanonicalizer` (test helper) and assert zcap's specific
  outcome, so they keep proving zcap's own checks reject first.
- **Identifiers (#157)**: RDFC normalizes IRIs, so keys must be the signed form. Capability,
  chain, invocation, document and revocation-request ids must be absolute IRIs equal to
  `Uri.AbsoluteUri` (`CanonicalIri`). Never key revocation, replay or budgets on a variant.
  dotNetRDF also drops IRIs .NET deems malformed (`[`, `]`, a second `#`) and rewrites others .NET
  leaves alone (encoded dot segments, invisible trailing segments); DataProofs 1.5.0 refuses both,
  but zcap checks first. Ids must be
  `CanonicalIri.IsCanonical` and targets `IsSignedTarget`, both decided by canonicalizing the IRI
  itself; controllers and verification methods must be `IsBindable`. Never predict RDFC's IRI form
  from `System.Uri`.
- **Serialization**: `ZcapJsonOptions.Default` preserves union shapes, opaque timestamp
  strings and extension data, and rejects duplicate JSON properties. A field is authenticated
  only if a context defines it; DataProofs 1.5.0 refuses undefined terms rather than dropping them.
  Revocation `reason`/`metadata` are signed but informational, never authorization inputs.
- **Profile rejection**: `CapabilityProfile` inspects capability/proof extensions,
  embedded ancestry and every proof-set member with depth/work bounds. Invocation
  and revocation checks cover every capability representation. An application
  document's unrelated fields are outside the capability scan.
- **Roots and proofs**: roots are referenced by ID and resolved through a trust boundary.
  An ID-only delegated invocation is rejected. Proof sets accept at least one valid
  delegation proof, but unsupported profile content in any member is rejected. The chain walk
  tries each chain the delegation proofs name, depth first and at most `MaxChainCandidates` (16),
  and verifies each link only with the proof whose chain it followed. A parent is reached only
  through its proof naming the ancestors its child lists. Never let one proof choose the parent
  another proof is judged against, and never let an unverified proof hide a valid chain.
  Standalone proof verification checks a single link, not full authorization.
- **Results**: detailed verify APIs return `VerificationResult` with a named outcome;
  bool APIs wrap `.IsValid`. `CouldNotVerify` distinguishes infrastructure faults.
  Expected denials log at Debug; unexpected faults log at Warning. Signed revocation
  retains its bool result.
- **DI invocation security**: verify the application context before trusting the signature,
  and enforce caller-provided expected action/targets (plus optional root pinning).
  Otherwise dropped terms or a confused-deputy replay can invalidate authorization.
  The in-stack `Invocation` envelope is separate from interoperable DI application documents.
- **Freshness (#71)**: invocation/revocation `created` must be parseable, within the nonce
  window and no more than the configured skew (default one minute) in the future.
  This lower bound applies even with `NullNonceStore`.
- **Durable delegation time (#99)**: no lower freshness bound. Present malformed/future
  `created` is rejected; `RequireDelegationProofCreated` optionally requires presence.
  `InvalidProofTime` is distinct from `StaleProof` and `Expired`.
- **Expiration (#73)**: chain/invocation verification requires delegated `expires`.
  The opt-in `EnforceMaxDelegationExpiration` ceiling applies per link (default three
  months), not to standalone proof verification. Revocation authorization exempts the
  ceiling, missing-expiration requirement and delegation-created checks so those
  policy failures do not block removal. Past-expired or already-revoked chains remain
  ineligible for a new revocation record. Unsupported vocabulary is never exempted.
- **Other controls**: restricted parents require non-empty action subsets; the chain
  limit bounds traversal work; offsetless timestamps parse as UTC. `RejectUnknownRootFields`
  is optional, while forbidden root fields are always rejected.
- **ASP.NET**: `AddZcapServices` registers verification and the service graph;
  `AddZcapDidSigner<T>`, `AddZcapDidResolver<T>`, `AddZcapRootCapabilityResolver<T>`,
  `AddZcapRevocationSupport` and `AddZcapReplayProtection` provide integrations.
  Revocation POST verifies a signed request and caps the body at 1 MB. There is no status
  GET: the spec and the JS stack define only the POST, and a scoped record has no bare-id
  status. No capability-controlled HTTP fetch occurs. The endpoint takes
  `encodeURIComponent(capabilityId)` and decodes it exactly once from the raw request target
  (the route value is already decoded except `%2F`; never decode it again).

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
  - _Security review_ — fan out review dimensions (chain validation, unsupported
    restriction rejection, attenuation, replay/nonce, revocation), then spawn N skeptics
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
1. **Plan First**: Write plan to `tasks/plan{timestamp}.md` with checkable items. The plan must document the human's intents and decisions. It must also document the results of your work.
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Capture Lessons**: Update 'tasks/lessons.md' after corrections
6. **Keep Documentation Relevant**: Update all relevant documentation including README.md, architecture.md.

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
