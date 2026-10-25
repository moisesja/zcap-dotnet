# zcap-dotnet

A .NET 10 implementation of the [W3C ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) authorization capability model.

[![CI Core](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci-core.yml/badge.svg)](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci-core.yml)
[![CI ASP.NET](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci-aspnet.yml/badge.svg)](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci-aspnet.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why This Library

ZCAP-LD uses object capabilities: if you hold a valid signed capability, you have authority to invoke the permitted action.

This library provides:

- Capability creation and delegation
- Delegation-chain verification
- Invocation signing and verification
- Native restrictions (`expires`, `allowedAction`, target narrowing); unsupported vocabulary caveats are rejected.
- Cross-language wire-format compatibility — proven live against `@digitalbazaar/zcap` (RDFC-1.0 / W3C Data Integrity; see [`interop/`](interop/README.md))
- Invocation replay protection with pluggable nonce stores
- Revocation persistence with pluggable storage backends
- Ed25519 and P-256 signature suites with RDFC-1.0 canonicalization (crypto delegated to NetCrypto via DataProofs)
- DID resolution via [NetDid](https://www.nuget.org/packages/NetDid.Core) (W3C-compliant did:key support)
- Multibase signature encoding

## Install

```bash
dotnet add package ZcapLd.Core
dotnet add package ZcapLd.AspNetCore # Optional endpoint adapter
```

## Quick Start

```csharp
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

// Supply your IDidSigner and IDidResolver implementations (for example, HSM/KMS-backed).
var signingService = new SigningService(didSigner, didResolver);
var capabilityService = new CapabilityService(signingService);
var verificationService = new VerificationService(didResolver);
var root = await capabilityService.CreateRootCapabilityAsync(ownerDid, "https://example.com/reports");
var delegated = await capabilityService.DelegateCapabilityAsync(
    root, agentDid, new[] { "read" }, DateTime.UtcNow.AddDays(1));
var invocation = capabilityService.CreateInvocation(delegated, "read");
invocation.Proof = await signingService.SignInvocationAsync(invocation, agentDid);
bool valid = await verificationService.VerifyInvocationAsync(invocation, delegated, root);
```

The explicit root above supplies the trust anchor. Alternatively configure
`IRootCapabilityResolver`. For cross-stack application-document invocations use
`SignCapabilityInvocationAsync` and `VerifyCapabilityInvocationAsync` with the
relying party's expected action and targets. Run the console example for both paths.

Version 5 removes typed caveats and their context-properties verification overloads.
See [the breaking changes](CHANGELOG.md) and the native restriction policy below.

### Single vs Multiple Controllers

Per W3C ZCAP-LD v0.4.0, a capability's `controller` may be **a single DID or an array of DIDs**.
`Capability.Controller` is a `ControllerSet` that preserves the shape on the wire — assign a
`string` for one controller or a `string[]` for several (implicit conversions). **Any** controller
in the set is authorized to invoke or delegate.

```csharp
// Single controller → serializes as a bare string: "controller": "did:key:zAlice"
var single = await capabilityService.CreateRootCapabilityAsync(
    "did:key:zAlice",
    "https://api.example.com/resources",
    new[] { "read" });

// Multiple controllers → serializes as an array: "controller": ["did:key:zAlice","did:key:zBob"]
var shared = await capabilityService.CreateRootCapabilityAsync(
    new[] { "did:key:zAlice", "did:key:zBob" },
    "https://api.example.com/resources",
    new[] { "read" });

// An invocation/delegation signed by EITHER zAlice or zBob verifies; any other key is rejected.
shared.Controller.Values;                       // ["did:key:zAlice", "did:key:zBob"]
shared.Controller.ContainsVerificationMethod("did:key:zBob#zBob"); // true

// When delegating from a multi-controller capability, choose which controller signs:
var delegatedByBob = await capabilityService.DelegateCapabilityAsync(
    shared,
    "did:key:zCarol",
    new[] { "read" },
    DateTime.UtcNow.AddDays(7),
    signerDid: "did:key:zBob");                 // must be one of `shared`'s controllers
```

## Delegation Chains & Root Resolution

The delegation proof's `capabilityChain` follows the W3C ZCAP-LD shape **exactly** (Issue #50): the
root is referenced **by id only** (never embedded), every ancestor is referenced by id, and **only the
immediate parent** delegated zcap is fully embedded — as the last entry. So:

| Delegation level | `capabilityChain` |
| --- | --- |
| First (from root) | `["urn:zcap:root:…"]` |
| Second | `["urn:zcap:root:…", { …parent embedded… }]` |
| Third | `["urn:zcap:root:…", "urn:uuid:first…", { …parent embedded… }]` |

Because the root is by-reference, the verifier needs a way to obtain it to authorize the first
delegation. Provide it one of two ways:

- **Resolver** — implement `IRootCapabilityResolver` (the resource owner resolves roots from its own
  store) and pass it to `VerificationService` (or register it in DI with
  `AddZcapRootCapabilityResolver<T>()`). An `IDidResolver` that *also* implements
  `IRootCapabilityResolver` is auto-detected. `InMemoryRootCapabilityResolver` is provided for dev.
- **Explicit root** — call the overloads that take the root directly:
  `VerifyCapabilityChainAsync(cap, root)`, `VerifyInvocationAsync(invocation, cap, root)`,
  `VerifyCapabilityProofAsync(cap, root)`, `RevokeCapabilityAsync(cap, signedRevocation, root)`.

When neither is available the verifier **fails closed**. The verifier also rejects non-spec chains
(an embedded root, duplicated ids, a parent referenced both by id and embedded, a wrong/missing
embedded parent).

> **Breaking change (3.0.0):** the `capabilityChain` wire format changed (it no longer embeds the
> root), so capabilities signed by earlier versions do not verify and must be re-delegated; and
> verifying a delegated capability now requires a resolver or an explicit root as described above.
>
> **Breaking change (4.0.0):** the cryptography and canonicalization are now delegated to the
> composable foundation — **NetCrypto** (via **NetDid 2.0.0**), **DataProofsDotnet.Rdfc**, and
> **NetCid**. This is **source-breaking** (recompile; the `NetDid.Core.Crypto.*` types moved to
> `NetCrypto.*`) but **wire-compatible**: the `Ed25519Signature2020` / `EcdsaSecp256r1Signature2019`
> proof bytes are unchanged, so capabilities issued by 3.x still verify — no re-delegation.

## Revocation Extensibility

Revocation requires **proof of possession**: a revoker proves control by *signing* a revocation
request, which the library authenticates (signature) and authorizes (against the capability's
verified delegation chain). There is no unauthenticated bare-DID path.

- `ISigningService.SignRevocationAsync(...)`: mint a signed revocation request
- `IVerificationService.RevokeCapabilityAsync(Capability, Invocation)`: authenticate + authorize + record
- `IRevocationStore`: plug in your own backend (database, contract gateway, oracle bridge, cache)
- `IRevocationService`: **persistence primitive** — performs no auth; never call directly from untrusted input
- `VerificationService`: checks revocation status during capability/invocation verification

```csharp
// Revoker side — sign a revocation request bound to the capability:
var signedRevocation = await signingService.SignRevocationAsync(
    delegated.Id, revokerDid, delegated.InvocationTarget, reason: "key compromised");

// Verifier side — authenticate, authorize against the chain, then record:
bool revoked = await verificationService.RevokeCapabilityAsync(delegated, signedRevocation);
```

Optional ASP.NET endpoint rails are provided by `ZcapLd.AspNetCore`:

```csharp
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddZcapServices(); // registers IVerificationService (required by the POST endpoint)
// Optionally override the store: builder.Services.AddZcapRevocationSupport<MyStore>();

var app = builder.Build();
app.MapZcapRevocationEndpoints(); // /zcaps/revocations/{*capabilityId}
app.Run();
```

### Setup Revocation Endpoints with ASP.NET

Use `ZcapLd.AspNetCore` when your runtime is ASP.NET and you want ready-made minimal API rails:

- Register services via `AddZcapServices()` (the POST/revoke endpoint resolves `IVerificationService`)
- Map routes via `MapZcapRevocationEndpoints(...)`
- POST a signed `{ capability, signedRevocation }`; the endpoint returns `403` if unauthenticated/unauthorized
- Override route prefix when needed (for example `/wallet/revocations`)

### Expose Revocation in Other Ways

If you do not want ASP.NET endpoints, drive `IVerificationService.RevokeCapabilityAsync(Capability,
Invocation)` from your own transport layer (gRPC handler, message consumer, admin CLI, worker). Call
the lower-level `IRevocationService` directly **only** after you have authenticated and authorized the
caller yourself — it records whatever it is given.

### Persistence Strategy Options

Configure storage via `IRevocationStore`:

- `InMemoryRevocationStore` for local development/testing
- database-backed custom stores for centralized persistence
- smart-contract/oracle-backed stores for decentralized persistence
- hybrid cache + durable store composites for high-throughput workloads

Full developer guide: [`docs/REVOCATION-INTEGRATION.md`](docs/REVOCATION-INTEGRATION.md)

## Native restrictions and verifier policy

The supported [ZCAP v0.4.0 profile](https://w3c-ccg.github.io/zcap-spec/v0.4.0/)
uses `expires`, `allowedAction`, and `invocationTarget` to restrict delegated authority.
Vocabulary-based `caveat` fields are rejected, including unknown types, empty arrays,
and null values, throughout embedded chains. Equivalent absolute-IRI/prefixed keys
and nested restriction nodes are rejected too. Capability/proof contexts are limited
to zcap/v1 and supported proof-suite contexts; inline aliases are unsupported.
Profile inspection is bounded to depth 64 and 65,536 visited values per scan;
exceeding those limits produces a distinct resource-limit diagnostic.
There is no custom caveat registry or
remote `ValidWhileTrue` handler.

```csharp
var child = await capabilityService.DelegateCapabilityAsync(
    root, agentDid, new[] { "read" }, DateTime.UtcNow.AddDays(1),
    invocationTarget: root.InvocationTarget + "/reports?section=summary");

// Register before AddZcapServices(), or pass policy: to VerificationService.
services.AddSingleton(new VerificationPolicy { AllowTargetAttenuation = true });
```

`AllowTargetAttenuation` defaults to **false**, matching `@digitalbazaar/zcap`:
parent/child and capability/invocation targets must match exactly. When enabled,
a suffix must begin with `/` or `?` if the base has no query, or `&` if it does.
The verifier additionally rejects literal `..` path segments. Creation allows an
explicit narrower target; verifier acceptance is a separate policy decision.

The resource API must enforce the meaning of each restriction. Lexical matching
cannot enforce usage counters, quotas, or query semantics. In particular, reject
ambiguous duplicate restriction parameters: `?maxUses=1&maxUses=100` must not
widen authority through last-value parsing. Proxies and resource routing must
interpret the authenticated target consistently, including percent encoding.

Use native `expires` instead of `ExpirationCaveat`. Revocation belongs to the
verifier responsible for the target; see [revocation integration](docs/REVOCATION-INTEGRATION.md).

## Root vs Delegated Semantics

- Root capability:
  - Contains `@context`, `id`, `controller`, `invocationTarget`
  - Does not include `proof`, `expires`, `parentCapability`
- Delegated capability:
  - Contains `parentCapability`, `expires`, delegation `proof`
  - Supports attenuation (`allowedAction`, target narrowing, expiration)

## Project Layout

- `src/ZcapLd.Core`: library code
- `src/ZcapLd.AspNetCore`: optional ASP.NET endpoint adapter package
- `tests/ZcapLd.Core.Tests`: unit, integration, and compliance tests
- `examples/ZcapLd.Examples`: native restriction and signed revocation examples
- `examples/ZcapLd.RevocationEndpointsDemo`: ASP.NET revocation with SQLite
- `interop`: live cross-stack interop harness vs `@digitalbazaar/zcap` (run `interop/run-interop.sh`)
- `docs`: implementation/security notes

## Developer Docs

- Architecture: [`architecture.md`](architecture.md)
- Interop & spec-compliance analysis: [`docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md`](docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md) (with live `@digitalbazaar/zcap` round-trip harness in [`interop/`](interop/README.md))
- Revocation Integration: [`docs/REVOCATION-INTEGRATION.md`](docs/REVOCATION-INTEGRATION.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- NuGet Release Runbook: [`docs/NUGET-RELEASE.md`](docs/NUGET-RELEASE.md)
- Monorepo Pipelines: [`docs/MONOREPO-PIPELINES.md`](docs/MONOREPO-PIPELINES.md)
- MIT License: [`LICENSE`](LICENSE)

## Local Development

```bash
dotnet restore
dotnet build ZcapLd.sln
dotnet test ZcapLd.sln
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
dotnet pack src/ZcapLd.AspNetCore/ZcapLd.AspNetCore.csproj -c Release
```

## CI/CD

- Core CI: `.github/workflows/ci-core.yml`
- ASP.NET Adapter CI: `.github/workflows/ci-aspnet.yml`
- Core publish: `.github/workflows/release-core-nuget.yml` on `core-v*.*.*` tags
- ASP.NET adapter publish: `.github/workflows/release-aspnet-nuget.yml` on `aspnet-v*.*.*` tags
- Shared package version source: `Directory.Build.props` (`ZcapLdVersion`)
- Secrets:
  - Core: `NUGET_API_KEY_CORE` (fallback `NUGET_API_KEY`)
  - ASP.NET adapter: `NUGET_API_KEY_ASPNET` (fallback `NUGET_API_KEY`)

## Security and Production Notes

- No default `IDidSigner` ships in the core package — consumers must provide their own (HSM/KMS/Key Vault).
- `InMemoryDidProvider` (in examples and tests) stores private keys in plaintext memory and is NOT for production use.
- Canonicalization is RDFC-1.0 (W3C RDF Dataset Canonicalization) only — the format that interoperates with `@digitalbazaar/zcap`. JCS support was removed in 4.0.0; there is no canonicalization option. Known W3C JSON-LD contexts are embedded for offline operation.
- Cryptography is provided by [NetCrypto](https://www.nuget.org/packages/NetCrypto) (Ed25519 / P-256 sign + verify), reached via [NetDid](https://www.nuget.org/packages/NetDid.Core) 3.1.0 for W3C-compliant did:key resolution; multibase via [NetCid](https://www.nuget.org/packages/NetCid); RDFC-1.0 via [DataProofsDotnet.Rdfc](https://www.nuget.org/packages/DataProofsDotnet.Rdfc).
- Ed25519 and P-256 are the supported signature suites; cryptography is delegated to NetCrypto (via DataProofs), not extended through a zcap API.

### Cross-stack interop caveats (`@digitalbazaar/zcap`)

Capability **delegation** interoperates with `@digitalbazaar/zcap` (proven live by [`interop/`](interop/README.md)). Two things to know for cross-stack use:

- **Use `Ed25519Signature2020`.** P-256 (`EcdsaSecp256r1Signature2019`) has no `@digitalbazaar/zcap` counterpart — it ships/tests Ed25519 only and serves no `ecdsa-2019/v1` context, so a P-256 capability will not verify there.
- **Invocation** interop works via Data Integrity `capabilityInvocation` proofs (`SignCapabilityInvocationAsync` / `VerifyCapabilityInvocationAsync`), proven cross-stack for root + delegated. The verifier requires the relying party to declare the **expected action and target(s)** it authorizes (as the reference impl does) and validates the application document's `@context`, so a valid invocation can't be replayed against a different endpoint or have its terms rewritten. HTTP-Signature invocations (the `ezcap` transport) are not yet supported (tracked in #119).
