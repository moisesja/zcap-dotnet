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
- Caveat processing (expiration, usage count, ValidWhileTrue remote revocation) with polymorphic JSON serialization for third-party caveat types via `CaveatTypeRegistry`
- Cross-language wire-format compatibility (W3C Data Integrity flat JCS shape, RFC 8785 escaping, derived-class field preservation)
- Invocation replay protection with pluggable nonce stores
- Revocation persistence with pluggable storage backends
- ValidWhileTrue caveat support with HTTP-based remote revocation checking
- Ed25519 and P-256 signature suites with JCS or RDFC-1.0 canonicalization (crypto delegated to NetCrypto via DataProofs)
- DID resolution via [NetDid](https://www.nuget.org/packages/NetDid.Core) (W3C-compliant did:key support)
- Multibase signature encoding

## Install

```bash
dotnet add package ZcapLd.Core
dotnet add package ZcapLd.AspNetCore # Optional endpoint adapter
```

## Quick Start

```csharp
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

// Wire up services — in production, replace InMemoryDidProvider with your
// IDidSigner (HSM/Key Vault) and IDidResolver implementations.
var didProvider = new InMemoryDidProvider(); // test helper: IDidSigner + IDidResolver + IRootCapabilityResolver

var signingService = new SigningService(didProvider, didProvider);
var capabilityService = new CapabilityService(signingService);
var caveatProcessor = new CaveatProcessor();
// Replay protection is ON by default (in-process InMemoryNonceStore, which is process-local —
// supply a shared INonceStore via the longer constructor for multi-node verifiers).
var verificationService = new VerificationService(didProvider, caveatProcessor);

var rootDid = "did:key:z6MkRoot";
var leafDid = "did:key:z6MkLeaf";

didProvider.GenerateAndRegisterKeyPair(rootDid);
didProvider.GenerateAndRegisterKeyPair(leafDid);

// Root capability (root metadata only)
var root = await capabilityService.CreateRootCapabilityAsync(
    rootDid,
    "https://api.example.com/resources",
    new[] { "read", "write" });

// A spec-exact delegation chain references the root by id only (never embedded), so the verifier
// resolves it via an IRootCapabilityResolver. The test provider implements one — register the root
// so first-level (and deeper) verification can authorize against it. Alternatively, pass the root
// explicitly: verificationService.VerifyInvocationAsync(invocation, delegated, root, null).
didProvider.RegisterRoot(root);

// Delegated capability (restrictions live here)
var delegated = await capabilityService.DelegateCapabilityAsync(
    root,
    leafDid,
    new[] { "read" },
    DateTime.UtcNow.AddDays(7),
    new Caveat[]
    {
        new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(3) }
    });

// CreateInvocation picks the spec-correct `capability` shape automatically (Issue #51): a root
// capability is referenced by id string, a delegated capability embeds the full zcap object — so you
// never have to choose between InvocationCapability.FromId(...) and .FromCapability(...) yourself.
var invocation = capabilityService.CreateInvocation(
    delegated, "read", "https://api.example.com/resources/123");

invocation.Proof = await signingService.SignInvocationAsync(invocation, leafDid);
var isValid = await verificationService.VerifyInvocationAsync(invocation, delegated);

// Need to know WHY verification failed? Every verify method has a `...DetailedAsync` sibling that
// returns a structured VerificationResult (outcome enum + message) instead of a bare bool (Issue #70):
var result = await verificationService.VerifyInvocationDetailedAsync(invocation, delegated);
if (!result.IsValid)
{
    // result.Outcome is e.g. Revoked, Expired, InvalidSignature, UnauthorizedController, Replayed,
    // CaveatFailed, ActionNotAllowed, InvalidTarget, ChainTooLong, … or CouldNotVerify (a config/
    // transient fault rather than an invalid capability). The bool method above == result.IsValid.
    Console.WriteLine($"Denied: {result.Outcome} — {result.Message}");
}
```

### Single vs Multiple Controllers

Per W3C ZCAP-LD v0.3, a capability's `controller` may be **a single DID or an array of DIDs**.
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
  `VerifyCapabilityChainAsync(cap, root)`, `VerifyInvocationAsync(invocation, cap, root, props)`,
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

## ValidWhileTrue Caveat (Remote Revocation)

The `ValidWhileTrue` caveat (per the W3C ZCAP-LD spec) enables remote revocation by embedding a URI in the capability. At verification time, the verifier checks the URI to confirm the capability is still valid. The delegator/controller hosts the endpoint — not the verifier.

**Controller side** (hosts the revocation status endpoint):

```csharp
builder.Services.AddZcapServices();              // POST/revoke endpoint needs IVerificationService
builder.Services.AddZcapRevocationSupport<MyStore>(); // override the store
app.MapZcapRevocationEndpoints();

// When delegating, attach the caveat pointing to your endpoint:
var delegated = await capabilityService.DelegateCapabilityAsync(
    root, partnerDid, new[] { "read" },
    DateTime.UtcNow.AddDays(30),
    new Caveat[]
    {
        new ValidWhileTrueCaveat
        {
            Uri = $"https://my-service/zcaps/revocations/{Uri.EscapeDataString(root.Id)}"
        }
    });
```

**Verifier side** (checks the URI during invocation verification):

```csharp
builder.Services.AddZcapValidWhileTrueSupport(); // registers HttpValidWhileTrueHandler
builder.Services.AddZcapServices();

// HttpClient can be configured for timeouts/retry:
builder.Services.AddHttpClient("ZcapValidWhileTrue", client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});
```

When a `ValidWhileTrue` caveat is encountered during verification, the handler GETs the URI and checks the `isRevoked` field in the response. Without a handler configured, the caveat fails closed (denies access).

## Root vs Delegated Semantics

- Root capability:
  - Contains `@context`, `id`, `controller`, `invocationTarget`
  - Does not include `proof`, `expires`, `parentCapability`
- Delegated capability:
  - Contains `parentCapability`, `expires`, delegation `proof`
  - Supports attenuation (`allowedAction`, target narrowing, caveats)

## Project Layout

- `src/ZcapLd.Core`: library code
- `src/ZcapLd.AspNetCore`: optional ASP.NET endpoint adapter package
- `tests/ZcapLd.Core.Tests`: unit, integration, and compliance tests
- `examples/ZcapLd.Examples`: console examples (8 scenarios including ValidWhileTrue)
- `examples/ZcapLd.RevocationEndpointsDemo`: ASP.NET revocation endpoints demo wired to SQLite (with ValidWhileTrue support)
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
- Canonicalization supports both JCS (JSON Canonicalization Scheme, RFC 8785) and RDFC-1.0 (W3C RDF Dataset Canonicalization) via pluggable `IDocumentCanonicalizer`. JCS is the default; known W3C JSON-LD contexts are embedded for offline operation.
- Cryptography is provided by [NetCrypto](https://www.nuget.org/packages/NetCrypto) (Ed25519 / P-256 sign + verify), reached via [NetDid](https://www.nuget.org/packages/NetDid.Core) 2.0.0 for W3C-compliant did:key resolution; multibase + JCS (RFC 8785) via [NetCid](https://www.nuget.org/packages/NetCid); RDFC-1.0 via [DataProofsDotnet.Rdfc](https://www.nuget.org/packages/DataProofsDotnet.Rdfc).
- Ed25519 and P-256 are the supported signature suites; cryptography is delegated to NetCrypto (via DataProofs), not extended through a zcap API.
