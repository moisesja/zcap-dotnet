# ZcapLd.Core

`ZcapLd.Core` is a .NET implementation of the W3C ZCAP-LD model for capability-based authorization.

## Install

```bash
dotnet add package ZcapLd.Core
```

## What It Provides

- Root capability creation (`urn:zcap:root:*`)
- Delegated capability creation with attenuation
- Invocation signing and verification
- Delegation chain verification
- Caveat support (expiration, usage count, and ValidWhileTrue remote revocation)
- ValidWhileTrue caveat with pluggable `IValidWhileTrueHandler` for remote revocation checking
- Revocation service abstractions with pluggable storage (`IRevocationStore`)
- Pluggable crypto suites (Ed25519 and P-256 included, additional curves extensible)
- Dynamic JSON-LD context URLs per crypto suite
- Multibase signature encoding

## Quick Example

```csharp
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

// Wire up services — in production, replace InMemoryDidProvider with your
// IDidSigner (HSM/Key Vault) and IDidResolver implementations.
var didProvider = new InMemoryDidProvider(); // test helper: IDidSigner + IDidResolver
var signingService = new SigningService(didProvider, didProvider);
var capabilityService = new CapabilityService(signingService);
var caveatProcessor = new CaveatProcessor();
var verificationService = new VerificationService(didProvider, caveatProcessor);

var rootDid = "did:key:z6MkRoot";
var leafDid = "did:key:z6MkLeaf";

didProvider.GenerateAndRegisterKeyPair(rootDid);
didProvider.GenerateAndRegisterKeyPair(leafDid);

// Root capabilities only define root authority metadata.
var root = await capabilityService.CreateRootCapabilityAsync(
    rootDid,
    "https://api.example.com/documents",
    new[] { "read", "write" });

// Restrictions (actions, caveats, expiry) are enforced on delegated capabilities.
var delegated = await capabilityService.DelegateCapabilityAsync(
    root,
    leafDid,
    new[] { "read" },
    DateTime.UtcNow.AddDays(7),
    new Caveat[]
    {
        new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(3) }
    });

// CreateInvocation selects the spec-correct `capability` shape automatically (Issue #51): a root
// capability is referenced by id, a delegated capability embeds the full zcap object.
var invocation = capabilityService.CreateInvocation(
    delegated, "read", "https://api.example.com/documents/abc");

invocation.Proof = await signingService.SignInvocationAsync(invocation, leafDid);
var isValid = await verificationService.VerifyInvocationAsync(invocation, delegated);
```

## ValidWhileTrue Caveat (Remote Revocation)

`ValidWhileTrueCaveat` enables remote revocation per the W3C ZCAP-LD spec. The delegator embeds a URI in the caveat; at verification time, the handler checks it. Core provides the `IValidWhileTrueHandler` interface — `ZcapLd.AspNetCore` provides the HTTP implementation.

```csharp
// Delegate with a ValidWhileTrue caveat pointing to the controller's endpoint
var delegated = await capabilityService.DelegateCapabilityAsync(
    root, partnerDid, new[] { "read" },
    DateTime.UtcNow.AddDays(30),
    new Caveat[]
    {
        new ValidWhileTrueCaveat
        {
            Uri = "https://my-service/zcaps/revocations/urn%3Auuid%3A12345"
        }
    });
```

Without a handler configured, `ValidWhileTrueCaveat` always fails closed (denies access).

## Revocation Backend Plug-In

`ZcapLd.Core` provides:

- `IRevocationStore` for storage providers
- `IRevocationService` for revocation workflow orchestration
- `IValidWhileTrueHandler` for async remote revocation checks (ValidWhileTrue caveat)
- `InMemoryRevocationStore` as the default implementation

## Exposing Revocation Without ASP.NET

`ZcapLd.Core` is transport-agnostic. You can expose revocation through:

- gRPC APIs
- message consumers
- worker services
- CLI/admin operations

In all cases, call `IRevocationService` from your transport/application layer.

## Persistence Strategies

Use `IRevocationStore` to plug in your persistence model:

- In-memory (`InMemoryRevocationStore`) for local development
- SQL/NoSQL-backed custom stores
- Smart-contract/oracle-backed stores
- Hybrid cache + durable stores

## Notes

- This package is designed for in-process usage.
- No default `IDidSigner` ships in the core package — consumers must provide their own (HSM/KMS/Key Vault).
- The `ICryptoSuite` abstraction supports pluggable algorithms; Ed25519 and P-256 are registered by default.
- Data integrity processing supports JCS (default) and RDFC-1.0 (W3C RDF Dataset Canonicalization) via pluggable `IDocumentCanonicalizer`. Register `RdfcDocumentCanonicalizer` for full Data Integrity spec compliance.

## Documentation

- Repository: https://github.com/moisesja/zcap-dotnet
- Architecture: `architecture.md`
- Revocation Guide: `docs/REVOCATION-INTEGRATION.md`
- Contributing: `CONTRIBUTING.md`
