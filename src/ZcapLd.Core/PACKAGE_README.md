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
- Caveat support (expiration and usage count)
- Revocation service abstractions with pluggable storage (`IRevocationStore`)
- Pluggable crypto suites (Ed25519 included, P-256/secp256k1 extensible)
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

var invocation = new Invocation
{
    Capability = delegated.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://api.example.com/documents/abc"
};

invocation.Proof = await signingService.SignInvocationAsync(invocation, leafDid);
var isValid = await verificationService.VerifyInvocationAsync(invocation, delegated);
```

## Revocation Backend Plug-In

`ZcapLd.Core` provides:

- `IRevocationStore` for storage providers
- `IRevocationService` for revocation workflow orchestration
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
- The `ICryptoSuite` abstraction supports pluggable algorithms; Ed25519 is registered by default.
- Data integrity processing currently uses deterministic JSON canonicalization rather than full RDF Dataset Canonicalization.

## Documentation

- Repository: https://github.com/moisesja/zcap-dotnet
- Architecture: `architecture.md`
- Revocation Guide: `docs/REVOCATION-INTEGRATION.md`
- Contributing: `CONTRIBUTING.md`
