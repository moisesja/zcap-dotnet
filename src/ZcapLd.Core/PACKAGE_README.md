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
- Ed25519 signatures with multibase encoding

## Quick Example

```csharp
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

var signing = new SigningService();
var capabilities = new CapabilityService(signing);
var verifier = new VerificationService(signing, new CaveatProcessor());

var rootDid = "did:key:z6MkRoot";
var leafDid = "did:key:z6MkLeaf";

signing.GenerateAndRegisterKeyPair(rootDid);
signing.GenerateAndRegisterKeyPair(leafDid);

// Root capabilities only define root authority metadata.
var root = await capabilities.CreateRootCapabilityAsync(
    rootDid,
    "https://api.example.com/documents",
    new[] { "read", "write" });

// Restrictions (actions, caveats, expiry) are enforced on delegated capabilities.
var delegated = await capabilities.DelegateCapabilityAsync(
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

invocation.Proof = await signing.SignInvocationAsync(invocation, leafDid);
var isValid = await verifier.VerifyInvocationAsync(invocation, delegated);
```

## Notes

- This package is designed for in-process usage.
- For production, use secure key management (HSM/KMS/Key Vault) instead of in-memory keys.
- Data integrity processing currently uses deterministic JSON canonicalization rather than full RDF Dataset Canonicalization.

## Documentation

- Repository: https://github.com/moisesja/zcap-dotnet
- Architecture: `architecture.md`
- Contributing: `CONTRIBUTING.md`
