# zcap-dotnet

A .NET 10 implementation of the [W3C ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) authorization capability model.

[![CI](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/moisesja/zcap-dotnet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why This Library

ZCAP-LD uses object capabilities: if you hold a valid signed capability, you have authority to invoke the permitted action.

This library provides:

- Capability creation and delegation
- Delegation-chain verification
- Invocation signing and verification
- Caveat processing (expiration and usage count)
- Ed25519 signatures with multibase encoding

## Install

```bash
dotnet add package ZcapLd.Core
```

## Quick Start

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

// Root capability (root metadata only)
var root = await capabilities.CreateRootCapabilityAsync(
    rootDid,
    "https://api.example.com/resources",
    new[] { "read", "write" });

// Delegated capability (restrictions live here)
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
    InvocationTarget = "https://api.example.com/resources/123"
};

invocation.Proof = await signing.SignInvocationAsync(invocation, leafDid);
var isValid = await verifier.VerifyInvocationAsync(invocation, delegated);
```

## Root vs Delegated Semantics

- Root capability:
  - Contains `@context`, `id`, `controller`, `invocationTarget`
  - Does not include `proof`, `expires`, `parentCapability`
- Delegated capability:
  - Contains `parentCapability`, `expires`, delegation `proof`
  - Supports attenuation (`allowedAction`, target narrowing, caveats)

## Project Layout

- `src/ZcapLd.Core`: library code
- `tests/ZcapLd.Core.Tests`: unit, integration, and compliance tests
- `examples/ZcapLd.Examples`: console examples
- `docs`: implementation/security notes

## Developer Docs

- Architecture: [`architecture.md`](architecture.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- NuGet Release Runbook: [`docs/NUGET-RELEASE.md`](docs/NUGET-RELEASE.md)
- MIT License: [`LICENSE`](LICENSE)

## Local Development

```bash
dotnet restore
dotnet build ZcapLd.sln
dotnet test ZcapLd.sln
dotnet pack src/ZcapLd.Core/ZcapLd.Core.csproj -c Release
```

## CI/CD

- CI workflow: `.github/workflows/ci.yml`
  - restore, build, test, pack
  - uploads `.nupkg` / `.snupkg` artifacts
- Publish workflow: `.github/workflows/release-nuget.yml`
  - publishes on `v*.*.*` tags
  - requires repository secret: `NUGET_API_KEY`

## Security and Production Notes

- Current signing service stores private keys in memory for development/testing.
- Production deployments should use HSM/KMS/Key Vault-backed signing.
- Canonicalization currently uses deterministic JSON canonicalization, not full RDF Dataset Canonicalization.
