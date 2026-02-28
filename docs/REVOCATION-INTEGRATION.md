# Revocation Integration Guide

This guide describes how to integrate revocation workflows in three ways:

1. Expose revocation endpoints using `ZcapLd.AspNetCore`
2. Expose revocation via other transport patterns (without ASP.NET adapter)
3. Configure persistence strategies for revocation registries

## 1. ASP.NET Endpoints with `ZcapLd.AspNetCore`

Install packages:

```bash
dotnet add package ZcapLd.Core
dotnet add package ZcapLd.AspNetCore
```

Register services and map endpoints:

```csharp
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// Default: in-memory revocation store
builder.Services.AddZcapRevocationSupport();

var app = builder.Build();

// Default route prefix: /zcaps/revocations
app.MapZcapRevocationEndpoints();
// Or custom prefix:
// app.MapZcapRevocationEndpoints("/wallet/revocations");

app.Run();
```

Default endpoint contract:

- `POST /zcaps/revocations/{*capabilityId}`: create/update revocation record
- `GET /zcaps/revocations/{*capabilityId}`: query revocation status

Runnable demo:

- `examples/ZcapLd.RevocationEndpointsDemo/README.md`

## 2. Expose Revocation in Other Ways

`ZcapLd.Core` is transport-agnostic. You can expose revocation using any application boundary by depending on `IRevocationService`:

- gRPC services
- message/event-driven consumers
- CLI/admin tools
- background worker APIs
- blockchain oracle/relayer services

Example service-layer usage:

```csharp
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

public sealed class RevocationApplicationService
{
    private readonly IRevocationService _revocationService;

    public RevocationApplicationService(IRevocationService revocationService)
    {
        _revocationService = revocationService;
    }

    public Task<RevocationRecord> RevokeAsync(string capabilityId, string revokerDid, DateTime? expiresAt)
    {
        return _revocationService.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId,
            RevokedBy = revokerDid,
            ExpiresAt = expiresAt
        });
    }

    public Task<bool> IsRevokedAsync(string capabilityId)
    {
        return _revocationService.IsRevokedAsync(capabilityId);
    }
}
```

## 3. Persistence Strategies for Revocation Registries

Revocation persistence is configured through `IRevocationStore`.

Core interfaces:

- `IRevocationStore`: backend adapter contract
- `IRevocationService`: orchestration and expiry-aware lookup behavior

### Strategy A: In-Memory (Dev/Test)

Use `InMemoryRevocationStore`:

```csharp
var revocationService = new RevocationService(new InMemoryRevocationStore());
```

### Strategy B: Relational/NoSQL Store

Implement `IRevocationStore` and register it:

```csharp
public sealed class SqlRevocationStore : IRevocationStore
{
    public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<RevocationRecord?> GetByCapabilityIdAsync(string capabilityId, CancellationToken cancellationToken = default) => Task.FromResult<RevocationRecord?>(null);
    public Task DeleteAsync(string capabilityId, CancellationToken cancellationToken = default) => Task.CompletedTask;
}
```

ASP.NET adapter registration:

```csharp
builder.Services.AddZcapRevocationSupport<SqlRevocationStore>();
```

### Strategy C: Smart Contract / Oracle Bridge

Use a store implementation that calls your on-chain contract or oracle gateway:

```csharp
builder.Services.AddZcapRevocationSupport(sp =>
    new OnChainRevocationStore(/* contract client, signer, config */));
```

### Strategy D: Hybrid (Cache + Durable Store)

Implement `IRevocationStore` as a composite:

- Read-through cache for `GetByCapabilityIdAsync`
- Durable write-through in `UpsertAsync`
- Coordinated delete/expiration cleanup

## 4. ValidWhileTrue Caveat (Remote Revocation)

The `ValidWhileTrue` caveat (per the W3C ZCAP-LD spec) enables remote revocation by embedding a URI in the capability. At verification time, the verifier checks the URI to confirm the capability is still valid. The delegator/controller hosts the endpoint — not the verifier.

### Controller Side

The controller hosts the revocation status endpoint and attaches a `ValidWhileTrue` caveat when delegating:

```csharp
builder.Services.AddZcapRevocationSupport<MyStore>();
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

To revoke, the controller POSTs to their own revocation endpoint. All verifiers checking the URI will see the updated status.

### Verifier Side

The verifier registers the `ValidWhileTrue` handler so that `CaveatProcessor` can check the URI during verification:

```csharp
builder.Services.AddZcapValidWhileTrueSupport(); // registers HttpValidWhileTrueHandler
builder.Services.AddZcapServices();

// Optional: configure timeouts/retry for the named HttpClient
builder.Services.AddHttpClient("ZcapValidWhileTrue", client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});
```

When a `ValidWhileTrue` caveat is encountered during verification, the handler GETs the URI and checks the `IsRevoked` field in the `RevocationStatusHttpResponse`. Without a handler configured, the caveat fails closed (denies access).

### Custom Handlers

You can provide a custom `IValidWhileTrueHandler` instead of the default HTTP handler:

```csharp
// Generic type registration
builder.Services.AddZcapValidWhileTrueSupport<MyCustomHandler>();

// Factory registration
builder.Services.AddZcapValidWhileTrueSupport(sp =>
    new MyCustomHandler(sp.GetRequiredService<IMyDependency>()));
```

### Attenuation Rules

When delegating a capability that contains a `ValidWhileTrue` caveat, the child capability must use the same URI as the parent. This prevents a delegatee from bypassing revocation by redirecting the check to a different endpoint.

## Operational Notes

- `VerificationService` checks revocation during proof, chain, and invocation verification.
- `RevocationService` treats expired revocation records as inactive and deletes them on read.
- For production, implement authorization policy in your endpoint/service boundary to validate who is allowed to revoke.
