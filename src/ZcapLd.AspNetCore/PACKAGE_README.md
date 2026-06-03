# ZcapLd.AspNetCore

Optional ASP.NET Core adapter for `ZcapLd.Core` revocation and ValidWhileTrue workflows.

## Features

- Minimal API endpoint rails for revocation status and revocation requests
- ValidWhileTrue caveat support via `HttpValidWhileTrueHandler` (HTTP-based remote revocation checking)
- DI registration helpers for default and custom `IRevocationStore` backends
- Works with pluggable stores (database, contract client, oracle bridge, cache)

## Quick Start

```csharp
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddZcapRevocationSupport();

var app = builder.Build();
app.MapZcapRevocationEndpoints();
app.Run();
```

For a custom backend, register your own `IRevocationStore` implementation:

```csharp
builder.Services.AddZcapRevocationSupport<MyRevocationStore>();
```

## Setup Revocation Endpoints

`MapZcapRevocationEndpoints()` exposes:

- `POST /zcaps/revocations/{*capabilityId}` — revoke from a **signed** request (proof-of-possession).
  Body: `{ capability, signedRevocation }` (the latter from `ISigningService.SignRevocationAsync`).
  Returns `403` when unauthenticated/unauthorized. Requires `AddZcapServices()` (it resolves
  `IVerificationService`), not `AddZcapRevocationSupport()` alone.
- `GET /zcaps/revocations/{*capabilityId}`

To customize route prefix:

```csharp
app.MapZcapRevocationEndpoints("/wallet/revocations");
```

## Expose Revocation in a Different Manner

If you do not want HTTP endpoints, use `ZcapLd.Core` directly and expose `IRevocationService` via your preferred transport:

- gRPC
- worker/message-driven services
- admin CLI flows
- contract relayer/oracle processes

## Persistence Strategies for Revocation Registries

Register persistence strategy through `AddZcapRevocationSupport(...)`:

- Default in-memory:

```csharp
builder.Services.AddZcapRevocationSupport();
```

- Custom type:

```csharp
builder.Services.AddZcapRevocationSupport<MyRevocationStore>();
```

- Custom factory (for advanced composition/hybrid stores):

```csharp
builder.Services.AddZcapRevocationSupport(sp =>
    new HybridRevocationStore(/* dependencies from sp */));
```

See `docs/REVOCATION-INTEGRATION.md` for full guidance.

## ValidWhileTrue Caveat Support

Enable HTTP-based ValidWhileTrue caveat checking for verifiers:

```csharp
builder.Services.AddZcapValidWhileTrueSupport();
builder.Services.AddZcapServices();
```

This registers `HttpValidWhileTrueHandler`, which GETs the caveat URI during invocation verification and checks the `isRevoked` field from the `RevocationStatusHttpResponse`. The existing `GET /zcaps/revocations/{*capabilityId}` endpoint serves as the backend.

The named `HttpClient` (`"ZcapValidWhileTrue"`) can be configured for timeouts and retry policies:

```csharp
builder.Services.AddHttpClient("ZcapValidWhileTrue", client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});
```

Custom handler implementations can be registered via:

```csharp
builder.Services.AddZcapValidWhileTrueSupport<MyCustomHandler>();
```

## Custom Caveats (Polymorphic Serialization)

`ZcapLd.Core` ships a polymorphic `JsonConverter<Caveat>` so a `Capability.Caveat` array round-trips through derived-class fields across the signing boundary. Without this, sign-time JSON and the wire body diverge and cross-language verifiers (`zcap-py` and others) reject the signature.

In-library caveats (`ExpirationCaveat`, `UsageCountCaveat`, `ValidWhileTrueCaveat`) are pre-registered. Your own caveat types must register before any signing or verification call:

```csharp
public sealed class TenantCaveat : Caveat
{
    public override string Type => "Tenant";

    [JsonPropertyName("tenantId")]
    public string TenantId { get; set; } = string.Empty;

    public override bool IsSatisfied(InvocationContext ctx)
        => ctx.Properties.TryGetValue("tenantId", out var v)
           && v is string s && s == TenantId;
}

builder.Services.AddZcapCaveatType<TenantCaveat>("Tenant");
```

The discriminator string must equal the caveat's `Type` override. Mark mutable runtime state (counters, last-seen timestamps, etc.) `[JsonIgnore]` — only the policy goes on the wire; otherwise mutation invalidates the signature.
