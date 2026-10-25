# ZcapLd.AspNetCore

Optional ASP.NET Core adapter for `ZcapLd.Core` signed revocation workflows.

## Features

- Minimal API endpoint rails for revocation status and revocation requests
- DI registration helpers for default and custom `IRevocationStore` backends
- Works with pluggable stores (database, contract client, oracle bridge, cache)

## Quick Start

```csharp
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddZcapServices();
builder.Services.AddZcapRevocationSupport();
// Configure an IRootCapabilityResolver for delegated-capability revocation.

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

## Target restrictions

Using `ZcapLd.Core.Services`, register `VerificationPolicy` before `AddZcapServices()` to permit target narrowing:

```csharp
builder.Services.AddSingleton(new VerificationPolicy { AllowTargetAttenuation = true });
builder.Services.AddZcapServices();
```

The default requires exact target matches. Applications enforce path/query semantics.
Version 5 removes `AddZcapValidWhileTrueSupport`, `AddZcapCaveatType`, and all
vocabulary caveat processing. Incoming `caveat` fields are rejected. Submit signed
revocations to the target verifier and use shared durable revocation state across replicas.
