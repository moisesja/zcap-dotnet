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
- `GET /zcaps/revocations/{*capabilityId}` — anonymous status: `{ capabilityId, isRevoked }`.

`{*capabilityId}` is `encodeURIComponent(capabilityId)`: one level of percent-encoding, which the
endpoint decodes exactly once (`Uri.EscapeDataString` output is accepted too). A root id already
contains escapes (`urn:zcap:root:https%3A%2F%2F…`), so it appears encoded twice in the URL; that is
correct. The id is read from the raw request target, so an id containing `/` is unambiguous on
Kestrel. The in-memory `TestServer` exposes no raw target; there the endpoint falls back to the route
value, in which an encoded `/` (`%2F`) stays encoded — send such ids with literal slashes on that host.
Intermediaries must forward the request target byte-for-byte: a proxy that decodes and re-encodes
the path turns `%2541` into `%41` and reintroduces the double decode.

Revoking a root over `POST` authorizes against the root the configured `IRootCapabilityResolver`
returns for that id, never the body's copy, so a root the server cannot resolve is not revocable.
Other ids are not anchored: records are keyed by bare capability id, so anyone with a valid chain
under any trusted root can force-revoke non-root ids, including delegated ids under other roots.
Do not share a host or revocation store between parties that must not be able to revoke each
other's capabilities. See [Revocation scope](https://github.com/moisesja/zcap-dotnet/blob/main/architecture.md#revocation-scope-known-limitation).

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
Without registered caveat types, incoming `caveat` fields are rejected. Version 6
restores `AddZcapCaveatType<T>(type)` for the opt-in caveat extension profile (#157).
Add `AddZcapCaveatHandler<T>()` for each type the resource enforces, and register both
before the ZCAP services are first resolved:

```csharp
builder.Services.AddZcapServices();
builder.Services.AddZcapCaveatType<EpsilonBudgetCaveat>("EpsilonBudget");
builder.Services.AddZcapCaveatHandler<EpsilonBudgetLedger>();
```

The revocation endpoint accepts caveat-bearing capabilities whose types are registered.
`AddZcapValidWhileTrueSupport` stays removed: no capability-supplied URL is fetched.
Submit signed revocations to the target verifier and use shared durable revocation state
across replicas.
