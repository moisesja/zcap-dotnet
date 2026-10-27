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

// The POST (revoke) endpoint authenticates + authorizes a SIGNED revocation request via
// IVerificationService, so register the full service graph. AddZcapRevocationSupport() alone
// (store + service only) is sufficient only for a GET-status-only deployment.
builder.Services.AddZcapServices();
// Optionally override the in-memory store, e.g. AddZcapRevocationSupport(_ => new MyStore(...));

var app = builder.Build();

// Default route prefix: /zcaps/revocations
app.MapZcapRevocationEndpoints();
// Or custom prefix:
// app.MapZcapRevocationEndpoints("/wallet/revocations");

app.Run();
```

Default endpoint contract:

- `POST /zcaps/revocations/{*capabilityId}`: revoke from a **signed** request (proof-of-possession).
  Body: `{ "capability": <the full capability being revoked>, "signedRevocation": <an Invocation
  signed via ISigningService.SignRevocationAsync> }`. The endpoint verifies the signature
  (authentication) and that the signer controls the capability or an ancestor (authorization).
  Returns `200` on success, `403` when unauthenticated/unauthorized, `400` on a malformed body or a
  route/body capability-id mismatch. There is **no** bare-`revokerDid` path.
- `GET /zcaps/revocations/{*capabilityId}`: query revocation status; anonymous, returns only
  `{ capabilityId, isRevoked }`.

`{*capabilityId}` is `encodeURIComponent(capabilityId)`, one level of percent-encoding that the
endpoint decodes exactly once. A root id already contains escapes (`urn:zcap:root:https%3A%2F%2F…`),
so it is encoded twice in the URL; that is correct and the endpoint echoes the exact id back. The id
is recovered from the raw request target (Kestrel populates it), so ids containing `/` are
unambiguous. On a host without a raw target (the in-memory `TestServer`) the endpoint falls back to
the route value, in which an encoded `/` stays `%2F`; send such ids with literal slashes there.
Intermediaries must forward the request target byte-for-byte: a proxy that decodes and re-encodes
the path turns `%2541` into `%41` and reintroduces the double decode.

Revoking a root over `POST` authorizes against the root the server's `IRootCapabilityResolver`
returns for that id, never the body's copy: a root-only chain has no delegation proof, so the body's
`controller` is never trusted. A root the server cannot resolve is not revocable.

Runnable demo:

- `examples/ZcapLd.RevocationEndpointsDemo/README.md`

## 2. Expose Revocation in Other Ways

> **Security:** `IRevocationService.RevokeAsync` is the **persistence primitive** — it performs **no
> authentication or authorization** and records whatever it is given. Never call it directly from
> untrusted input. To enforce proof-of-possession + chain authorization, route requests through
> `IVerificationService.RevokeCapabilityAsync(Capability, Invocation)` (build the signed request with
> `ISigningService.SignRevocationAsync`). The example below is for a host that has **already**
> authenticated and authorized the caller out-of-band.

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

## 4. Revocation across verifier instances

Submit a signed revocation request and the capability's delegation chain to the
revocation endpoint of the verifier responsible for its invocation target. The POST
authenticates the signer and checks control of the capability or an ancestor before
recording revocation. An ancestor revocation invalidates descendant chains.
Retain revocation records until the affected capability expires.

The built-in GET endpoint exposes only `capabilityId` and `isRevoked`. It is a
status API, not a capability-specified policy oracle. Version 5 removes the
`ValidWhileTrue` model, HTTP handler and DI registrations. The old URI was not
signature-bound under the bundled context and could be redirected by a holder.
SSRF protections did not establish the integrity of that URI.

All replicas that authorize the same target must consult authoritative revocation
state, through a shared `IRevocationStore` or an explicitly configured trusted
revocation service. Account for cache invalidation and fail-closed behavior during
store outages. Short expirations can bound exposure but do not provide immediate
revocation.

For delegation involving independently operated verifiers, the deployment must
agree on who owns revocation state and how updates reach every verifier. Neither
the endpoint model nor path/query attenuation discovers unknown verifiers or
automatically distributes revocations. Do not reintroduce arbitrary holder-supplied
URLs as trusted revocation policy.

## Operational Notes

- `VerificationService` checks revocation during proof, chain, and invocation verification.
- `RevocationService` treats expired revocation records as inactive and deletes them on read.
- For production, implement authorization policy in your endpoint/service boundary to validate who is allowed to revoke.

### Security note — `reason`/`metadata` are informational, not tamper-evident (4.0.0)

As of 4.0.0 zcap signs proofs with RDFC-1.0 only. RDFC drops JSON-LD terms that are not defined in a
served context from the canonical N-Quads, and the free-form `reason`/`metadata` you pass to
`SignRevocationAsync` are not zcap-context terms — so they are **not covered by the signature**. They
are recorded on the `RevocationRecord` for audit, but an actor who already holds a validly-signed
revocation request can alter them without invalidating it.

What **is** cryptographically bound and cannot be forged or altered: the capability being revoked
(`capability`), the `revoke` action (`capabilityAction`), the `invocationTarget`, and the revoker's
identity (authenticated by key possession; `RevokedBy` is the verification method that signed the
request, never client-asserted). A revocation therefore cannot be forged, retargeted to a different
capability, or attributed to another party — only the human-readable note is unbound. If you need
`reason`/`metadata` to be tamper-evident, do not rely on the proof for it (e.g. record them in an
authenticated server-side audit log). (Pre-4.0.0 JCS builds did bind these fields.)
