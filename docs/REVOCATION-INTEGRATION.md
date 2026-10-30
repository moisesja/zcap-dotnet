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
// registers only the store + service.
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

There is no status GET. The ZCAP specification and the Digital Bazaar reference stack define only
the POST, and once records are scoped to the delegator that signed a capability (#158) a bare id
has no single status. Holders learn of revocation from a `Revoked` verification outcome. If you
need status queries, expose `IRevocationService.IsRevokedAsync(id, scope)` behind your own
authorization, with the scope the caller is entitled to ask about.

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
`controller` is never trusted. A root the server cannot resolve is not revocable. A delegated
capability is recorded under the delegator that signed it; see "Revocation scope" below.

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

    // Operator revocation of a capability the host has already authenticated out of band. The
    // scope is the delegator that signed the capability's delegation proof (#158); for a root use
    // RevocationScope.Root. RevocationScope.Unscoped revokes the id on EVERY chain, which is the 5.x
    // behaviour and is appropriate only for an id the operator knows to be unique.
    public Task<RevocationRecord> RevokeAsync(Capability capability, string revokerDid, DateTime? expiresAt)
    {
        return _revocationService.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capability.Id,
            Scope = capability.Proof is null
                ? RevocationScope.Root
                : RevocationScope.ForDelegationProof(capability.Proof.Primary),
            RevokedBy = revokerDid,
            ExpiresAt = expiresAt
        });
    }

    public Task<bool> IsRevokedAsync(Capability capability)
    {
        return _revocationService.IsRevokedAsync(
            capability.Id,
            capability.Proof is null ? RevocationScope.Root : RevocationScope.ForDelegationProof(capability.Proof.Primary));
    }
}
```

A record is keyed by `RevocationRecord.Key`, an opaque digest of the id and its scope. Two records for
one id in different scopes are distinct; a lookup in a scope also sees the id's unscoped record.

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

Implement `IRevocationStore` and register it. The contract (#158):

- The primary key is `RevocationRecord.Key`, a 64-character lowercase hex digest of the capability
  id and its `RevocationScope`. **Never** key, merge or look rows up by the capability id: two
  records for one id in different scopes are distinct rows, and a primary key on the id would let
  a record written under an attacker's scope overwrite a legitimate one. Keys are fixed-width hex,
  so collation does not matter, but compare them exactly.
- Persist every field, including `Scope` (its text form, `RevocationScope.ToString()` /
  `RevocationScope.Parse`), and return records unchanged. `RevocationService` refuses a returned
  record whose key it did not request or whose stored id and scope disagree with its key, and reads
  each record back after writing it, so a store that drops or rewrites the scope fails verification
  closed instead of widening a revocation.
- `GetAsync(keys)` returns the records stored under any of the given keys (a few dozen at most,
  two per chain link); `DeleteAsync(key)` removes one row.
- Upgrading from 5.x: migrate each bare-id row to a record with `Scope = RevocationScope.Unscoped`
  and `Key = RevocationScope.Unscoped.KeyFor(capabilityId)`. Unscoped records apply to their id on
  every chain, so recorded revocations keep working; new signed revocations are always scoped.
  `examples/ZcapLd.RevocationEndpointsDemo/SqliteRevocationStore.cs` shows the schema and a
  one-time migration.

```csharp
public sealed class SqlRevocationStore : IRevocationStore
{
    public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
        => Task.CompletedTask; // INSERT … ON CONFLICT (revocation_key) DO UPDATE, with record.Key, record.Scope.ToString(), …

    public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<RevocationRecord>>([]); // SELECT … WHERE revocation_key IN (…), Scope = RevocationScope.Parse(row.scope)

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
        => Task.CompletedTask; // DELETE … WHERE revocation_key = key
}
```

The contract tests in `tests/ZcapLd.AspNetCore.Tests/RevocationStoreContractTests.cs` run against
the in-memory and SQLite stores; run them against yours.

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

- Read-through cache for `GetAsync`, keyed by record key
- Durable write-through in `UpsertAsync` (the service reads the key back immediately, so the
  cache must not serve a stale miss for a key just written)
- Coordinated delete/expiration cleanup by exact key

## 4. Revocation across verifier instances

Submit a signed revocation request and the capability's delegation chain to the
revocation endpoint of the verifier responsible for its invocation target. The POST
authenticates the signer and checks control of the capability or an ancestor before
recording revocation. An ancestor revocation invalidates descendant chains.
Retain revocation records until the affected capability expires.

There is no status endpoint and no capability-specified policy oracle. Version 5 removed
the `ValidWhileTrue` model, HTTP handler and DI registrations (the old URI was not
signature-bound under the bundled context and could be redirected by a holder; SSRF
protections did not establish its integrity), and version 6 removes the anonymous status
GET, which the specification and the reference stack never defined.

All replicas that authorize the same target must consult authoritative revocation
state, through a shared `IRevocationStore` or an explicitly configured trusted
revocation service. Account for cache invalidation and fail-closed behavior during
store outages. Short expirations can bound exposure but do not provide immediate
revocation.

### Revocation scope

Records are keyed by the capability id **and** a scope (#158), as `bedrock-zcap-storage`
keys them by `(delegator, capability.id)`: a delegated capability under the delegator that
signed it (the DID of its delegation proof's verification method), a root as a root, and
migrated 5.x or operator records unscoped. A forged copy of an id under another chain is
signed by the forger and lands in the forger's scope, where no genuine chain looks, so
sharing a verifier or a store between root owners no longer lets one revoke the other's
capabilities. Verifiers that share a store must still agree on what each root id means and
resolve DIDs the same way. See [Revocation scope](../architecture.md#revocation-scope).

For delegation involving independently operated verifiers, the deployment must
agree on who owns revocation state and how updates reach every verifier. Neither
the endpoint model nor path/query attenuation discovers unknown verifiers or
automatically distributes revocations. Do not reintroduce arbitrary holder-supplied
URLs as trusted revocation policy.

## Operational Notes

- `VerificationService` checks revocation during proof, chain, and invocation verification, after
  each link's delegation proof verifies and under that proof's delegator.
- `RevocationService` treats expired revocation records as inactive and deletes them on read, by
  exact key.
- For production, implement authorization policy in your endpoint/service boundary to validate who is allowed to revoke.

### Security note — `reason`/`metadata` are signed but informational (6.0.0)

From 4.0.0 to 5.x, RDFC-1.0 dropped the `reason`/`metadata` you pass to `SignRevocationAsync` from
the signature, because no served context defined them. Since 6.0.0 the library canonicalizes every
revocation request under its own revocation context (`urn:zcap-dotnet:revocation-context:v1`), which
defines them and the `capabilityRevocation` purpose. Editing either one now invalidates the request.

They are still informational: they are recorded on the `RevocationRecord` for audit, and never
decide authorization. Authorization rests on the bound capability (`capability`), the `revoke`
action (`capabilityAction`), the `invocationTarget` and the revoker's identity, authenticated by key
possession (`RevokedBy` is the verification method that signed the request, never client-asserted).
Revocation requests signed by 5.x do not verify under 6.0, and vice versa.
