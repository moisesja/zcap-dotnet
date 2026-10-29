# ZcapLd.RevocationEndpointsDemo

Demonstration of `ZcapLd.AspNetCore` revocation endpoints backed by a SQLite store.

## Run

```bash
dotnet run --project examples/ZcapLd.RevocationEndpointsDemo/ZcapLd.RevocationEndpointsDemo.csproj --urls http://localhost:5099
```

## Endpoints

- `POST /zcaps/revocations/{url-encoded-capability-id}`

There is no status GET. The ZCAP specification and the Digital Bazaar reference stack define only
the POST, and a bare id has no single status once records are scoped to the delegator that signed
the capability (#158). Holders learn of revocation from a `Revoked` verification outcome.

`{url-encoded-capability-id}` is `encodeURIComponent(capabilityId)`, decoded exactly once by the
endpoint. A root id already contains escapes, so it is encoded twice in the URL:

| capability id | request path |
|---|---|
| `urn:uuid:12345` | `/zcaps/revocations/urn%3Auuid%3A12345` |
| `urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource` | `/zcaps/revocations/urn%3Azcap%3Aroot%3Ahttps%253A%252F%252Fexample.com%252Fresource` |

Revoking a root over `POST` requires that root to be registered with the host's
`IRootCapabilityResolver`; the body's copy of the root is never trusted for authorization.

## Example Requests

Revocation requires **proof of possession** — there is no bare-`revokerDid` path. The body carries the
full capability being revoked plus a revocation request signed by a key that controls the capability
(or an ancestor), produced by `ISigningService.SignRevocationAsync(...)`:

```jsonc
// signed-revocation.json
{
  "capability": { /* the full delegated capability, including its proof + capabilityChain */ },
  "signedRevocation": {
    "id": "urn:uuid:…",
    "capability": "urn:uuid:12345",
    "capabilityAction": "revoke",
    "invocationTarget": "https://api.example.com/resource",
    "proof": {
      "type": "Ed25519Signature2020",
      "proofPurpose": "capabilityRevocation",
      "verificationMethod": "did:key:z6Mk…#z6Mk…",
      "proofValue": "z…",
      "revocationReason": "credential compromised"
    }
  }
}
```

```bash
curl -X POST "http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345" \
  -H "Content-Type: application/json" \
  --data @signed-revocation.json
```

A request that is unauthenticated (bad/forged signature) or unauthorized (the signer controls no link
in the chain) returns **403** and records nothing. A route id that disagrees with the body capability id
returns **400**.

### Root resolution (required for delegated revocation)

Authorizing the revocation of a **delegated** capability verifies its delegation chain, and a
spec-exact chain references the root **by id only** (Issue #50). The server must therefore resolve that
root — it is never trusted from the request body, since a client-supplied root could name an
attacker-chosen controller. This demo registers an in-memory resolver
(`AddZcapRootCapabilityResolver<InMemoryRootCapabilityResolver>()`); you must **seed the roots** you
will accept delegated revocations against, otherwise those requests fail closed with **403**:

```csharp
// At startup (the resource owner knows its own roots):
var roots = (InMemoryRootCapabilityResolver)app.Services.GetRequiredService<IRootCapabilityResolver>();
roots.Register(root); // a Capability created via CreateRootCapabilityAsync
```

A production resource server implements `IRootCapabilityResolver` over its own root store. Revoking a
**root** capability needs it too: the root is authorized against the resolver's copy, never the
body's (Issue #155). The `ZcapLd.AspNetCore.Tests` integration tests exercise the full
delegated-revocation flow with a seeded resolver.

## Shared revocation state

This demo submits signed revocations to the target verifier and persists them in
SQLite. It does not poll capability-supplied URLs. All production verifier replicas
must share authoritative revocation state. See the repository revocation guide for
multi-verifier deployment considerations.

Records are keyed by the capability id **and** the delegator that signed it (the controller of the
delegation proof's verification method), as `bedrock-zcap-storage` keys them; a root is keyed as a
root. A forged copy of an id under another chain is signed by someone else and lands in that
signer's scope, where no genuine chain looks, so sharing this host or its database between root
owners no longer lets one revoke the other's capabilities. `SqliteRevocationStore` keys rows by the
record's opaque digest (`revocation_key`) and, at startup, migrates a pre-6.0 `revocation_registry`
table into unscoped records, which every chain honours as before. See
[Revocation scope](../../architecture.md#revocation-scope).
