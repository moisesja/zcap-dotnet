# ZcapLd.RevocationEndpointsDemo

Demonstration of `ZcapLd.AspNetCore` revocation endpoints backed by a SQLite store.

## Run

```bash
dotnet run --project examples/ZcapLd.RevocationEndpointsDemo/ZcapLd.RevocationEndpointsDemo.csproj --urls http://localhost:5099
```

## Endpoints

- `POST /zcaps/revocations/{url-encoded-capability-id}`
- `GET /zcaps/revocations/{url-encoded-capability-id}`

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

Check status:

```bash
curl "http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345"
```

## ValidWhileTrue Caveat Support

This demo also serves as the backend for `ValidWhileTrue` caveats. When a delegator creates a capability with a `ValidWhileTrue` caveat, the URI points to the `GET` endpoint above. At verification time, a verifier with `AddZcapValidWhileTrueSupport()` configured will automatically check this URI.

Example caveat in a delegated capability:

```json
{
  "type": "ValidWhileTrue",
  "uri": "http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345"
}
```

The verifier's `HttpValidWhileTrueHandler` GETs the URI and checks the `isRevoked` field in the response. If the capability has been revoked (via the `POST` endpoint), the caveat check fails and the invocation is denied.

## SQLite File Location

By default the demo uses:

- `examples/ZcapLd.RevocationEndpointsDemo/revocations-demo.db`

Override path:

```bash
Revocation__SqlitePath=/absolute/path/revocations.db dotnet run --project examples/ZcapLd.RevocationEndpointsDemo/ZcapLd.RevocationEndpointsDemo.csproj --urls http://localhost:5099
```
