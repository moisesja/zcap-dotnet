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

Revoke a capability:

```bash
curl -X POST "http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345" \
  -H "Content-Type: application/json" \
  -d '{
    "revokerDid": "did:key:z6MkDemo",
    "rootCapabilityId": "urn:zcap:root:https%3A%2F%2Fapi.example.com%2Fresource",
    "expiresAt": "2026-06-01T00:00:00Z",
    "reason": "credential compromised",
    "metadata": {
      "ticket": "SEC-741"
    }
  }'
```

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
