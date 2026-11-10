# ZcapLd.RevocationEndpointsDemo

An ASP.NET host that exposes the `ZcapLd.AspNetCore` signed-revocation endpoint, backed by a SQLite
store, next to one protected resource, so a revocation can be seen taking effect.

## Walkthrough

```bash
dotnet run --project examples/ZcapLd.RevocationEndpointsDemo -- --walkthrough
```

This starts the host, provisions a root, drives the real HTTP endpoints through four steps, prints every
request body and response, and exits non-zero if any step returns an unexpected status:

| step | request | expected |
|---|---|---|
| 1 | The agent reads the report with a DI-secured invocation of its delegated capability | `200` |
| 2 | A stranger (a real key with no place in the chain) signs and posts a revocation of that capability | `403`, nothing recorded |
| 3 | The owner (controller of the root, the capability's parent) signs and posts the same revocation | `200` |
| 4 | The agent reads again with a freshly signed invocation | `403` with `{"outcome":"Revoked"}` |

Step 4 is the point of the model: revocation is recorded at the verifier responsible for the target and
checked where access is enforced. Nothing is sent to the holder, and everything delegated below a revoked
link is revoked with it.

Provisioning happens in `RevocationWalkthrough.ProvisionAsync`: it generates three `did:key`s with the
demo keyring, creates the root for `https://demo.example/documents/report` with `read`, delegates `read`
to the agent for a day, and registers the root with the server's `InMemoryRootCapabilityResolver`. That is
trusted startup code standing in for "the resource owner provisions its root". It is never request input.

Without `--walkthrough`, `dotnet run` serves the endpoints with **no root registered**, so it accepts no
revocation and no invocation until one is provisioned. That is deliberate: a spec-exact delegation chain
names its root by id only (#50), the server must resolve it from its own store, and a root revocation is
authorized against the resolved root (#155). A root taken from a request could name an attacker-chosen
controller, so there is no root-registration endpoint either. A production resource server implements
`IRootCapabilityResolver` over the roots it issues.

`dotnet run` uses `Properties/launchSettings.json`: `http://localhost:5099`, environment `Development`.
The launch profile wins over an ambient `ASPNETCORE_ENVIRONMENT`, so `dotnet run` is always `Development`
(denial reasons disclosed, `ZcapLd` logged at `Debug`). To serve as any other environment, run with
`--no-launch-profile` or run the published `dotnet ZcapLd.RevocationEndpointsDemo.dll`, which defaults to
`Production`.

## Endpoints

- `POST /zcaps/revocations/{url-encoded-capability-id}`: the signed revocation endpoint from
  `ZcapLd.AspNetCore` (`MapZcapRevocationEndpoints`). `200` with `{capabilityId, isRevoked: true}` (the other
  `RevocationStatusHttpResponse` fields are serialized as `null`) when the revocation is recorded; `403` when the request is unauthenticated (bad or forged signature) or
  unauthorized (the signer controls no link in the chain), recording nothing; `400` when the route id
  disagrees with the body's capability id; `413` above 1 MB.
- `POST /documents/report`: the protected resource. The body is a DI-secured application document, a JSON
  object carrying a `capabilityInvocation` proof that embeds the delegated capability. It is verified with
  `VerifyCapabilityInvocationDetailedAsync(document, "read", "https://demo.example/documents/report")`:
  the expected action and target come from the server, never from the document. `200` with a small
  payload, otherwise `403`. In `Development` the `403` body is `{"outcome":"<VerificationOutcome>"}`; in
  any other environment it is empty, because the reason tells an attacker which check failed.
- `GET /` and `GET /health`: description and liveness.

There is no status GET. The ZCAP specification and the Digital Bazaar reference stack define only the
POST, and a bare id has no single status once records are scoped to the delegator that signed the
capability (#158). Holders learn of revocation from a `Revoked` verification outcome.

`{url-encoded-capability-id}` is `encodeURIComponent(capabilityId)`, decoded exactly once by the
endpoint. A root id already contains escapes, so it is encoded twice in the URL:

| capability id | request path |
|---|---|
| `urn:uuid:12345` | `/zcaps/revocations/urn%3Auuid%3A12345` |
| `urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource` | `/zcaps/revocations/urn%3Azcap%3Aroot%3Ahttps%253A%252F%252Fexample.com%252Fresource` |

Revoking a root over `POST` requires that root to be registered with the host's
`IRootCapabilityResolver`; the body's copy of the root is never trusted for authorization.

## The revocation request

Revocation requires **proof of possession**; there is no bare-`revokerDid` path. The body carries the full
capability being revoked plus a revocation request signed by a key that controls the capability or an
ancestor, produced by `ISigningService.SignRevocationAsync(capabilityId, signerDid, invocationTarget, reason?, metadata?)`.
This is what the walkthrough sends in step 3 (throwaway keys and ids):

```jsonc
// signed-revocation.json
{
  "capability": { /* the full delegated capability: @context, id, controller, invocationTarget,
                     allowedAction, expires, parentCapability and its proof with capabilityChain */ },
  "signedRevocation": {
    "id": "urn:uuid:45df7276-960a-4823-bbe4-4e498b714259",
    "capability": "urn:uuid:c9c3043e-cea6-412e-a73a-29ef69930a95",
    "capabilityAction": "revoke",
    "invocationTarget": "https://demo.example/documents/report",
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2026-11-10T03:17:19.781704Z",
      "proofPurpose": "capabilityRevocation",
      "verificationMethod": "did:key:z6MkiiX2DJ1PyaY8MQw8RzgBcfMXKXkxpq3N4P7aXY4YtK9W#z6MkiiX2DJ1PyaY8MQw8RzgBcfMXKXkxpq3N4P7aXY4YtK9W",
      "proofValue": "z4Po1zA6w2KXP8RT4n5bEmXiBSx6pQBjbMJVA4CE4kagvt2TA1gvU2CJKsuA8M95yxMyiEGPCJm6ycpHa2MxkYSKD",
      "capability": "urn:uuid:c9c3043e-cea6-412e-a73a-29ef69930a95",
      "invocationTarget": "https://demo.example/documents/report",
      "capabilityAction": "revoke",
      "revocationReason": "access withdrawn"
    }
  }
}
```

The verifier requires every field shown. The proof's `capability`, `capabilityAction` and
`invocationTarget` must equal the body's, and `created` is checked for freshness: five minutes by default,
no more than one minute in the future. A request written by hand, or generated once and pasted in, goes
stale; the walkthrough signs each one just before sending it. `revocationReason` is signed but
informational.

```bash
curl -X POST "http://localhost:5099/zcaps/revocations/urn%3Auuid%3Ac9c3043e-cea6-412e-a73a-29ef69930a95" \
  -H "Content-Type: application/json" \
  --data @signed-revocation.json
```

The invocation body for `POST /documents/report` is the `JsonObject` returned by
`SigningService.SignCapabilityInvocationAsync(InvocationCapability.FromCapability(delegated), "read", target, agentDid)`,
serialized with `ZcapJsonOptions.Default`. The walkthrough prints one in step 1. Each invocation must be
freshly signed: the verifier consumes the proof's nonce, so a replayed document is refused.

## Seeing why a request got 403

The library logs an expected denial (bad signature, unknown root, unauthorized signer, revoked, stale
proof) at `Debug`, because a hostile client can trigger every one of them at will. `appsettings.Development.json`
raises `ZcapLd` to `Debug`, so in `Development` the console shows the reason, for example in step 2:

```
dbug: ZcapLd.Core.Services.VerificationService[0]
      Verification method not authorized by controller 'did:key:z6Mk…' for CapabilityDelegation.
```

Infrastructure faults (`CouldNotVerify`) log at `Warning` in every environment.

## Keys

`DemoKeyring` is a demo-only `IDidSigner`: Ed25519 private keys in plaintext memory behind real
`did:key:z6Mk…` identifiers. It only signs; the server resolves `did:key` with the library's
`DidKeyResolver` and never sees the keyring. A production signer wraps an HSM, a cloud KMS or a key vault.

## Shared revocation state

This demo submits signed revocations to the target verifier and persists them in SQLite
(`revocations-demo.db` in the project directory, or `Revocation:SqlitePath`). It does not poll
capability-supplied URLs. All production verifier replicas must share authoritative revocation state. See
the repository revocation guide for multi-verifier deployment considerations.

Records are keyed by the capability id **and** the delegator that signed it (the controller of the
delegation proof's verification method), as `bedrock-zcap-storage` keys them; a root is keyed as a
root. A forged copy of an id under another chain is signed by someone else and lands in that
signer's scope, where no genuine chain looks, so sharing this host or its database between root
owners no longer lets one revoke the other's capabilities. `SqliteRevocationStore` keys rows by the
record's opaque digest (`revocation_key`) and, at startup, migrates a pre-6.0 `revocation_registry`
table into unscoped records, which every chain honours as before. See
[Revocation scope](../../architecture.md#revocation-scope).
