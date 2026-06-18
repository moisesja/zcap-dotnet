# ZCAP-LD JS interop harness

A Node.js harness built on the **real** [`@digitalbazaar/zcap`](https://github.com/digitalbazaar/zcap)
v9 reference library. It generates and verifies ZCAP-LD **delegated
capabilities** (capability **delegation** proofs only — *not* invocations) so we
can prove cross-stack interop with the `zcap-dotnet` .NET implementation.

## Files

| File          | Purpose                                                                 |
| ------------- | ----------------------------------------------------------------------- |
| `lib.mjs`     | Shared helpers: deterministic did:key derivation, documentLoader, `verifyDelegation`. |
| `gen.mjs`     | Generates a deterministic root + single-level delegated capability into `../vectors/`. |
| `verify.mjs`  | `node verify.mjs <delegatedFile> <rootFile>` → prints `PASS`/`FAIL`, exit 0/1. |

## Setup

```bash
npm install
```

Node v23.7.0, npm 10.9.2. All dependency versions are pinned (exact) in
`package.json`.

## Self-test (proves the recipe)

```bash
npm run selftest
# == node gen.mjs && node verify.mjs ../vectors/js-delegated.json ../vectors/js-root.json
```

Expected output ends with:

```
PASS
```

Individually:

```bash
node gen.mjs                                                  # writes ../vectors/js-root.json + js-delegated.json
node verify.mjs ../vectors/js-delegated.json ../vectors/js-root.json   # -> PASS, exit 0
```

## Negative control (tamper → FAIL)

Mutating any signed field (e.g. `allowedAction`) breaks the Ed25519 signature,
so verification must `FAIL` with exit code 1:

```bash
node gen.mjs
node -e "const fs=require('node:fs');const d=JSON.parse(fs.readFileSync('../vectors/js-delegated.json','utf8'));d.allowedAction=['read','write'];fs.writeFileSync('/tmp/js-delegated-tampered.json',JSON.stringify(d,null,2));"
node verify.mjs /tmp/js-delegated-tampered.json ../vectors/js-root.json
```

Expected output:

```
FAIL
{
  "name": "VerificationError",
  "message": "Verification error(s).",
  "errors": [
    {
      "name": "Error",
      "message": "Invalid signature."
    }
  ]
}
```

## Cross-stack contract

`verify.mjs` accepts a delegated capability in exactly the JSON shape
`zcap-dotnet` emits, given the matching root file:

- **Root** (`js-root.json`) — single-string `@context: "https://w3id.org/zcap/v1"`,
  `id: urn:zcap:root:<encodeURIComponent(invocationTarget)>`, `controller`,
  `invocationTarget`. Registered in the documentLoader by its `id`.
- **Delegated** — `@context: ["https://w3id.org/zcap/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1"]`, `id` (`urn:uuid:…`),
  `controller` (delegate did:key), `invocationTarget`, `allowedAction`,
  `expires`, `parentCapability` (root id), and an `Ed25519Signature2020`
  `proof` with `proofPurpose: capabilityDelegation`,
  `verificationMethod: did:key:…#…` (the **root** controller key),
  `capabilityChain: [rootId]`, and `proofValue: z…`.

Verification works purely from the JSON + did:key resolution — no
digitalbazaar-internal key objects need be present. JSON key ordering inside the
`proof` is irrelevant (JSON-LD canonicalizes before hashing), so the .NET
emitter's field order verifies identically.

Keys are deterministic: root controller seed = 32×`0x01`, delegate seed =
32×`0x02`. Matching keys across stacks is **not** required — each stack signs its
own vectors with its own keys.
