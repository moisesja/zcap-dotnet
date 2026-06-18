# Live cross-stack interop harness (zcap-dotnet ⇄ @digitalbazaar/zcap)

This harness **proves at runtime** that zcap-dotnet's RDFC-1.0 path is wire-compatible
with the [`@digitalbazaar/zcap`](https://github.com/digitalbazaar/zcap) v9 reference
implementation (the spec authors' library) for **capability delegation proofs** — by
signing a real capability on one stack and verifying it on the other, in both
directions, including a tamper-detection negative control and a two-level chain.

It is the empirical counterpart to [`docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md`](../docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md),
which inferred RDFC byte-compatibility from decompiled internals + golden-vector
hashes. This harness replaces inference with an actual `@digitalbazaar/zcap`
`verify()` accepting (and rejecting) zcap-dotnet artifacts.

## What it proves

| # | Check | Expected |
|---|---|---|
| 1 | **Outbound** — zcap-dotnet signs (RDFC-1.0) → `@digitalbazaar/zcap` verifies | PASS |
| 2 | **Inbound** — `@digitalbazaar/zcap` signs → zcap-dotnet verifies (RDFC-1.0) | PASS |
| 3 | **Negative (outbound)** — tampered `allowedAction` on a dotnet zcap → db rejects | FAIL |
| 4 | **Negative (inbound)** — tampered `allowedAction` on a db zcap → dotnet rejects | FAIL |
| 5 | **Multi-level outbound** — dotnet 2-level chain `[rootId, {parent}]` → db verifies | PASS |
| 6 | **Multi-level inbound** — db 2-level chain → dotnet verifies | PASS |

## Scope

- **In scope:** capability **delegation** proofs (`proofPurpose: capabilityDelegation`),
  Ed25519Signature2020 over RDFC-1.0, did:key controllers. This is the dominant
  interop path (the canonicalization blocker, #1 in the analysis report).
- **Out of scope:** **invocations**. zcap-dotnet signs a self-contained
  `{id, capability, capabilityAction, invocationTarget}` envelope as the document,
  whereas digitalbazaar signs an arbitrary application payload with the invocation
  metadata only in the proof — a structural mismatch (blocker #2) independent of
  canonicalization. Not exercised here.
- The default zcap-dotnet canonicalization is **JCS**, which is *not* interoperable;
  this harness explicitly uses **RDFC-1.0** on both the signer and verifier. The
  takeaway: RDFC-1.0 is the interop mode.

## Run it

```bash
interop/run-interop.sh
```

Requires the .NET 10 SDK and Node.js (tested on Node 23 / npm 10). On first run it
does `npm ci` in `js/`. Exit code is 0 iff all six checks held. Vectors are
regenerated each run with fresh expiries (so digitalbazaar's expiration check
passes) and written under `interop/vectors/` (git-ignored — they are reproducible
outputs, not source).

## In CI

An xUnit wrapper — [`tests/ZcapLd.Interop.Tests`](../tests/ZcapLd.Interop.Tests) —
shells out to `run-interop.sh`, asserts exit 0 + `ALL 6 CHECKS PASSED`, and
**skips gracefully** (`[SkippableFact]`) when `bash`/`node`/`npm`/`dotnet` are not
all on PATH (so it is a no-op on machines without Node). It is deliberately **not**
in `ZcapLd.sln`, so `dotnet test ZcapLd.sln` and the core CI never require Node.

The dedicated [`.github/workflows/ci-interop.yml`](../.github/workflows/ci-interop.yml)
job sets up .NET 10 + Node 22, runs `npm ci`, then
`dotnet test tests/ZcapLd.Interop.Tests/...`. Run the wrapper locally with:

```bash
dotnet test tests/ZcapLd.Interop.Tests/ZcapLd.Interop.Tests.csproj
```

## Layout

```
interop/
├── run-interop.sh              # one-command orchestrator (build → gen → cross-verify → report)
├── ZcapLd.Interop/             # .NET CLI (standalone, NOT in ZcapLd.sln)
│   ├── Program.cs              #   gen / gen-multi / verify subcommands (RDFC-1.0)
│   └── DeterministicDidProvider.cs  # in-harness IDidSigner/IDidResolver, deterministic did:key
├── js/                         # Node harness over the REAL @digitalbazaar/zcap v9
│   ├── lib.mjs                 #   documentLoader (zcap-v1 + ed25519-2020 contexts, did:key, root-by-id) + verifyDelegation
│   ├── gen.mjs / gen-multi.mjs #   produce single- / two-level delegated zcaps
│   └── verify.mjs              #   verify <delegated> <root> → PASS/FAIL, exit 0/1
└── vectors/                    # generated (git-ignored)
```

## Key compatibility facts established

- zcap-dotnet's **RDFC-1.0 signing input** — `SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))` —
  is byte-identical to `jsonld-signatures` / `@digitalbazaar/ed25519-signature-2020`.
- The embedded JSON-LD contexts (`zcap-v1`, `ed25519-2020/v1`) and term expansion match upstream.
- The `urn:zcap:root:{encodeURIComponent(target)}` root id and the
  `[rootId, …ancestorIds, {immediateParent}]` chain shape are accepted by digitalbazaar.
  (Plain http(s) targets only; targets containing `! ' ( ) *` hit the `Uri.EscapeDataString`
  vs `encodeURIComponent` divergence — see report blocker #4.)
- `did:key` controllers minted by either stack resolve on the other (Ed25519, `z6Mk…`).

## Pinned JS dependencies

`@digitalbazaar/zcap` 9.0.1, `jsonld-signatures` 11.6.0,
`@digitalbazaar/ed25519-signature-2020` 5.4.0,
`@digitalbazaar/ed25519-verification-key-2020` 4.2.0,
`@digitalbazaar/did-method-key` 5.3.0, `@digitalbazaar/zcap-context` 2.0.1,
`ed25519-signature-2020-context` 1.1.0 (see `js/package-lock.json`).
