# Live ZCAP interoperability tests

Run `bash interop/run-interop.sh` with .NET 10, Node.js, npm and jq installed.
The harness builds its CLI, installs pinned JavaScript dependencies when absent,
generates fresh signed documents, and verifies both directions with the real
`@digitalbazaar/zcap` 9.0.1 and `jsonld-signatures` 11.6.0.

## Baseline (12 assertions)

- Single-hop delegation, both directions.
- Tampered delegation action rejected, both directions.
- Two-level delegation with an embedded parent, both directions.
- Root/delegated DI application-document invocation, both directions.
- Tampered invocation action rejected, both directions.

## Supported-profile matrix (#149, 109 assertions)

`js/profile.mjs` independently signs exact, path and query target variants in both
stacks. It checks delegation, root invocation and delegated invocation with target
attenuation enabled and disabled, including `/`, `?`, `&` boundaries and invalid
prefixes. Negative .NET cases require a validation outcome, not a crashed process.

Built-in typed caveats must be rejected by stock JavaScript safe-mode signing and
verification. .NET rejects capability `caveat` fields, including unknown/empty/null
forms. More extensive .NET tests cover embedded ancestors, secondary proofs and
all public signing/verification entry paths.

`AllowTargetAttenuation` / `allowTargetAttenuation` default to false. The target
API must enforce query semantics; the harness proves lexical policy compatibility.
.NET's additional literal path-traversal guard is tested in the unit suite.

All proofs in this harness use Ed25519Signature2020 and RDFC-1.0. The harness does
not establish HTTP-signature transport, P-256, distributed revocation, or full
v0.4 specification compliance. See [the compatibility report](../docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md).

The interop test project wraps this script for `.github/workflows/ci-interop.yml`.
Generated vectors and dependency/build directories are ignored by Git.
