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

## Supported-profile matrix (#149)

`js/profile.mjs` independently signs exact, path and query target variants in both
stacks. It checks delegation, root invocation and delegated invocation with target
attenuation enabled and disabled, including `/`, `?`, `&` boundaries and invalid
prefixes. Negative .NET cases require a validation outcome, not a crashed process.

Legacy built-in caveats trigger precise JavaScript JSON-LD safe-mode errors during
signing: an undefined `maxUses` property or a relative type reference. The harness
asserts those error details. Separately, JS signs and verifies recognized caveat
nodes in compact, absolute-IRI and `@nest` forms without enforcing their meaning.
.NET rejects those authentic documents. Altering a signed node then triggers a
specifically asserted JS signature failure. These are distinct checks.

.NET also rejects unknown/empty/null caveats in either direct key spelling. Unit
tests cover scoped prefixes, inline aliases, other JSON-LD nesting, ancestors,
secondary proofs, and public signing/verification paths. Capability/proof contexts
are limited to zcap/v1 and the supported suites; application-document bodies remain
outside that restriction scan.

`AllowTargetAttenuation` / `allowTargetAttenuation` default to false. The target
API must enforce query semantics; the harness proves lexical policy compatibility.
.NET's additional literal path-traversal guard is tested in the unit suite.

All proofs in this harness use Ed25519Signature2020 and RDFC-1.0. The harness does
not establish HTTP-signature transport, P-256, distributed revocation, or full
v0.4 specification compliance. See [the compatibility report](../docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md).

The interop test project wraps this script for `.github/workflows/ci-interop.yml`.
Generated vectors and dependency/build directories are ignored by Git.
