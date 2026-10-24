# ZCAP v0.4.0 profile and interoperability

Version 5 targets the documented native-attenuation profile in
[the requirements guide](ZCAP-LD-SPECIFICATION-REQUIREMENTS.md). Interoperability is
measured against the pinned `@digitalbazaar/zcap` 9.0.1, `jsonld-signatures` 11.6.0
and `Ed25519Signature2020` 5.4.0 in `interop/js/package.json`.

## Tested compatibility

`interop/run-interop.sh` retains twelve baseline assertions:

| Checks | Scope |
| --- | --- |
| 1–2 | Single-hop delegation, both directions |
| 3–4 | Tampered allowed action rejected, both directions |
| 5–6 | Two-level delegation with embedded parent, both directions |
| 7–10 | Root and delegated application-document DI invocation, both directions |
| 11–12 | Tampered invocation action rejected, both directions |

`interop/js/profile.mjs` adds 109 assertions, signing independent target variants in each
stack and tests exact targets, `/`, `?`, `&`, sibling-prefix errors and wrong
query delimiters. Both verifier policy settings are exercised for delegation,
root invocation and delegated invocation. Negative CLI checks require a validation
outcome rather than treating any process crash as successful rejection.

The profile matrix also verifies that built-in typed caveats are refused by stock
JS safe-mode signing/verification and by .NET verification. .NET additionally
rejects empty/null/custom caveat fields by presence. Unit tests cover nested
ancestors, secondary proofs, both invocation forms and signing rejection.

## Issue #149 and correction to #144

Earlier reports claimed .NET bound all caveat bytes and that JavaScript verified
caveats while ignoring their meaning. Both generalizations were incorrect:

- Under the bundled contexts, `UsageCount.maxUses` and `ValidWhileTrue.uri` are
  absent from signed N-Quads; their relative type values are not useful signed
  distinctions either. A holder could rewrite parameters or swap these types.
- `Expiration.expires` is signed because the context defines `expires`. The
  expiration-only experiment in [#144](https://github.com/moisesja/zcap-dotnet/issues/144)
  did not establish integrity of other types. The broader conclusion is withdrawn.
- Stock `jsonld-signatures` safe mode rejects these built-in type values. They
  never formed a working interoperable caveat vocabulary with this harness.

Version 5 removes the caveat API and rejects all capability `caveat` fields.
It does not offer an extension-context or passthrough acceptance mode. The custom
caveat acceptance proposal in [#112](https://github.com/moisesja/zcap-dotnet/issues/112)
is superseded for this profile; unknown caveat types remain unsupported.

The original twelve cases contain no typed caveats, so their expected results
remain unchanged. Public API migration removes processors/context arguments; it
does not change canonical bytes for supported capabilities. Golden vectors pin
those bytes.

## Target policy

Both stacks default to exact targets: `.NET VerificationPolicy.AllowTargetAttenuation`
and JavaScript `allowTargetAttenuation` are false. Enabling them permits lexical
path/query narrowing. Applications still enforce the meaning of the target.
The .NET literal `..` path-segment rejection is deliberate hardening; do not
interpret the JS implementation as a reason to remove it. Neither a lexical
prefix nor a valid signature establishes that a resource API enforces duplicate
query restrictions or normalizes paths safely.

## Proof suites and limits

RDFC-1.0 / Ed25519Signature2020 is the tested shared format. v0.4's updated examples
use `DataIntegrityProof` / `eddsa-jcs-2022`; upstream labels the release changes
non-normative. This does not require abandoning the existing peer-compatible
format. Supporting another suite requires a separately tested peer configuration.

P-256 is locally supported, but not covered by the stock Ed25519 harness. The
in-stack `Invocation` envelope is distinct from the interoperable application-doc
DI mode. HTTP-signature invocation transport remains separate (#119).

Revocation distribution, replay-store sharing, endpoint query semantics and
multi-operator trust are application/deployment concerns. The live tests do not
claim interoperability for those mechanisms or full specification compliance.
Do not infer a compliance percentage from the number of passing tests.
