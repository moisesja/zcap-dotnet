# ZCAP library roadmap

## Version 5: issue #149

- Native restrictions: `expires`, `allowedAction`, explicit invocation-target narrowing.
- Unsupported vocabulary caveats removed and rejected throughout capability chains.
- Exact targets by default; explicit verifier opt-in for path/query attenuation.
- RDFC and existing proof suites retained, with live JS interoperability coverage.
- Signed revocation at the verifier and shared authoritative store guidance.

See [requirements](ZCAP-LD-SPECIFICATION-REQUIREMENTS.md),
[compatibility evidence](ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md), and
[the implementation checklist](../tasks/todo20261024-149.md).

## Remaining work

- HTTP-signature invocation transport (#119), distinct from the implemented DI
  application-document path.
- An explicitly negotiated/tested modern `DataIntegrityProof` cryptosuite profile
  if consumers need it. v0.4 examples alone do not mandate a wire-format change.
- Deployment-specific revocation distribution between independent operators;
  shared verifier storage does not discover or notify unknown verifiers.
- Ongoing specification tracking: the v0.4 caveat narrative is inconsistent with
  its vocabulary-removal note (which was already present in published v0.3).

#112's proposed acceptance of unknown typed caveats is superseded by the supported
profile. #144's broad integrity conclusion is corrected in the compatibility report.
There is no plan to preserve unsafe legacy caveat acceptance.
