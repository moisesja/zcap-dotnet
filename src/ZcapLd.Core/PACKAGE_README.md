# ZcapLd.Core

.NET 10 library for the supported ZCAP v0.4.0 profile: root and delegated
capabilities, Ed25519/P-256 proofs, controller authorization, replay protection,
and signed revocation. Proofs use RDFC-1.0 through DataProofs and NetCrypto.

Provide an `IDidSigner` and `IDidResolver`; no private-key store is installed by default.
`DidKeyResolver` handles `did:key`. For several DID methods, register one adapter per method
in a `CompositeDidResolver` (full prefixes such as `"did:web:"`): it routes key resolution
and controller authorization to the adapter for the controller's method, so each adapter should
also implement NetDid's `IVerificationRelationshipResolver`. Key-only adapters fail closed.

```csharp
var signing = new SigningService(didSigner, didResolver);
var capabilities = new CapabilityService(signing);
var root = await capabilities.CreateRootCapabilityAsync(ownerDid, "https://example.com/reports");
var child = await capabilities.DelegateCapabilityAsync(root, agentDid, new[] { "read" },
    DateTime.UtcNow.AddDays(1));
var verifier = new VerificationService(didResolver);
var invocation = capabilities.CreateInvocation(child, "read");
invocation.Proof = await signing.SignInvocationAsync(invocation, agentDid);
bool authorized = await verifier.VerifyInvocationAsync(invocation, child, root);
```

Supply the root explicitly as above, or configure `IRootCapabilityResolver`.
For cross-stack invocation use `SignCapabilityInvocationAsync` and
`VerifyCapabilityInvocationAsync`; the relying party supplies its expected action
and target. The root is referenced by ID; a delegated invocation embeds the zcap.

Version 5 removes all typed caveat APIs and invocation-context property overloads.
Incoming `caveat` fields are rejected even when null or empty. Use `expires`,
`allowedAction`, and an optional delegation `invocationTarget` instead.
Equivalent IRI/prefixed keys and nested restrictions are rejected throughout
capability/proof JSON. Their contexts must be zcap/v1 or a supported proof-suite
context; inline aliases and unrelated vocabularies are unsupported.
`VerificationPolicy.AllowTargetAttenuation` defaults to false; explicitly enable
it for path/query narrowing. The target API must enforce parameter semantics.

Use `IRevocationStore` and signed revocation requests. Replicated verifiers must
share authoritative revocation state; there is no automatic polling of a URI
supplied by a capability holder. `INonceStore` must likewise be shared when replay
protection spans verifier instances.

See [the repository](https://github.com/moisesja/zcap-dotnet) for the full guide,
policy options, examples and live JavaScript interoperability tests.
