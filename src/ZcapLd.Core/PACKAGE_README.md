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

Prefer `expires`, `allowedAction` and an optional delegation `invocationTarget`.
Without a `CaveatTypeRegistry`, incoming `caveat` fields are rejected even when null
or empty, and equivalent IRI/prefixed keys and nested restrictions are rejected
throughout capability/proof JSON. Contexts must be zcap/v1, a supported proof-suite
context or a registered caveat context; inline aliases and unrelated vocabularies are
unsupported.

Version 6 restores custom caveats as an opt-in extension profile (#157), which other
ZCAP stacks do not accept. Subclass `Caveat` and register the class with
`CaveatTypeRegistry`. Pass the registry to `SigningService`, `CapabilityService` and
`VerificationService`, and register an `ICaveatHandler` per type at the resource. Every
parameter is signed through a pinned per-type context. Children must restate and narrow
inherited caveats. Only invocation verification authorizes caveats; chain checks return
`CaveatEnforcementRequired`. See `docs/CAVEAT-PROFILE.md` in the repository.
`VerificationPolicy.AllowTargetAttenuation` defaults to false; explicitly enable
it for path/query narrowing. The target API must enforce parameter semantics.

Use `IRevocationStore` and signed revocation requests. Replicated verifiers must
share authoritative revocation state; there is no automatic polling of a URI
supplied by a capability holder. `INonceStore` must likewise be shared when replay
protection spans verifier instances.

Revocation records are keyed by the capability id and a `RevocationScope`: the delegator that
signed the capability (the DID of its delegation proof's verification method, as
`bedrock-zcap-storage` keys them), the root, or, for migrated 5.x and operator records only,
every chain. A forged copy of an id under another chain lands in the forger's scope, where no
genuine chain looks. Custom `IRevocationStore`s key rows by `RevocationRecord.Key`, never by the
id. See [Revocation scope](https://github.com/moisesja/zcap-dotnet/blob/main/architecture.md#revocation-scope).

See [the repository](https://github.com/moisesja/zcap-dotnet) for the full guide,
policy options, examples and live JavaScript interoperability tests.
