# Caveat extension profile v1

Status: implemented in ZcapLd.Core 6.0.0 (#157). This is an **application-specific
extension** of ZCAP-LD, not part of the v0.4 draft. Capabilities that carry caveats are
rejected by `@digitalbazaar/zcap` and by any zcap-dotnet verifier that has not registered the
caveat types. Capabilities without caveats are unaffected and stay interoperable.

## Why it exists

ZCAP v0.4 restricts authority with `expires`, `allowedAction` and invocation-target
narrowing. Some restrictions do not fit those fields. A cumulative privacy budget is one: a
genomics agent granted ε = 3 may run a cost-1 query and a cost-2 query, then must be refused,
however its action and target are set.

Releases 2.x–4.x carried typed caveats, but #149 showed their parameters were not signed.
RDFC-1.0 drops every JSON key the active `@context` does not define, so `maxUses` or `uri`
could be edited after signing. Release 5.0.0 removed caveats. This profile restores the same
wire shape, with every parameter signed and every unsignable input rejected.

## Wire format

A delegated capability carries the caveats in `caveat`, as before. It also lists, in its **own**
`@context`, one generated context per caveat type it carries:

```json
{
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "urn:zcap-dotnet:caveat-context:v1:EpsilonBudget"
  ],
  "id": "urn:uuid:…",
  "parentCapability": "urn:uuid:…",
  "controller": "did:key:…",
  "invocationTarget": "https://clinical.example/fhir/Observation",
  "allowedAction": ["query"],
  "expires": "2099-01-01T00:00:00.000000Z",
  "caveat": [{ "maxEpsilon": 3, "type": "EpsilonBudget" }],
  "proof": { "…": "…" }
}
```

### Generated contexts

For a type `T` with declared parameters `p1…pn`, the context
`urn:zcap-dotnet:caveat-context:v1:T` is the RFC 8785 serialization of:

```json
{ "@context": { "@protected": true,
    "T": { "@id": "urn:zcap-dotnet:caveat:v1:T",
           "@context": { "@protected": true,
             "p1": { "@id": "urn:zcap-dotnet:caveat:v1:T#p1", "@type": "@json" } } } } }
```

`zcap/v1` defines `caveat` (`sec:caveat`), so each entry is an RDF node. Its `type` expands
to the type IRI and activates the type-scoped context. That context makes each parameter a JSON
literal, so its whole value, nested data included, is part of the signed N-Quads. The context
is served from memory and **never fetched**. Issuers and verifiers must register the same
parameter set under the same type name; any mismatch fails closed.

### Integrity rules (enforced when signing and when verifying)

RDFC silently drops whatever the context does not define. Every rule below exists to refuse
exactly those inputs:

1. `caveat` appears only at the top level of a capability object (the verified capability, an
   embedded `capabilityChain` parent, or an invocation's embedded capability). That object's
   own `@context` lists the context of every caveat type it carries. A root never carries one.
2. `caveat` is an array of 1–16 objects, at most 64 KiB of JSON. Each object has a single string
   `type` naming a registered type (`^[A-Za-z][A-Za-z0-9_]{0,63}$`), plus only that type's declared
   parameters.
   There is no `id`, no `@` keyword and no undeclared key, and at most one caveat per type.
3. Parameter values are JSON literals with:
   - no `null` (DataProofs' JCS fallback strips nulls);
   - nesting depth ≤ 8 and ≤ 1024 values per capability;
   - no duplicate member names;
   - strings ≤ 4096 characters, with no control characters, no U+2028/U+2029 and no unpaired
     surrogates;
   - numbers that are finite and written exactly in RFC 8785 form, without an exponent, and
     either 0 or of magnitude 0.0001…2⁵³.

   In this domain dotNetRDF's JSON literal equals RFC 8785, so two different values never sign
   alike. Other stacks that implement JSON-LD 1.1 `@json` produce the same bytes.
4. With a registry configured, scanned capability and proof JSON may not contain a key with `:`,
   a keyword other than `@context`, a key named after a caveat type, or a `type` naming a caveat
   type outside a caveat entry. `sec:caveat` and the full caveat IRI are always rejected.
5. Parameter names may not be `id`, `type`, or a term of the zcap or supported suite contexts.
   Such a name would redefine a protected term or read as ZCAP vocabulary. Classes that capture
   extension data cannot be registered.

## Attenuation

Every delegated link must **restate** each caveat type its parent carries, and
`child.IsAttenuationOf(parent)` must hold. Dropping or widening one is an
`AttenuationViolation`. A child may add new caveat types. The default `IsAttenuationOf`
requires exact restatement. Override it to allow narrowing; it must be reflexive and
transitive. The issuer (`DelegateCapabilityAsync`) inherits unrestated parent caveats verbatim
and refuses to widen.

## Verification

| API | Caveat-bearing chain result |
| --- | --- |
| `VerifyInvocation*` (envelope) and `VerifyCapabilityInvocation*` (Data Integrity) | `Valid` only after every caveat type's handler allows it |
| `VerifyCapabilityChain*` | `CaveatEnforcementRequired` (not valid), with `VerificationResult.Caveats` |
| `VerifyCapabilityProof*` | `CaveatEnforcementRequired` when the link carries caveats, or, with a registry, whenever it is below the first level: its embedded parent is not verified on this path, so inherited caveats cannot be ruled out |
| `RevokeCapabilityAsync` | Integrity rules only; `Validate`, `IsAttenuationOf` and handlers are skipped so a capability stays revocable |

Outcomes: an unregistered type is `UnsupportedCaveat`. A registered type without a handler is
`UnsupportedCaveat` at invocation, decided before the nonce is used. A rule violation is
`MalformedCapability`. A handler denial is `CaveatNotSatisfied`. A handler exception is
`CouldNotVerify`. On the envelope path the invocation's embedded capability must equal the
capability being verified.

Invocation order: chain and attenuation, handler presence, invocation signature, controller
authorization, freshness, replay (the nonce is consumed), then handlers. Handlers run in
ordinal type order, evaluation stops at the first denial, and `ReleaseAsync` is called on every
handler that had already allowed the request. A replayed or forged invocation never reaches a
handler.

## Enforcement contract (`ICaveatHandler`)

The library authenticates the delegated bounds, enforces monotonic attenuation, and guarantees
that handlers run last, once per invocation, for fresh, authorized, non-replayed requests. The
handler's context contains only authenticated data:

- `Grants`: each link's caveat of this type, root side first, with `GrantKey`;
- `Chain` and `RootCapabilityId`;
- `CapabilityAction` and `InvocationTarget`;
- `InvocationId` (the replay nonce), `VerificationMethod` and `Created`.

There is deliberately no property bag. **The resource is responsible for:**

- **Trusted cost.** Derive the cost from the signed action and target. Fields of a Data
  Integrity application document that the contexts do not define are not signed. Encode
  request-dependent cost basis in the target (v0.4 query narrowing) or the action. The Data
  Integrity form pins both to the relying party's expected action and targets. On the envelope
  form the resource must perform exactly `invocation.CapabilityAction` and `InvocationTarget`.
- **Atomic, hierarchical accounting.** Check and debit every grant in `Grants` in one atomic
  operation, so siblings share their ancestors' budgets. Key state by `GrantKey`, a SHA-256 of
  the id path from the root, and not by the issuer-chosen capability id. Read each ceiling from
  the presented grant on every request.
- **No caching by invocation id.** `InvocationId` is chosen by the invoker. After the nonce store
  forgets it, the same id can return with a different action. Never reuse a decision keyed by it.
  The verifier's replay check already lets each invocation reach handlers at most once, as long as
  the nonce store retains the nonce.
- **Shared state.** Share the nonce store and the ledger across all verifier replicas, and keep
  nonce entries for at least the nonce window (the default `InMemoryNonceStore` is per process).
- **Retries.** The nonce is consumed before handlers run, so a client retries a denied request
  with a new invocation id. Minting new sibling or leaf capabilities does not create new budget:
  every debit also lands on the ancestors' grants.
- **Several stateful types.** Implement `ReleaseAsync` (or compensate) when another handler can
  deny after yours allowed.

## Identifiers

RDFC normalizes IRIs through `System.Uri`, so a variant id would verify as the signed one. It
also silently drops an IRI that .NET does not consider well formed, such as one containing `[`,
`]` or a second `#`. A malformed id removes the whole node from the signed graph; a malformed target
or controller removes that triple. The rules below apply in every profile, at signing and at
verification:

- Capability ids, `parentCapability`, `capabilityChain` ids, invocation ids and revocation request
  ids must be well-formed absolute IRIs already in normalized form (`new Uri(id).AbsoluteUri == id`).
- Capability and invocation targets and controllers must be well-formed absolute IRIs. Percent-encode
  `[` and `]`, for example `?filter%5Bid%5D=123`.

## Registering types

```csharp
public sealed class EpsilonBudgetCaveat : Caveat
{
    public override string Type => "EpsilonBudget";
    [JsonPropertyName("maxEpsilon")] public required double MaxEpsilon { get; init; }
    public override void Validate()
    {
        if (!(MaxEpsilon > 0 && MaxEpsilon <= 100))
            throw new CapabilityValidationException("maxEpsilon out of range");
    }
    public override bool IsAttenuationOf(Caveat parent)
        => parent is EpsilonBudgetCaveat p && MaxEpsilon <= p.MaxEpsilon;
}

var caveats = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>("EpsilonBudget");
var signing = new SigningService(signer, resolver, caveats);
var capabilities = new CapabilityService(signing, caveats);
var verifier = new VerificationService(resolver, revocations, nonces,
    caveats: caveats, caveatHandlers: new ICaveatHandler[] { new EpsilonBudgetLedger(store) });

// ASP.NET Core
services.AddZcapServices();
services.AddZcapCaveatType<EpsilonBudgetCaveat>("EpsilonBudget");
services.AddZcapCaveatHandler<EpsilonBudgetLedger>();
```

Register every type before the services are first resolved: a registry is frozen when a
service receives it. `capability.GetCaveats(registry)` reads validated caveats (form only, not
signatures). See `examples/ZcapLd.Examples/EpsilonBudget.cs` for a complete ledger.

## Historical capabilities and migration

- Capabilities from 2.x–4.x carried `caveat` without a type context. They are rejected in every
  profile, because their parameters were never signed. Re-issue them under this profile.
- **Wallets (OpaqAI wallet platform):** register the same caveat classes on the
  `CapabilityService`/`SigningService` that delegate. Pass `caveats:` to
  `DelegateCapabilityAsync` (inherited ones need not be repeated). Do not strip caveats when
  forwarding. Expect `CaveatEnforcementRequired` from chain checks.
- **Clinical orchestrator:** replace the `IsSatisfied => true` override (the member no longer
  exists) with `Validate` and `IsAttenuationOf`.
- **Resource verifiers:** register an `ICaveatHandler` per type and move the budget ledger to
  `GrantKey`-keyed hierarchical debits.
- **Other stacks (zcap-py):** implement this document and the generated context, and test
  against the fixtures in [`caveat-profile-v1/`](caveat-profile-v1/README.md).
  zcap-py 0.6.0's legacy signing contract is not assumed compatible.
- Other zcap-dotnet changes in 6.0.0 that affect migration: envelope invocations and signed
  revocations are now canonicalized under the suite context as well, so `created` is signed. A
  5.x client and a 6.x server cannot exchange them. Ids must be normalized absolute IRIs.
