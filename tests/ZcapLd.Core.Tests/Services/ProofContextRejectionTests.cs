using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// A proof carries no <c>@context</c> of its own: proofs are canonicalized under the document's context, and
/// DataProofs replaces any proof-level one before RDFC, so such a member would be unsigned and unread
/// (#159 adversarial review). The profile refuses it on every path, and the standalone proof path applies
/// the same context-shape rule as the chain path.
/// </summary>
public class ProofContextRejectionTests
{
    private const string ZcapContext = "https://w3id.org/zcap/v1";
    private const string Target = "https://ctx.example/resource";

    private readonly InMemoryDidProvider _did = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly VerificationService _verifier;

    public ProofContextRejectionTests()
    {
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
        _verifier = new VerificationService(
            _did, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore());
    }

    private static Dictionary<string, JsonElement> ProofContext(params string[] urls) => new(StringComparer.Ordinal)
    {
        ["@context"] = JsonSerializer.SerializeToElement<object>(urls.Length == 1 ? urls[0] : urls),
    };

    [Theory(DisplayName = "A proof-level @context added after signing is refused on the delegation paths")]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task DelegationProof_WithOwnContext_IsMalformed(KeyType keyType)
    {
        var owner = _did.GenerateDidKey(keyType);
        var agent = _did.GenerateDidKey(keyType);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid);

        // The signature still covers the same bytes: this member is never canonicalized.
        delegated.Proof!.Primary.AdditionalProperties = ProofContext(ZcapContext, "https://w3id.org/security/suites/ed25519-2020/v1");

        var chain = await _verifier.VerifyCapabilityChainDetailedAsync(delegated);
        chain.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        chain.Message.Should().Contain(CapabilityProfile.ProofContextMessage);
        var standalone = await _verifier.VerifyCapabilityProofDetailedAsync(delegated);
        standalone.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "A proof-level @context is refused on an envelope invocation")]
    public async Task EnvelopeInvocationProof_WithOwnContext_IsMalformed()
    {
        var owner = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var invocation = new Invocation { Capability = root.Id, CapabilityAction = "read", InvocationTarget = Target };
        invocation.Proof = await _signing.SignInvocationAsync(invocation, owner);

        invocation.Proof.AdditionalProperties = ProofContext(ZcapContext);

        var result = await _verifier.VerifyInvocationDetailedAsync(invocation, root);
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        result.Message.Should().Contain(CapabilityProfile.ProofContextMessage);
    }

    [Fact(DisplayName = "A proof-level @context is refused on a Data Integrity invocation")]
    public async Task DataIntegrityInvocationProof_WithOwnContext_IsMalformed()
    {
        var owner = _did.GenerateDidKey(KeyType.P256);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var secured = await _signing.SignCapabilityInvocationAsync(InvocationCapability.FromId(root.Id), "read", Target, owner);
        (await _verifier.VerifyCapabilityInvocationAsync(secured, "read", new[] { Target })).Should().BeTrue();

        secured["proof"]!["@context"] = new JsonArray(ZcapContext, ZcapSuiteCatalogP256Context());

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured, "read", new[] { Target });
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        result.Message.Should().Contain(CapabilityProfile.ProofContextMessage);
    }

    [Fact(DisplayName = "A proof-level @context is refused on a signed revocation")]
    public async Task RevocationProof_WithOwnContext_IsRefused()
    {
        var owner = _did.GenerateDidKey();
        var agent = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        var revocation = await _signing.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget);

        revocation.Proof!.AdditionalProperties = ProofContext(ZcapContext);

        (await _verifier.RevokeCapabilityAsync(delegated, revocation)).Should().BeFalse();
        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid,
            "the refused request must not have recorded a revocation");
    }

    [Fact(DisplayName = "Signing refuses a proof-level @context too")]
    public async Task SigningRevocation_WithOwnContextExtension_IsRefused()
    {
        // The signing path runs the same profile over the proof it is about to sign (reason/metadata ride
        // in the same extension dictionary), so the rule holds for issuers as well as verifiers.
        CapabilityProfile.GetProofRejectionReason(new Proof
        {
            Type = "Ed25519Signature2020",
            Created = ZcapTimestamps.Format(DateTime.UtcNow),
            ProofPurpose = Proof.CapabilityDelegationPurpose,
            VerificationMethod = "did:key:z6MkSomeSigner#z6MkSomeSigner",
            ProofValue = "z",
            AdditionalProperties = ProofContext(ZcapContext),
        }).Should().Be(CapabilityProfile.ProofContextMessage);
        await Task.CompletedTask;
    }

    [Theory(DisplayName = "The standalone proof path applies the chain path's context-shape rule")]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task StandaloneProof_ContextNotBeginningWithZcap_IsMalformed(KeyType keyType)
    {
        var owner = _did.GenerateDidKey(keyType);
        var agent = _did.GenerateDidKey(keyType);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        var suiteContext = ((object[])delegated.Context)[1];

        // Same triples, so the signature still verifies; the shape rule (MUST-04) refuses it on both paths.
        delegated.Context = new object[] { suiteContext, ZcapContext };

        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await _verifier.VerifyCapabilityProofDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    private static string ZcapSuiteCatalogP256Context() => ZcapLd.Core.Cryptography.ZcapSuiteCatalog.P256ContextUrl;

    // ─── Serialized embedded ancestors (the normal wire representation) ───────────────────────────────
    // A capabilityChain entry parsed from JSON is a JsonElement, not a typed Capability, so its proofs are
    // scanned as raw JSON. The @context rule must hold there too (PR #163 review): the chain walk later
    // deserializes the ancestor and verifies it without re-running the profile.

    private const string Ed25519Context = "https://w3id.org/security/suites/ed25519-2020/v1";

    private static JsonElement Serialized(Capability capability, Action<JsonObject> edit)
    {
        var node = JsonNode.Parse(CapabilityJson.Serialize(capability))!.AsObject();
        edit(node);
        return JsonSerializer.SerializeToElement(node, ZcapJsonOptions.Default);
    }

    private async Task AssertRefusedAsync(Capability child, string signer, object[] chain)
    {
        // The issuer refuses to sign the shape.
        var unsigned = CapabilityJson.Parse(CapabilityJson.Serialize(child));
        unsigned.Proof = null;
        var act = () => _signing.SignCapabilityAsync(unsigned, signer, Proof.CapabilityDelegationPurpose, chain);
        (await act.Should().ThrowAsync<CapabilityValidationException>())
            .WithMessage($"*{CapabilityProfile.ProofContextMessage}*");

        // A holder on a lenient stack signs it anyway: both verification paths refuse it, before and after
        // a full JSON round trip of the leaf.
        var forged = CapabilityJson.Parse(CapabilityJson.Serialize(child));
        forged.Proof = await RawProofSigner.SignCapabilityAsync(_did, forged, signer, chain);
        foreach (var candidate in new[] { forged, CapabilityJson.Parse(CapabilityJson.Serialize(forged)) })
        {
            var standalone = await _verifier.VerifyCapabilityProofDetailedAsync(candidate);
            standalone.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
            standalone.Message.Should().Contain(CapabilityProfile.ProofContextMessage);
            var fullChain = await _verifier.VerifyCapabilityChainDetailedAsync(candidate);
            fullChain.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        }
    }

    [Fact(DisplayName = "A serialized embedded parent whose proof carries @context is refused at signing and on both paths")]
    public async Task EmbeddedParentProof_WithOwnContext_SerializedInput_IsRefused()
    {
        var owner = _did.GenerateDidKey();
        var mid = _did.GenerateDidKey();
        var holder = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var parent = await _caps.DelegateCapabilityAsync(root, mid, new[] { "read" }, DateTime.UtcNow.AddHours(2));
        var child = await _caps.DelegateCapabilityAsync(parent, holder, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        (await _verifier.VerifyCapabilityProofDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.Valid);

        var rawParent = Serialized(parent, node => node["proof"]!["@context"] = Ed25519Context);

        await AssertRefusedAsync(child, mid, new object[] { root.Id, rawParent });
    }

    [Fact(DisplayName = "A proof array on a serialized embedded parent is scanned member by member")]
    public async Task EmbeddedParentProofArray_WithOwnContextOnOneMember_IsRefused()
    {
        var ownerA = _did.GenerateDidKey();
        var ownerB = _did.GenerateDidKey();
        var mid = _did.GenerateDidKey();
        var holder = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(new[] { ownerA, ownerB }, Target, new[] { "read" }));
        var parent = await _caps.DelegateCapabilityAsync(root, mid, new[] { "read" }, DateTime.UtcNow.AddHours(2), signerDid: ownerA);
        var second = await _signing.SignCapabilityAsync(parent, ownerB, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        parent.Proof = ProofSet.FromValues(new[] { parent.Proof!.Primary, second });
        var child = await _caps.DelegateCapabilityAsync(parent, holder, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        (await _verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.Valid);

        var rawParent = Serialized(parent, node => node["proof"]!.AsArray()[1]!["@context"] = Ed25519Context);

        await AssertRefusedAsync(child, mid, new object[] { root.Id, rawParent });
    }

    [Fact(DisplayName = "A proof @context on the ancestor embedded inside the parent's proof is refused")]
    public async Task DeeperEmbeddedAncestorProof_WithOwnContext_IsRefused()
    {
        var owner = _did.GenerateDidKey();
        var a = _did.GenerateDidKey();
        var b = _did.GenerateDidKey();
        var c = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var first = await _caps.DelegateCapabilityAsync(root, a, new[] { "read" }, DateTime.UtcNow.AddHours(3));
        var second = await _caps.DelegateCapabilityAsync(first, b, new[] { "read" }, DateTime.UtcNow.AddHours(2));
        var third = await _caps.DelegateCapabilityAsync(second, c, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        (await _verifier.VerifyCapabilityChainDetailedAsync(third)).Outcome.Should().Be(VerificationOutcome.Valid);

        // second's proof embeds first; the @context goes on first's proof inside second's serialized copy.
        var rawSecond = Serialized(second,
            node => node["proof"]!["capabilityChain"]!.AsArray()[1]!["proof"]!["@context"] = Ed25519Context);

        await AssertRefusedAsync(third, b, new object[] { root.Id, first.Id, rawSecond });
    }
}
