using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// JSON-LD lets a holder restate a signed term under a key the model does not read: inside
/// <c>@nest</c>, in an <c>@included</c> node with the capability's own id, or under its full IRI.
/// The signed graph, and so the delegator's signature, is unchanged, but the model would see no
/// <c>allowedAction</c> or <c>expires</c>. The verifier must refuse such keys in every profile.
/// </summary>
public class RestatedTermTests
{
    private readonly InMemoryDidProvider _did = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;

    public RestatedTermTests()
    {
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
    }

    private VerificationService Verifier(InMemoryRevocationStore? store = null)
        => new(_did, new RevocationService(store ?? new InMemoryRevocationStore()), new InMemoryNonceStore());

    private static Capability Rewrite(Capability capability, Action<JsonObject> edit)
    {
        var json = JsonSerializer.SerializeToNode(capability, ZcapJsonOptions.Default)!.AsObject();
        edit(json);
        return json.Deserialize<Capability>(ZcapJsonOptions.Default)!;
    }

    private static void Hide(JsonObject node, string term, string carrier)
    {
        var value = node[term]!.DeepClone();
        node.Remove(term);
        switch (carrier)
        {
            case "@nest":
                node["@nest"] = new JsonObject { [term] = value };
                break;
            case "@included":
                node["@included"] = new JsonArray(new JsonObject { ["id"] = node["id"]!.DeepClone(), [term] = value });
                break;
            default:
                node[carrier] = value;
                break;
        }
    }

    private async Task<(Capability root, Capability readOnly, string holder)> ReadOnlyGrantAsync(string target)
    {
        var owner = _did.GenerateDidKey();
        var holder = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, owner, target); // no allowedAction
        var readOnly = await _caps.DelegateCapabilityAsync(root, holder, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        return (root, readOnly, holder);
    }

    [Theory(DisplayName = "A holder cannot hide its allowedAction to invoke another action")]
    [InlineData("@nest")]
    [InlineData("@included")]
    [InlineData("https://w3id.org/security#allowedAction")]
    public async Task HiddenAllowedAction_Refused(string carrier)
    {
        var (_, readOnly, holder) = await ReadOnlyGrantAsync("https://example.com/restated/" + Uri.EscapeDataString(carrier));
        var tampered = Rewrite(readOnly, json => Hide(json, "allowedAction", carrier));
        tampered.AllowedAction.Should().BeNull("the model no longer sees the restriction");

        var envelope = new Invocation
        {
            Capability = InvocationCapability.FromCapability(tampered), CapabilityAction = "write",
            InvocationTarget = tampered.InvocationTarget,
        };
        // SigningService refuses to embed such a capability; the holder's own signer would not.
        envelope.Proof = await RawProofSigner.SignInvocationAsync(_did, envelope, holder);
        // The profile check runs before the signature, so swapping the capability into an honest
        // Data Integrity proof reaches it as a holder-signed document would.
        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(readOnly), "write", tampered.InvocationTarget, holder);
        secured["proof"]!["capability"] = JsonSerializer.SerializeToNode(tampered, ZcapJsonOptions.Default);

        (await Verifier().VerifyInvocationDetailedAsync(envelope, tampered)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
        (await Verifier().VerifyCapabilityInvocationDetailedAsync(secured, "write", new[] { tampered.InvocationTarget }))
            .Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await Verifier().VerifyCapabilityChainDetailedAsync(tampered)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Signing refuses a capability that restates a term under a keyword")]
    public async Task Signing_RestatedTerm_Throws()
    {
        var (root, readOnly, _) = await ReadOnlyGrantAsync("https://example.com/restated/signing");
        var tampered = Rewrite(readOnly, json => Hide(json, "allowedAction", "@nest"));

        var sign = () => _signing.SignCapabilityAsync(
            tampered, root.Controller!.Values.Single(), Proof.CapabilityDelegationPurpose, new object[] { root.Id });

        (await sign.Should().ThrowAsync<ZcapLd.Core.Exceptions.CapabilityValidationException>())
            .WithMessage(CapabilityProfile.KeywordKeyMessage);
    }

    [Fact(DisplayName = "A holder cannot hide the restrictions of an embedded ancestor either")]
    public async Task HiddenAncestorRestriction_Refused()
    {
        var owner = _did.GenerateDidKey();
        var middle = _did.GenerateDidKey();
        var holder = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, owner, "https://example.com/restated/depth");
        var parent = await _caps.DelegateCapabilityAsync(root, middle, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        var leaf = await _caps.DelegateCapabilityAsync(parent, holder, new[] { "read" }, DateTime.UtcNow.AddDays(4), signerDid: middle);
        var tampered = Rewrite(leaf, json =>
        {
            Hide(json, "allowedAction", "@nest");
            Hide(json["proof"]!["capabilityChain"]![1]!.AsObject(), "allowedAction", "@nest");
        });
        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(tampered), CapabilityAction = "write",
            InvocationTarget = tampered.InvocationTarget,
        };
        invocation.Proof = await RawProofSigner.SignInvocationAsync(_did, invocation, holder);

        (await Verifier().VerifyInvocationDetailedAsync(invocation, tampered)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Standalone proof verification cannot be shown an expired link as current")]
    public async Task HiddenExpiry_StandaloneProof_Refused()
    {
        var owner = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, owner, "https://example.com/restated/expiry");
        var expired = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = root.Id,
            Controller = _did.GenerateDidKey(),
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(-1)),
        };
        expired.Proof = await _signing.SignCapabilityAsync(expired, owner, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        (await Verifier().VerifyCapabilityProofDetailedAsync(expired)).Outcome.Should().Be(VerificationOutcome.Expired);

        var tampered = Rewrite(expired, json => Hide(json, "expires", "@nest"));

        (await Verifier().VerifyCapabilityProofDetailedAsync(tampered)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Theory(DisplayName = "A signed revocation reason or metadata cannot be erased in transit")]
    [InlineData("value-object")]
    [InlineData("array")]
    [InlineData("@nest")]
    [InlineData("metadata-array")]
    public async Task RevocationDetails_ErasureForms_Refused(string form)
    {
        var (_, readOnly, holder) = await ReadOnlyGrantAsync("https://example.com/restated/revocation-" + form.TrimStart('@'));
        var store = new InMemoryRevocationStore();
        var signed = await _signing.SignRevocationAsync(readOnly.Id, holder, readOnly.InvocationTarget,
            reason: "key compromised", metadata: new Dictionary<string, string> { ["ticket"] = "SEC-1" });

        // Each form signs the same statements, so only the verifier's shape check can refuse it.
        var wire = JsonSerializer.SerializeToNode(signed, ZcapJsonOptions.Default)!.AsObject();
        var proof = wire["proof"]!.AsObject();
        var reason = proof[Proof.RevocationReasonField]!.DeepClone();
        var metadata = proof[Proof.RevocationMetadataField]!.DeepClone();
        switch (form)
        {
            case "value-object":
                proof[Proof.RevocationReasonField] = new JsonObject { ["@value"] = reason };
                break;
            case "array":
                proof[Proof.RevocationReasonField] = new JsonArray(reason);
                break;
            case "@nest":
                proof.Remove(Proof.RevocationReasonField);
                proof.Remove(Proof.RevocationMetadataField);
                proof["@nest"] = new JsonObject { [Proof.RevocationReasonField] = reason, [Proof.RevocationMetadataField] = metadata };
                break;
            case "metadata-array":
                proof[Proof.RevocationMetadataField] = new JsonArray(metadata);
                break;
        }
        var tampered = wire.Deserialize<Invocation>(ZcapJsonOptions.Default)!;

        (await Verifier(store).RevokeCapabilityAsync(readOnly, tampered)).Should().BeFalse();
        var key = RevocationScope.ForDelegationProof(readOnly.Proof!.Primary).KeyFor(readOnly.Id);
        (await store.GetAsync([key])).Should().BeEmpty();
        (await Verifier(store).RevokeCapabilityAsync(readOnly, signed)).Should().BeTrue();
        (await store.GetAsync([key])).Single().Reason.Should().Be("key compromised");
    }
}
