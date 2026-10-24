using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

public class CapabilityProfileTests
{
    private readonly InMemoryDidProvider _dids = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly string _owner;
    private readonly string _holder;
    private VerificationService Verifier(bool attenuate = false) => new(_dids,
        new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
        policy: new VerificationPolicy { AllowTargetAttenuation = attenuate });

    public CapabilityProfileTests()
    {
        _owner = _dids.GenerateDidKey();
        _holder = _dids.GenerateDidKey();
        _signing = new SigningService(_dids, _dids);
        _caps = new CapabilityService(_signing);
    }

    private async Task<(Capability Root, Capability Leaf)> Chain(string target = "https://example.com/r")
    {
        var root = await _caps.CreateRootCapabilityAsync(_owner, target);
        _dids.RegisterRoot(root);
        var leaf = await _caps.DelegateCapabilityAsync(root, _holder, ["read"], DateTime.UtcNow.AddDays(1));
        return (root, leaf);
    }

    private static Capability Copy(Capability cap) => JsonSerializer.Deserialize<Capability>(
        JsonSerializer.Serialize(cap, ZcapJsonOptions.Default), ZcapJsonOptions.Default)!;
    private static void Caveat(Capability cap, string json) =>
        (cap.AdditionalProperties ??= new())["caveat"] = JsonDocument.Parse(json).RootElement.Clone();

    // Construct legacy signed fixtures below the public signing boundary. Otherwise a regression
    // in verification could be masked by SignCapabilityAsync's issuance rejection.
    private async Task ResignLegacy(Capability cap, string signer)
    {
        var proof = cap.Proof!.Primary;
        var bytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(cap), proof);
        proof.ProofValue = MultibaseCodec.Encode((await _dids.SignAsync(signer, bytes)).Signature);
    }

    public static TheoryData<string> Caveats => new()
    {
        "null", "[]", "{}",
        "[{\"type\":\"Expiration\",\"expires\":\"2099-01-01T00:00:00Z\"}]",
        "[{\"type\":\"UsageCount\",\"maxUses\":1}]",
        "[{\"type\":\"ValidWhileTrue\",\"uri\":\"https://issuer.example/status\"}]",
        "[{\"type\":\"UnknownRestriction\",\"value\":1}]"
    };

    [Theory]
    [MemberData(nameof(Caveats))]
    public async Task EveryCaveatShape_IsRejectedAtIssuanceAndVerification(string caveat)
    {
        var (root, leaf) = await Chain();
        (await Verifier().VerifyCapabilityChainAsync(leaf, root)).Should().BeTrue();
        Caveat(leaf, caveat);
        await ResignLegacy(leaf, _owner);
        var received = Copy(leaf);
        received.AdditionalProperties.Should().ContainKey("caveat");
        (await Verifier().VerifyCapabilityProofDetailedAsync(received, root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await Verifier().VerifyCapabilityChainDetailedAsync(received, root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await _caps.ValidateCapabilityAsync(received)).Should().BeFalse();
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _signing.SignCapabilityAsync(received, _owner, "capabilityDelegation"));
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _caps.DelegateCapabilityAsync(received, _owner, ["read"]));
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(received), "read", received.InvocationTarget, _holder));
        var envelope = new Invocation { Capability = InvocationCapability.FromCapability(received), CapabilityAction = "read", InvocationTarget = received.InvocationTarget };
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _signing.SignInvocationAsync(envelope, _holder));
    }

    [Theory]
    [InlineData("UsageCount", "maxUses", "1", "1000000")]
    [InlineData("ValidWhileTrue", "uri", "\"https://issuer.example/status\"", "\"https://holder.example/always-valid\"")]
    [InlineData("Expiration", "expires", "\"2027-01-01T00:00:00Z\"", "\"2099-01-01T00:00:00Z\"")]
    public async Task EditingLegacyParameters_NeverReturnsValid(string type, string field, string before, string after)
    {
        var (root, leaf) = await Chain();
        Caveat(leaf, $"[{{\"type\":\"{type}\",\"{field}\":{before}}}]");
        await ResignLegacy(leaf, _owner);
        Caveat(leaf, $"[{{\"type\":\"{type}\",\"{field}\":{after}}}]");
        (await Verifier().VerifyCapabilityProofDetailedAsync(Copy(leaf), root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact]
    public async Task ProoflessRoot_CaveatPresenceIsRejectedEvenWhenUnknownFieldsAreAllowed()
    {
        var (root, _) = await Chain();
        Caveat(root, "null");
        (await Verifier().VerifyCapabilityProofDetailedAsync(root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await Verifier().VerifyCapabilityChainAsync(root)).Should().BeFalse();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmbeddedGrandparent_AndSecondaryProof_AreInspected(bool secondaryProof)
    {
        var (root, first) = await Chain();
        var middle = await _caps.DelegateCapabilityAsync(first, _holder, ["read"]);
        var leaf = await _caps.DelegateCapabilityAsync(middle, _holder, ["read"]);
        (await Verifier().VerifyCapabilityProofAsync(leaf, root)).Should().BeTrue();
        var legacy = Copy(first);
        Caveat(legacy, "[]");
        if (secondaryProof)
        {
            leaf.Proof = new[] { leaf.Proof!.Primary, new Proof { ProofPurpose = "assertionMethod", CapabilityChain = [root.Id, legacy] } };
        }
        else
        {
            middle.Proof!.Primary.CapabilityChain = [root.Id, legacy];
        }
        (await Verifier().VerifyCapabilityProofDetailedAsync(Copy(leaf), root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await Verifier().VerifyCapabilityChainDetailedAsync(Copy(leaf), root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _signing.SignCapabilityAsync(leaf, _holder, "capabilityDelegation"));
        await Assert.ThrowsAsync<CapabilityValidationException>(() => _signing.SignCapabilityAsync(first, _owner, "capabilityDelegation", [root.Id, Copy(legacy)]));
    }

    [Theory]
    [InlineData("argument")]
    [InlineData("body")]
    [InlineData("proof")]
    public async Task EnvelopeChecksAllThreeCapabilityRepresentations(string location)
    {
        var (root, leaf) = await Chain();
        var invocation = _caps.CreateInvocation(Copy(leaf), "read");
        invocation.Proof = await _signing.SignInvocationAsync(invocation, _holder);
        invocation.Proof.Capability = InvocationCapability.FromCapability(Copy(leaf));
        (await Verifier().VerifyInvocationAsync(invocation, leaf, root)).Should().BeTrue();
        var target = location switch { "argument" => leaf, "body" => invocation.Capability.EmbeddedCapability!, _ => invocation.Proof.Capability.EmbeddedCapability! };
        Caveat(target, "null");
        (await Verifier().VerifyInvocationDetailedAsync(invocation, leaf, root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact]
    public async Task DiInvocation_RejectsEmbeddedCaveat_WithoutRejectingApplicationFields()
    {
        var (root, leaf) = await Chain();
        var app = new JsonObject
        {
            ["@context"] = new JsonArray("https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1"),
            ["id"] = "urn:uuid:" + Guid.NewGuid(), ["type"] = "https://example.com/Request",
            ["caveat"] = new JsonObject { ["id"] = "https://example.com/application-note" }
        };
        var doc = await _signing.SignCapabilityInvocationAsync(InvocationCapability.FromCapability(leaf), "read", leaf.InvocationTarget, _holder, app);
        (await Verifier().VerifyCapabilityInvocationAsync(doc, "read", [leaf.InvocationTarget], root)).Should().BeTrue();
        doc["proof"]!["capability"]!["caveat"] = new JsonArray();
        (await Verifier().VerifyCapabilityInvocationDetailedAsync(doc, "read", [leaf.InvocationTarget], rootCapability: root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact]
    public async Task EditingLegacyCaveatType_NeverReturnsValid()
    {
        var (root, leaf) = await Chain();
        Caveat(leaf, "[{\"type\":\"UsageCount\",\"maxUses\":0}]");
        await ResignLegacy(leaf, _owner);
        Caveat(leaf, "[{\"type\":\"ValidWhileTrue\",\"uri\":\"https://holder.example/valid\"}]");
        (await Verifier().VerifyCapabilityProofDetailedAsync(Copy(leaf), root)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Theory]
    [InlineData("argument")]
    [InlineData("root")]
    [InlineData("body")]
    [InlineData("proof")]
    public async Task RevocationChecksAllCapabilityRepresentations_BeforeRecording(string location)
    {
        var (root, leaf) = await Chain();
        var store = new InMemoryRevocationStore();
        var verifier = new VerificationService(_dids, new RevocationService(store));
        var request = await _signing.SignRevocationAsync(leaf.Id, _owner, leaf.InvocationTarget);
        var embedded = Copy(leaf);
        switch (location)
        {
            case "argument": Caveat(leaf, "null"); break;
            case "root": Caveat(root, "null"); break;
            case "body":
                Caveat(embedded, "null");
                request.Capability = InvocationCapability.FromCapability(embedded);
                break;
            case "proof":
                Caveat(embedded, "null");
                request.Proof!.Capability = InvocationCapability.FromCapability(embedded);
                break;
        }
        // Sign below the public boundary to exercise verification of a valid legacy signature.
        var bytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            ProofSigningPayloadBuilder.CloneInvocationWithoutProof(request), request.Proof!);
        request.Proof!.ProofValue = MultibaseCodec.Encode((await _dids.SignAsync(_owner, bytes)).Signature);
        (await verifier.RevokeCapabilityAsync(leaf, request, root)).Should().BeFalse();
        (await store.GetByCapabilityIdAsync(leaf.Id)).Should().BeNull();

        leaf.AdditionalProperties?.Remove("caveat");
        root.AdditionalProperties?.Remove("caveat");
        var clean = await _signing.SignRevocationAsync(leaf.Id, _owner, leaf.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(leaf, clean, root)).Should().BeTrue();
        (await store.GetByCapabilityIdAsync(leaf.Id)).Should().NotBeNull();
    }

    [Fact]
    public void ProfileInspection_BoundsWideAndDeepJsonGraphs()
    {
        CapabilityProfile.IsSupported(new Capability(), Enumerable.Repeat<object>("urn:test", 1023).ToArray()).Should().BeTrue();
        CapabilityProfile.IsSupported(new Capability(), Enumerable.Repeat<object>("urn:test", 1024).ToArray()).Should().BeFalse();
        foreach (var depth in new[] { 10, 40 })
        {
            var json = "{}";
            for (var i = 0; i < depth; i++) json = "{\"proof\":{\"capabilityChain\":[" + json + "]}}";
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256 });
            CapabilityProfile.IsSupported(new Capability(), [doc.RootElement]).Should().Be(depth == 10);
        }
    }

    [Fact]
    public void ProgrammaticCycles_FailClosed()
    {
        var cap = new Capability();
        cap.Proof = new Proof { CapabilityChain = [cap] };
        CapabilityProfile.IsSupported(cap).Should().BeFalse();
    }

    [Theory]
    [InlineData("", "", true)]
    [InlineData("", "/child", true)]
    [InlineData("", "?section=one", true)]
    [InlineData("?section=one", "&view=summary", true)]
    [InlineData("", "child", false)]
    [InlineData("", "&section=one", false)]
    [InlineData("?section=one", "?view=summary", false)]
    [InlineData("?section=one", "/child", false)]
    [InlineData("", "/../secret", false)]
    public async Task TargetPolicy_GatesDelegationAndBothInvocationForms(string baseSuffix, string suffix, bool validNarrowing)
    {
        var (root, leaf) = await Chain("https://example.com/r" + baseSuffix);
        var target = leaf.InvocationTarget + suffix;
        foreach (var allow in new[] { false, true })
        {
            var expected = suffix.Length == 0 || (allow && validNarrowing);
            var envelope = _caps.CreateInvocation(leaf, "read", target);
            envelope.Proof = await _signing.SignInvocationAsync(envelope, _holder);
            (await Verifier(allow).VerifyInvocationAsync(envelope, leaf, root)).Should().Be(expected);
            var doc = await _signing.SignCapabilityInvocationAsync(InvocationCapability.FromCapability(leaf), "read", target, _holder);
            (await Verifier(allow).VerifyCapabilityInvocationAsync(doc, "read", [target], root)).Should().Be(expected);
            // Use a valid signer with a deliberately chosen target so verification is tested
            // independently of the creation-time attenuation check.
            var child = Copy(leaf);
            child.InvocationTarget = target;
            child.Proof = await _signing.SignCapabilityAsync(child, _owner, "capabilityDelegation", [root.Id]);
            (await Verifier(allow).VerifyCapabilityProofAsync(child, root)).Should().Be(expected);
            (await Verifier(allow).VerifyCapabilityChainAsync(child, root)).Should().Be(expected);
        }
        if (validNarrowing)
        {
            var created = await _caps.DelegateCapabilityAsync(root, _holder, ["read"], DateTime.UtcNow.AddDays(1), invocationTarget: target);
            created.InvocationTarget.Should().Be(target);
        }
        else
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _caps.DelegateCapabilityAsync(root, _holder, ["read"], DateTime.UtcNow.AddDays(1), invocationTarget: target));
        }
    }
}
