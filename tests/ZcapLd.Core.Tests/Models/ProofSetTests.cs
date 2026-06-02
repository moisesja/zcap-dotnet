using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>
/// Unit tests for <see cref="ProofSet"/> and its JSON converter (Issue #48).
/// Covers both spec-allowed wire shapes for a delegated zcap's <c>proof</c> (single object /
/// array of objects), shape preservation, malformed-value rejection, and delegation-proof
/// selection.
/// </summary>
public class ProofSetTests
{
    private static readonly JsonSerializerOptions Options = ZcapJsonOptions.Default;

    private const string DelegationProofJson =
        """{ "type": "Ed25519Signature2020", "proofPurpose": "capabilityDelegation", "capabilityChain": ["urn:zcap:root:x"], "proofValue": "z2delegation" }""";

    private const string AssertionProofJson =
        """{ "type": "Ed25519Signature2020", "proofPurpose": "assertionMethod", "proofValue": "z2assertion" }""";

    private static string Capability(string proofJson) =>
        $$"""
        {
          "@context": ["https://w3id.org/zcap/v1"],
          "id": "urn:uuid:delegated",
          "controller": "did:key:z6MkBob",
          "invocationTarget": "https://example.com/r",
          "parentCapability": "urn:zcap:root:x",
          "expires": "2027-01-01T00:00:00.000000Z",
          "proof": {{proofJson}}
        }
        """;

    // ─── Deserialization ───────────────────────────────────────────────

    [Fact]
    public void Deserialize_ProofAsObject_ProducesSingleProofSet()
    {
        var capability = JsonSerializer.Deserialize<Capability>(Capability(DelegationProofJson), Options)!;

        capability.Proof.Should().NotBeNull();
        capability.Proof!.IsArrayForm.Should().BeFalse();
        capability.Proof.Count.Should().Be(1);
        capability.Proof.Primary.ProofPurpose.Should().Be("capabilityDelegation");
    }

    [Fact]
    public void Deserialize_ProofAsArray_ProducesArrayProofSet()
    {
        var capability = JsonSerializer.Deserialize<Capability>(
            Capability($"[{AssertionProofJson}, {DelegationProofJson}]"), Options)!;

        capability.Proof.Should().NotBeNull();
        capability.Proof!.IsArrayForm.Should().BeTrue();
        capability.Proof.Count.Should().Be(2);
        capability.Proof.FirstDelegationProof().Should().NotBeNull();
        capability.Proof.FirstDelegationProof()!.ProofPurpose.Should().Be("capabilityDelegation");
        capability.Proof.FirstDelegationProof()!.CapabilityChain.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Deserialize_ProofArray_PreservesUnknownProofFields()
    {
        const string proofWithExtras =
            """{ "type": "Ed25519Signature2020", "proofPurpose": "capabilityDelegation", "capabilityChain": ["urn:zcap:root:x"], "domain": "https://resource.example", "nonce": "abc123", "proofValue": "z2" }""";

        var capability = JsonSerializer.Deserialize<Capability>(
            Capability($"[{proofWithExtras}]"), Options)!;

        var proof = capability.Proof!.Primary;
        proof.AdditionalProperties.Should().ContainKey("domain");
        proof.AdditionalProperties.Should().ContainKey("nonce");
    }

    // ─── Serialization (shape preservation) ────────────────────────────

    [Fact]
    public void Serialize_SingleProof_EmitsObject()
    {
        var capability = new Capability
        {
            Id = "urn:uuid:delegated",
            Controller = "did:key:z6MkBob",
            InvocationTarget = "https://example.com/r",
            Proof = new Proof { Type = "Ed25519Signature2020", ProofPurpose = "capabilityDelegation", ProofValue = "z2" }
        };

        var json = JsonSerializer.Serialize(capability, Options);

        json.Should().Contain("\"proof\":{");
        json.Should().NotContain("\"proof\":[");
    }

    [Fact]
    public void Serialize_MultipleProofs_EmitsArray()
    {
        var capability = new Capability
        {
            Id = "urn:uuid:delegated",
            Controller = "did:key:z6MkBob",
            InvocationTarget = "https://example.com/r",
            Proof = ProofSet.FromValues(new[]
            {
                new Proof { Type = "Ed25519Signature2020", ProofPurpose = "assertionMethod", ProofValue = "z1" },
                new Proof { Type = "Ed25519Signature2020", ProofPurpose = "capabilityDelegation", ProofValue = "z2" }
            })
        };

        var json = JsonSerializer.Serialize(capability, Options);

        json.Should().Contain("\"proof\":[");
        json.Should().Contain("\"assertionMethod\"");
        json.Should().Contain("\"capabilityDelegation\"");
    }

    [Fact]
    public void RoundTrip_SingleElementArray_StaysArrayForm()
    {
        var capability = JsonSerializer.Deserialize<Capability>(
            Capability($"[{DelegationProofJson}]"), Options)!;
        capability.Proof!.IsArrayForm.Should().BeTrue();

        var reserialized = JsonSerializer.Serialize(capability, Options);
        reserialized.Should().Contain("\"proof\":[");
    }

    // ─── Malformed-value rejection ─────────────────────────────────────

    [Fact]
    public void Deserialize_EmptyProofArray_Throws()
    {
        var act = () => JsonSerializer.Deserialize<Capability>(Capability("[]"), Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_ProofArrayWithNonObject_Throws()
    {
        var act = () => JsonSerializer.Deserialize<Capability>(
            Capability($"[{DelegationProofJson}, \"not-an-object\"]"), Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void FromValues_EmptyArray_Throws()
    {
        var act = () => ProofSet.FromValues(Array.Empty<Proof>());
        act.Should().Throw<ArgumentException>();
    }

    // ─── Delegation-proof selection ────────────────────────────────────

    [Fact]
    public void FirstDelegationProofWithChain_SkipsNonDelegationAndChainlessProofs()
    {
        var set = ProofSet.FromValues(new[]
        {
            new Proof { ProofPurpose = "assertionMethod", ProofValue = "z1" },
            new Proof { ProofPurpose = "capabilityDelegation", ProofValue = "z2" }, // no chain
            new Proof { ProofPurpose = "capabilityDelegation", CapabilityChain = new object[] { "urn:zcap:root:x" }, ProofValue = "z3" }
        });

        set.DelegationProofs().Should().HaveCount(2);
        set.FirstDelegationProof()!.ProofValue.Should().Be("z2");
        set.FirstDelegationProofWithChain()!.ProofValue.Should().Be("z3");
    }
}
