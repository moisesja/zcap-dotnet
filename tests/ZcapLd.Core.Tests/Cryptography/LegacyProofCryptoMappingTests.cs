using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Pins the load-bearing <see cref="LegacyProofCrypto.ToDataIntegrityProof"/> round-trip
/// (review feedback on PR #109). zcap maps its <see cref="Proof"/> to DataProofs'
/// <c>DataIntegrityProof</c> by JSON round-trip; every zcap-specific field (<c>capabilityChain</c>
/// incl. an embedded delegated capability object, <c>capability</c>, <c>capabilityAction</c>,
/// <c>invocationTarget</c>) MUST land in <c>AdditionalProperties</c> so DataProofs folds it into the
/// signing payload. If DataProofs ever "knows" one of those names — or its AdditionalProperties
/// handling changes — the field vanishes from signed bytes silently, because the sign and verify
/// paths share this mapping symmetrically (an in-process round-trip would still pass with the field
/// dropped on both sides). The existing golden vectors only exercise a first-level delegation, so
/// these assert the deeper invocation/multi-entry-chain shapes the reviewer flagged as uncovered.
/// </summary>
public class LegacyProofCryptoMappingTests
{
    private const string RootId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource";
    private const string Target = "https://example.com/api/resource";

    private static Capability EmbeddedParent() => new()
    {
        Id = "urn:uuid:11111111-1111-1111-1111-111111111111",
        Controller = "did:key:z6MkParentController",
        InvocationTarget = Target,
        AllowedAction = new[] { "read" },
        ParentCapability = RootId,
        // A nested proof on the embedded parent — confirms nesting survives the round-trip.
        Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkParentController#z6MkParentController",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofValue = "zParentProofValue",
            CapabilityChain = new object[] { RootId },
        },
    };

    [Fact(DisplayName = "Mapping: multi-entry capabilityChain (incl. embedded capability) survives into AdditionalProperties")]
    public void DelegationProof_MultiEntryChain_RoundTripsFaithfully()
    {
        var parent = EmbeddedParent();
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkChildController#z6MkChildController",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofValue = "zChildProofValue",
            // Deep chain: [ rootId (string), {embedded immediate parent} ] — the spec-exact shape
            // for a second-level delegation that the first-level golden never exercises.
            CapabilityChain = new object[] { RootId, parent },
        };

        var di = LegacyProofCrypto.ToDataIntegrityProof(proof);

        // Modeled members map onto the strongly-typed properties...
        di.Type.Should().Be("Ed25519Signature2020");
        di.ProofPurpose.Should().Be("capabilityDelegation");
        di.VerificationMethod.Should().Be("did:key:z6MkChildController#z6MkChildController");
        di.ProofValue.Should().Be("zChildProofValue");

        // ...and capabilityChain rides in AdditionalProperties, faithfully.
        di.AdditionalProperties.Should().NotBeNull();
        di.AdditionalProperties!.Should().ContainKey("capabilityChain");

        var chain = di.AdditionalProperties["capabilityChain"];
        chain.ValueKind.Should().Be(JsonValueKind.Array);
        chain.GetArrayLength().Should().Be(2);

        var first = chain[0];
        first.ValueKind.Should().Be(JsonValueKind.String, "the root is referenced by id only");
        first.GetString().Should().Be(RootId);

        var embedded = chain[1];
        embedded.ValueKind.Should().Be(JsonValueKind.Object, "the immediate parent is fully embedded");
        embedded.GetProperty("id").GetString().Should().Be(parent.Id);
        embedded.GetProperty("invocationTarget").GetString().Should().Be(Target);
        embedded.GetProperty("allowedAction")[0].GetString().Should().Be("read");
        embedded.GetProperty("parentCapability").GetString().Should().Be(RootId);
        // The embedded parent's own nested proof must survive too.
        embedded.GetProperty("proof").GetProperty("proofValue").GetString().Should().Be("zParentProofValue");
    }

    [Fact(DisplayName = "Mapping: invocation capability + capabilityAction + invocationTarget survive into AdditionalProperties")]
    public void InvocationProof_EmbeddedCapabilityAndAction_RoundTripsFaithfully()
    {
        var delegated = EmbeddedParent();
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = "did:key:z6MkInvokerController#z6MkInvokerController",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofValue = "zInvocationProofValue",
            // Per ZCAP-LD v0.3 a delegated DI invocation embeds the FULL delegated zcap object.
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target,
        };

        var di = LegacyProofCrypto.ToDataIntegrityProof(proof);

        di.AdditionalProperties.Should().NotBeNull();
        di.AdditionalProperties!.Should().ContainKeys("capability", "capabilityAction", "invocationTarget");

        var capability = di.AdditionalProperties["capability"];
        capability.ValueKind.Should().Be(JsonValueKind.Object, "a delegated invocation embeds the full zcap, not just its id");
        capability.GetProperty("id").GetString().Should().Be(delegated.Id);
        capability.GetProperty("invocationTarget").GetString().Should().Be(Target);

        di.AdditionalProperties["capabilityAction"].GetString().Should().Be("read");
        di.AdditionalProperties["invocationTarget"].GetString().Should().Be(Target);

        // Modeled members never leak into AdditionalProperties (clean separation).
        di.AdditionalProperties.Should().NotContainKeys("type", "proofPurpose", "verificationMethod", "proofValue", "created");
    }
}
