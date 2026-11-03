using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Pins the one wire-compatibility break of the DataProofs 2.0.0 upgrade (PR #163 review). dotNetRDF 3.5.1's
/// RDFC canonicalizer, which DataProofs 1.5.0 and zcap 5.x used, labels tied blank nodes in the wrong
/// order (dotnetrdf#917). A delegation whose proof options embed a parent carrying two or more delegation
/// proofs canonicalizes those proof graphs as tied blank nodes, so a child signed under the old labelling
/// verifies under the corrected one only when the old traversal order happened to be right. The fixtures
/// were generated at 2f27deb (DataProofs 1.5.0) and verified there; <c>-affected</c> fails here and must be
/// reissued, <c>-unaffected</c> still verifies. Parents and single-proof chains are not affected.
/// </summary>
public class DataProofsCanonicalizationCompatibilityTests
{
    private static readonly string FixtureDirectory =
        Path.Combine(FindRepositoryRoot(), "tests", "ZcapLd.Core.Tests", "Compliance", "fixtures");

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "ZcapLd.sln")))
            directory = Path.GetDirectoryName(directory);
        return directory ?? throw new InvalidOperationException("ZcapLd.sln not found above the test assembly.");
    }

    private static (Capability Root, Capability Parent, Capability Child) Load(string name)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(FixtureDirectory, name)));
        Capability Read(string member) =>
            JsonSerializer.Deserialize<Capability>(document.RootElement.GetProperty(member).GetRawText(), ZcapJsonOptions.Default)!;
        return (Read("root"), Read("parent"), Read("child"));
    }

    private static VerificationService VerifierFor(Capability root)
    {
        // The fixtures use real did:key controllers, so public keys resolve from the DIDs themselves.
        var dids = new InMemoryDidProvider();
        dids.RegisterRoot(root);
        return new VerificationService(dids);
    }

    [Fact(DisplayName = "A 5.x child over a co-signed parent whose old labelling was wrong no longer verifies: reissue it")]
    public async Task AffectedPreUpgradeChain_ReturnsInvalidSignature()
    {
        var (root, parent, child) = Load("dataproofs-1.5.0-cosigned-chain-affected.json");
        var verifier = VerifierFor(root);
        parent.Proof!.Values.Should().HaveCount(2, "the parent is co-signed, which is what makes the embedded proof graphs tie");

        (await verifier.VerifyCapabilityChainDetailedAsync(parent)).Outcome.Should().Be(VerificationOutcome.Valid,
            "the parent's own proof options embed only the root id, so its bytes did not change");
        (await verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.InvalidSignature,
            "the child was signed over dotNetRDF's defective labelling of the parent's tied proof graphs");
        (await verifier.VerifyCapabilityProofDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "A 5.x child over a co-signed parent whose old labelling happened to be right still verifies")]
    public async Task UnaffectedPreUpgradeChain_StillVerifies()
    {
        var (root, parent, child) = Load("dataproofs-1.5.0-cosigned-chain-unaffected.json");
        var verifier = VerifierFor(root);
        parent.Proof!.Values.Should().HaveCount(2);

        (await verifier.VerifyCapabilityChainDetailedAsync(parent)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await verifier.VerifyCapabilityProofDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "The same co-signed shape issued under the corrected canonicalizer verifies")]
    public async Task CoSignedChain_IssuedNow_Verifies()
    {
        var dids = new InMemoryDidProvider();
        var signing = new SigningService(dids, dids);
        var caps = new CapabilityService(signing);
        var verifier = new VerificationService(dids);
        var ownerA = dids.GenerateDidKey();
        var ownerB = dids.GenerateDidKey();
        var mid = dids.GenerateDidKey();
        var holder = dids.GenerateDidKey();
        var root = dids.RegisterRoot(await caps.CreateRootCapabilityAsync(new[] { ownerA, ownerB }, "https://compat.example/reissued", new[] { "read" }));
        var parent = await caps.DelegateCapabilityAsync(root, mid, new[] { "read" }, DateTime.UtcNow.AddHours(2), signerDid: ownerA);
        var second = await signing.SignCapabilityAsync(parent, ownerB, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        parent.Proof = ProofSet.FromValues(new[] { parent.Proof!.Primary, second });

        // Reissuance: the child is delegated again under 6.0 over the same co-signed parent.
        var child = await caps.DelegateCapabilityAsync(parent, holder, new[] { "read" }, DateTime.UtcNow.AddHours(1));

        (await verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await verifier.VerifyCapabilityChainDetailedAsync(CapabilityJson.Parse(CapabilityJson.Serialize(child)))).Outcome
            .Should().Be(VerificationOutcome.Valid);
    }
}
