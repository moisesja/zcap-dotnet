using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Issuing caveats, their wire shape, and which APIs may treat a caveat-bearing chain as valid
/// (#157). The standard profile (no registry) is unchanged and still rejects every caveat.
/// </summary>
public class CaveatIssuanceAndProfileTests
{
    private readonly CaveatTestBed _bed = new();

    [Fact(DisplayName = "Wire shape: caveat array as before, plus the type's pinned context")]
    public async Task Delegation_WireShape()
    {
        var chain = await _bed.BuildChainAsync();
        using var json = JsonDocument.Parse(CapabilityJson.Serialize(chain.Agent));

        json.RootElement.GetProperty("caveat").GetRawText().Should().Be("[{\"maxEpsilon\":3,\"type\":\"EpsilonBudget\"}]");
        json.RootElement.GetProperty("@context").EnumerateArray().Select(e => e.GetString()).Should().Equal(
            "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1",
            "urn:zcap-dotnet:caveat-context:v1:EpsilonBudget");
    }

    [Fact(DisplayName = "A caveat-free delegation from a caveat-enabled issuer keeps the standard shape")]
    public async Task CaveatFreeDelegation_HasNoCaveatContext()
    {
        var owner = _bed.Keys.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_bed.Capabilities, _bed.Keys, owner, "https://plain.example/r");
        var delegated = await _bed.Capabilities.DelegateCapabilityAsync(
            root, _bed.Keys.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(1));

        CapabilityJson.Serialize(delegated).Should().NotContain("caveat");
        var standardVerifier = new VerificationService(_bed.Keys);
        (await standardVerifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "An unrestated parent caveat is inherited verbatim")]
    public async Task Delegation_InheritsParentCaveat()
    {
        var chain = await _bed.BuildChainAsync();
        var child = await _bed.Capabilities.DelegateCapabilityAsync(
            chain.Agent, _bed.Keys.GenerateDidKey(), new[] { "query" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });

        var caveats = child.GetCaveats(_bed.Registry);
        caveats.Select(c => c.Type).Should().Equal("EpsilonBudget", "Region");
        caveats.OfType<EpsilonBudgetCaveat>().Single().MaxEpsilon.Should().Be(3);
    }

    [Fact(DisplayName = "The issuer refuses to widen a parent caveat")]
    public async Task Delegation_Widening_Throws()
    {
        var chain = await _bed.BuildChainAsync();

        var act = () => _bed.Capabilities.DelegateCapabilityAsync(
            chain.Agent, _bed.Keys.GenerateDidKey(), new[] { "query" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 3.5 } });

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory(DisplayName = "The issuer refuses invalid or unrepresentable caveat values")]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1001)]
    [InlineData(0.00001)]
    public async Task Delegation_InvalidValue_Throws(double budget)
    {
        var owner = _bed.Keys.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_bed.Capabilities, _bed.Keys, owner, $"https://bad.example/{budget}");

        var act = () => _bed.Capabilities.DelegateCapabilityAsync(
            root, _bed.Keys.GenerateDidKey(), new[] { "query" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = budget } });

        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    [Fact(DisplayName = "Caveats need a registry on the issuer")]
    public async Task Delegation_WithoutRegistry_Throws()
    {
        var keys = new InMemoryDidProvider();
        var capabilities = new CapabilityService(new SigningService(keys, keys));
        var root = await TestRoots.CreateAndRegisterRootAsync(capabilities, keys, keys.GenerateDidKey(), "https://no-registry.example/r");

        var act = () => capabilities.DelegateCapabilityAsync(root, keys.GenerateDidKey(), new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 1 } });

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact(DisplayName = "Chain verification never authorizes caveats: CaveatEnforcementRequired with the grants")]
    public async Task ChainVerification_ReturnsEnforcementRequired()
    {
        var chain = await _bed.BuildChainAsync();

        var result = await _bed.Verifier.VerifyCapabilityChainDetailedAsync(chain.Agent);

        result.Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired);
        result.IsValid.Should().BeFalse();
        (await _bed.Verifier.VerifyCapabilityChainAsync(chain.Agent)).Should().BeFalse();
        result.Caveats!.Select(g => (g.CapabilityId, ((EpsilonBudgetCaveat)g.Caveat).MaxEpsilon))
            .Should().Equal((chain.Orchestrator.Id, 8d), (chain.Agent.Id, 3d));
        result.Caveats!.Select(g => g.GrantKey).Should().OnlyHaveUniqueItems().And.AllSatisfy(k => k.Should().HaveLength(64));
    }

    [Fact(DisplayName = "Standalone proof verification never authorizes caveats")]
    public async Task ProofVerification_ReturnsEnforcementRequired()
    {
        var chain = await _bed.BuildChainAsync();

        (await _bed.Verifier.VerifyCapabilityProofDetailedAsync(chain.Agent)).Outcome
            .Should().Be(VerificationOutcome.CaveatEnforcementRequired);
    }

    [Fact(DisplayName = "Positive control: EpsilonBudget verifies through both invocation forms")]
    public async Task Invocation_BothForms_Valid()
    {
        var chain = await _bed.BuildChainAsync();
        var envelope = await _bed.InvokeAsync(chain.Agent, chain.AgentDid);
        var document = await _bed.Signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(chain.Agent), "query", CaveatTestBed.Target, chain.AgentDid);

        (await _bed.Verifier.VerifyInvocationDetailedAsync(CaveatTestBed.RoundTrip(envelope), CaveatTestBed.RoundTrip(chain.Agent)))
            .Outcome.Should().Be(VerificationOutcome.Valid);
        (await _bed.Verifier.VerifyCapabilityInvocationDetailedAsync(document, "query", CaveatTestBed.Target))
            .Outcome.Should().Be(VerificationOutcome.Valid);
        _bed.Ledger.Calls.Should().Be(2);
    }

    [Fact(DisplayName = "Standard profile: a verifier without a registry rejects caveats everywhere")]
    public async Task StandardVerifier_RejectsCaveats()
    {
        var chain = await _bed.BuildChainAsync();
        var invocation = await _bed.InvokeAsync(chain.Agent, chain.AgentDid);
        var document = await _bed.Signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(chain.Agent), "query", CaveatTestBed.Target, chain.AgentDid);
        var standard = new VerificationService(_bed.Keys, new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), relationshipResolver: _bed.Keys, rootResolver: _bed.Keys);
        var revocation = await _bed.Signing.SignRevocationAsync(chain.Agent.Id, chain.OrchestratorDid, chain.Agent.InvocationTarget);

        (await standard.VerifyCapabilityChainDetailedAsync(chain.Agent)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await standard.VerifyCapabilityProofDetailedAsync(chain.Agent)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await standard.VerifyInvocationDetailedAsync(invocation, chain.Agent)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await standard.VerifyCapabilityInvocationDetailedAsync(document, "query", CaveatTestBed.Target)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
        (await standard.RevokeCapabilityAsync(chain.Agent, revocation)).Should().BeFalse();
    }

    [Fact(DisplayName = "Standard profile: a signer without a registry refuses caveat-bearing input")]
    public async Task StandardSigner_RefusesCaveats()
    {
        var chain = await _bed.BuildChainAsync();
        var standardSigning = new SigningService(_bed.Keys, _bed.Keys);
        var invocation = new CapabilityService(standardSigning);

        var act = () => invocation.CreateInvocation(chain.Agent, "query");

        act.Should().Throw<CapabilityValidationException>();
    }

    [Fact(DisplayName = "Revocation of a caveat-bearing capability needs no handler")]
    public async Task Revocation_WithoutHandlers_Succeeds()
    {
        var chain = await _bed.BuildChainAsync();
        var verifier = _bed.NewVerifier(handlers: null);
        var request = await _bed.Signing.SignRevocationAsync(chain.Agent.Id, chain.OrchestratorDid, chain.Agent.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(CaveatTestBed.RoundTrip(chain.Agent), request)).Should().BeTrue();
        (await _bed.Verifier.VerifyInvocationDetailedAsync(await _bed.InvokeAsync(chain.Agent, chain.AgentDid), chain.Agent))
            .Outcome.Should().Be(VerificationOutcome.Revoked);
        _bed.Ledger.Calls.Should().Be(0);
    }
}
