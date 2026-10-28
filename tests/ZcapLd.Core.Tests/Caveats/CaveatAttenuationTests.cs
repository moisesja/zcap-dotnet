using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Children signed consistently by a key of the attacker's choosing — including the real parent
/// controller — must still not widen or drop an inherited caveat (#157). Post-signing tampering is
/// covered separately; here every signature is genuine.
/// </summary>
public class CaveatAttenuationTests
{
    private const string Zcap = "https://w3id.org/zcap/v1";
    private const string Ed25519 = "https://w3id.org/security/suites/ed25519-2020/v1";
    private readonly CaveatTestBed _bed = new();

    private static Capability Child(Capability parent, string controller, params object[] caveats)
    {
        var context = new List<object> { Zcap, Ed25519 };
        context.AddRange(caveats.Select(c => (string)((dynamic)c).type).Distinct().Select(CaveatTypeRegistry.GetContextUrl));
        return new Capability
        {
            Context = context.ToArray(),
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = parent.Id,
            Controller = controller,
            InvocationTarget = parent.InvocationTarget,
            AllowedAction = parent.AllowedAction,
            Expires = parent.Expires, // equal to the parent's, so only caveats can violate attenuation
            AdditionalProperties = caveats.Length == 0
                ? null
                : new Dictionary<string, JsonElement> { ["caveat"] = JsonSerializer.SerializeToElement(caveats) },
        };
    }

    private static object[] ChainFor(CaveatTestBed.Chain chain, Capability parent)
        => parent.Id == chain.Orchestrator.Id ? new object[] { chain.Root.Id, chain.Orchestrator } : new object[] { chain.Root.Id };

    private async Task<Capability> SignAsync(Capability child, string signer, object[] capabilityChain)
    {
        child.Proof = await _bed.Signing.SignCapabilityAsync(child, signer, "capabilityDelegation", capabilityChain);
        return child;
    }

    private async Task<VerificationResult> InvokeAsync(Capability capability, string signer)
    {
        var invocation = _bed.Capabilities.CreateInvocation(capability, "query");
        invocation.Proof = await _bed.Signing.SignInvocationAsync(invocation, signer);
        return await _bed.Verifier.VerifyInvocationDetailedAsync(invocation, capability);
    }

    [Fact(DisplayName = "Parent controller signs a child with a larger budget: attenuation violation")]
    public async Task WidenedChild_SignedByParentController_Rejected()
    {
        var chain = await _bed.BuildChainAsync();
        var holder = _bed.Keys.GenerateDidKey();
        var child = await SignAsync(Child(chain.Orchestrator, holder, new { maxEpsilon = 9, type = "EpsilonBudget" }),
            chain.OrchestratorDid, ChainFor(chain, chain.Orchestrator));

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
        (await _bed.Verifier.VerifyCapabilityProofDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
        (await InvokeAsync(child, holder)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
        _bed.Ledger.Calls.Should().Be(0);
    }

    [Fact(DisplayName = "Parent controller signs a child without the caveat: attenuation violation")]
    public async Task DroppedCaveat_SignedByParentController_Rejected()
    {
        var chain = await _bed.BuildChainAsync();
        var holder = _bed.Keys.GenerateDidKey();
        var child = await SignAsync(Child(chain.Agent, holder), chain.AgentDid,
            new object[] { chain.Root.Id, chain.Orchestrator.Id, chain.Agent });

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
        (await _bed.Verifier.VerifyCapabilityProofDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
        (await InvokeAsync(child, holder)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
    }

    [Fact(DisplayName = "Positive control: same construction with a narrower budget and an added caveat is accepted")]
    public async Task NarrowedChild_Accepted()
    {
        var chain = await _bed.BuildChainAsync();
        var holder = _bed.Keys.GenerateDidKey();
        var child = await SignAsync(
            Child(chain.Orchestrator, holder, new { maxEpsilon = 7.5, type = "EpsilonBudget" }, new { data = "radiology", type = "Tag" }),
            chain.OrchestratorDid, ChainFor(chain, chain.Orchestrator));
        var verifier = _bed.NewVerifier(new ICaveatHandler[]
            { _bed.Ledger, new ScriptedCaveatHandler("Tag", _ => CaveatDecision.Satisfied) });
        var invocation = _bed.Capabilities.CreateInvocation(child, "query");
        invocation.Proof = await _bed.Signing.SignInvocationAsync(invocation, holder);

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired);
        (await verifier.VerifyInvocationDetailedAsync(invocation, child)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "A caveat type added mid-chain must be restated below")]
    public async Task AddedTypeDroppedBelow_Rejected()
    {
        var chain = await _bed.BuildChainAsync();
        var mid = _bed.Keys.GenerateDidKey();
        var holder = _bed.Keys.GenerateDidKey();
        var withRegion = await _bed.Capabilities.DelegateCapabilityAsync(chain.Agent, mid, new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us", "eu" } } });
        var dropsRegion = await SignAsync(Child(withRegion, holder, new { maxEpsilon = 1, type = "EpsilonBudget" }), mid,
            new object[] { chain.Root.Id, chain.Orchestrator.Id, chain.Agent.Id, withRegion });

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(dropsRegion)).Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
    }

    [Fact(DisplayName = "A key the parent controller does not authorize cannot sign a child")]
    public async Task SelfSignedByAttacker_UnauthorizedController()
    {
        var chain = await _bed.BuildChainAsync();
        var attacker = _bed.Keys.GenerateDidKey();
        var child = await SignAsync(Child(chain.Orchestrator, attacker, new { maxEpsilon = 8, type = "EpsilonBudget" }),
            attacker, ChainFor(chain, chain.Orchestrator));

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
    }

    [Fact(DisplayName = "A proof naming the parent's verification method but signed by another key fails")]
    public async Task ForeignKeyUnderParentVerificationMethod_InvalidSignature()
    {
        var chain = await _bed.BuildChainAsync();
        var attacker = _bed.Keys.GenerateDidKey();
        var child = Child(chain.Orchestrator, attacker, new { maxEpsilon = 100, type = "EpsilonBudget" });
        var proof = await RawProofSigner.SignCapabilityAsync(_bed.Keys, child, attacker, ChainFor(chain, chain.Orchestrator),
            new RdfcDocumentCanonicalizer(_bed.Registry));
        proof.VerificationMethod = await _bed.Keys.GetVerificationMethodAsync(chain.OrchestratorDid);
        child.Proof = proof;

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "A mid-chain delegator cannot raise its own budget in the embedded copy of its grant")]
    public async Task MidChainDelegatorEditsEmbeddedParent_Rejected()
    {
        var chain = await _bed.BuildChainAsync();
        var holder = _bed.Keys.GenerateDidKey();
        // The orchestrator delegates under a copy of its own grant whose budget it raised to 1000.
        var forgedParent = CapabilityJson.Edit(chain.Orchestrator, json => json["caveat"]![0]!["maxEpsilon"] = 1000);
        var child = await SignAsync(Child(forgedParent, holder, new { maxEpsilon = 500, type = "EpsilonBudget" }),
            chain.OrchestratorDid, new object[] { chain.Root.Id, forgedParent });

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(child)).Outcome.Should().Be(VerificationOutcome.InvalidSignature);
        (await InvokeAsync(child, holder)).IsValid.Should().BeFalse();
    }

    [Fact(DisplayName = "A chain under a different root is refused when the relying party pins its root")]
    public async Task RootSubstitution_RefusedByPin()
    {
        var chain = await _bed.BuildChainAsync();
        var other = await _bed.BuildChainAsync(target: "https://other.example/fhir");
        var document = await _bed.Signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(other.Agent), "query", other.Agent.InvocationTarget, other.AgentDid);

        (await _bed.Verifier.VerifyCapabilityInvocationDetailedAsync(document, "query", new[] { other.Agent.InvocationTarget },
            expectedRootCapabilityIds: new[] { chain.Root.Id })).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        _bed.Ledger.Calls.Should().Be(0);
    }

    [Fact(DisplayName = "Swapping the root id in the signed chain breaks the signature")]
    public async Task SwappedRootId_Rejected()
    {
        var chain = await _bed.BuildChainAsync();
        var other = await _bed.BuildChainAsync(target: "https://swap.example/fhir");

        var swapped = CapabilityJson.Edit(chain.Orchestrator, json =>
        {
            json["parentCapability"] = other.Root.Id;
            json["proof"]!["capabilityChain"] = new JsonArray(other.Root.Id);
        });

        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(swapped)).IsValid.Should().BeFalse();
        (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(swapped)).Outcome
            .Should().NotBe(VerificationOutcome.CaveatEnforcementRequired);
    }
}
