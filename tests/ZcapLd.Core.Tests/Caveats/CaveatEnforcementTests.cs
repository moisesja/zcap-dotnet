using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Resource-owned, stateful enforcement through <see cref="ICaveatHandler"/> (#157), using the
/// <see cref="InMemoryEpsilonLedger"/> test adapter: cumulative budgets, concurrency, replay,
/// retries, sibling grants and handler failure.
/// </summary>
public class CaveatEnforcementTests
{
    private readonly CaveatTestBed _bed = new();

    private async Task<VerificationOutcome> InvokeAsync(Capability capability, string signer, string action = "query")
        => (await _bed.Verifier.VerifyInvocationDetailedAsync(await _bed.InvokeAsync(capability, signer, action), capability)).Outcome;

    [Fact(DisplayName = "A budget of 3 allows costs 1 and 2, then denies a further 1")]
    public async Task CumulativeBudget_Exhausts()
    {
        var chain = await _bed.BuildChainAsync(agentBudget: 3);

        (await InvokeAsync(chain.Agent, chain.AgentDid, "query")).Should().Be(VerificationOutcome.Valid);
        (await InvokeAsync(chain.Agent, chain.AgentDid, "query-large")).Should().Be(VerificationOutcome.Valid);
        (await InvokeAsync(chain.Agent, chain.AgentDid, "query")).Should().Be(VerificationOutcome.CaveatNotSatisfied,
            "the action is allowed and the grant unexpired, but the signed ceiling is spent");
    }

    [Fact(DisplayName = "An action with no defined cost is denied by the resource")]
    public async Task UnknownCost_Denied()
    {
        var chain = await _bed.BuildChainAsync(actions: new[] { "query", "export" });

        (await InvokeAsync(chain.Agent, chain.AgentDid, "export")).Should().Be(VerificationOutcome.CaveatNotSatisfied);
    }

    [Fact(DisplayName = "Concurrent invocations never spend more than the ceiling")]
    public async Task Concurrent_NeverOverspends()
    {
        var chain = await _bed.BuildChainAsync(orchestratorBudget: 20, agentBudget: 10);
        var invocations = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => _bed.InvokeAsync(chain.Agent, chain.AgentDid)));

        var outcomes = await Task.WhenAll(invocations.Select(i => _bed.Verifier.VerifyInvocationDetailedAsync(i, chain.Agent)));

        outcomes.Count(o => o.Outcome == VerificationOutcome.Valid).Should().Be(10);
        outcomes.Count(o => o.Outcome == VerificationOutcome.CaveatNotSatisfied).Should().Be(40);
        var grants = (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(chain.Agent)).Caveats!;
        _bed.Ledger.Spent(grants[1].GrantKey).Should().Be(10);
        _bed.Ledger.Spent(grants[0].GrantKey).Should().Be(10);
    }

    [Fact(DisplayName = "A replayed invocation is refused and never reaches the handler")]
    public async Task Replay_DoesNotSpend()
    {
        var chain = await _bed.BuildChainAsync();
        var invocation = await _bed.InvokeAsync(chain.Agent, chain.AgentDid);

        (await _bed.Verifier.VerifyInvocationDetailedAsync(invocation, chain.Agent)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _bed.Verifier.VerifyInvocationDetailedAsync(CaveatTestBed.RoundTrip(invocation), chain.Agent)).Outcome
            .Should().Be(VerificationOutcome.Replayed);

        _bed.Ledger.Calls.Should().Be(1);
        var grants = (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(chain.Agent)).Caveats!;
        _bed.Ledger.Spent(grants[^1].GrantKey).Should().Be(1);
    }

    [Fact(DisplayName = "After a denial the client retries with a new invocation id; the old one is consumed")]
    public async Task RetryAfterDenial_NeedsNewId()
    {
        var chain = await _bed.BuildChainAsync(agentBudget: 1);
        (await InvokeAsync(chain.Agent, chain.AgentDid, "query")).Should().Be(VerificationOutcome.Valid);
        var denied = await _bed.InvokeAsync(chain.Agent, chain.AgentDid, "query");
        (await _bed.Verifier.VerifyInvocationDetailedAsync(denied, chain.Agent)).Outcome.Should().Be(VerificationOutcome.CaveatNotSatisfied);

        (await _bed.Verifier.VerifyInvocationDetailedAsync(denied, chain.Agent)).Outcome.Should().Be(VerificationOutcome.Replayed);
    }

    [Fact(DisplayName = "Siblings share their parent's budget")]
    public async Task Siblings_ShareParentBudget()
    {
        var chain = await _bed.BuildChainAsync(orchestratorBudget: 3, agentBudget: 3);
        var sibling = _bed.Keys.GenerateDidKey();
        var siblingGrant = await _bed.Capabilities.DelegateCapabilityAsync(chain.Orchestrator, sibling,
            new[] { "query", "query-large" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 3 } });

        (await InvokeAsync(chain.Agent, chain.AgentDid, "query-large")).Should().Be(VerificationOutcome.Valid);
        (await InvokeAsync(siblingGrant, sibling, "query")).Should().Be(VerificationOutcome.Valid);
        (await InvokeAsync(siblingGrant, sibling, "query")).Should().Be(VerificationOutcome.CaveatNotSatisfied,
            "each sibling has 3 of its own, but together they may not exceed the orchestrator's 3");
    }

    [Fact(DisplayName = "Grant keys differ by chain position even when an issuer reuses a capability id")]
    public async Task GrantKeys_ArePathBound()
    {
        var first = await _bed.BuildChainAsync(target: "https://a.example/fhir");
        var otherOwner = _bed.Keys.GenerateDidKey();
        var otherRoot = await TestRoots.CreateAndRegisterRootAsync(_bed.Capabilities, _bed.Keys, otherOwner, "https://b.example/fhir");
        // Another issuer mints a grant that reuses the first orchestrator grant's id.
        var reused = CapabilityJson.Edit(first.Orchestrator, json =>
        {
            json.Remove("proof");
            json["parentCapability"] = otherRoot.Id;
            json["invocationTarget"] = otherRoot.InvocationTarget;
        });
        reused.Proof = await _bed.Signing.SignCapabilityAsync(reused, otherOwner, "capabilityDelegation", new object[] { otherRoot.Id });

        var firstGrant = (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(first.Orchestrator)).Caveats!.Single();
        var reusedGrant = (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(reused)).Caveats!.Single();

        reusedGrant.CapabilityId.Should().Be(firstGrant.CapabilityId);
        reusedGrant.GrantKey.Should().NotBe(firstGrant.GrantKey, "a ledger keyed by GrantKey must not mix the two budgets");
        firstGrant.GrantKey.Should().Be(ZcapLd.Core.Cryptography.CaveatCodec.GrantKey(new[] { first.Root.Id, first.Orchestrator.Id }));
    }

    [Fact(DisplayName = "Handlers run in type order; a later denial releases earlier allowances")]
    public async Task LaterDenial_ReleasesEarlier()
    {
        var region = new ScriptedCaveatHandler("Region", _ => CaveatDecision.Deny("outside the allowed regions"));
        var bed = new CaveatTestBed(new InMemoryEpsilonLedger(), region);
        var chain = await bed.BuildChainAsync();
        var regional = await bed.Capabilities.DelegateCapabilityAsync(chain.Agent, chain.AgentDid, new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });
        var invocation = await bed.InvokeAsync(regional, chain.AgentDid);

        var result = await bed.Verifier.VerifyInvocationDetailedAsync(invocation, regional);

        result.Outcome.Should().Be(VerificationOutcome.CaveatNotSatisfied);
        result.Message.Should().Be("outside the allowed regions");
        bed.Ledger.Calls.Should().Be(1, "EpsilonBudget sorts before Region");
        bed.Ledger.Releases.Should().Be(1);
        var grants = (await bed.Verifier.VerifyCapabilityChainDetailedAsync(regional)).Caveats!;
        grants.Where(g => g.Caveat is EpsilonBudgetCaveat).Should().AllSatisfy(g => bed.Ledger.Spent(g.GrantKey).Should().Be(0));
    }

    [Fact(DisplayName = "A failing handler fails closed and releases earlier allowances")]
    public async Task HandlerFault_CouldNotVerify()
    {
        var region = new ScriptedCaveatHandler("Region", _ => throw new TimeoutException("ledger unavailable"));
        var bed = new CaveatTestBed(new InMemoryEpsilonLedger(), region);
        var chain = await bed.BuildChainAsync();
        var regional = await bed.Capabilities.DelegateCapabilityAsync(chain.Agent, chain.AgentDid, new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });

        var result = await bed.Verifier.VerifyInvocationDetailedAsync(await bed.InvokeAsync(regional, chain.AgentDid), regional);

        result.Outcome.Should().Be(VerificationOutcome.CouldNotVerify);
        bed.Ledger.Releases.Should().Be(1);
    }

    [Fact(DisplayName = "The handler sees only authenticated invocation data")]
    public async Task HandlerContext_IsAuthenticated()
    {
        CaveatEnforcementContext? seen = null;
        var ledger = new ScriptedCaveatHandler("EpsilonBudget", context => { seen = context; return CaveatDecision.Satisfied; });
        var bed = new CaveatTestBed(ledger);
        var chain = await bed.BuildChainAsync();
        var document = await bed.Signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(chain.Agent), "query-large", CaveatTestBed.Target, chain.AgentDid);

        (await bed.Verifier.VerifyCapabilityInvocationDetailedAsync(document, "query-large", CaveatTestBed.Target)).Outcome
            .Should().Be(VerificationOutcome.Valid);

        seen!.CapabilityAction.Should().Be("query-large");
        seen.InvocationTarget.Should().Be(CaveatTestBed.Target);
        seen.InvocationId.Should().Be(document["id"]!.GetValue<string>());
        seen.RootCapabilityId.Should().Be(chain.Root.Id);
        seen.Chain.Select(c => c.Id).Should().Equal(chain.Root.Id, chain.Orchestrator.Id, chain.Agent.Id);
        seen.Grants.Select(g => ((EpsilonBudgetCaveat)g.Caveat).MaxEpsilon).Should().Equal(8, 3);
        seen.VerificationMethod.Should().StartWith(chain.AgentDid);
    }

    [Fact(DisplayName = "Envelope invocation: the embedded capability must be the one verified")]
    public async Task EnvelopeEmbeddedMismatch_Malformed()
    {
        var chain = await _bed.BuildChainAsync();
        var looser = await _bed.Capabilities.DelegateCapabilityAsync(chain.Orchestrator, chain.AgentDid,
            new[] { "query" }, DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 8 } });
        var sameIdLooser = CapabilityJson.Edit(looser, json => json["id"] = chain.Agent.Id);
        var invocation = _bed.Capabilities.CreateInvocation(sameIdLooser, "query");
        invocation.Proof = await _bed.Signing.SignInvocationAsync(invocation, chain.AgentDid);

        (await _bed.Verifier.VerifyInvocationDetailedAsync(invocation, chain.Agent)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability);
        _bed.Ledger.Calls.Should().Be(0);
    }

    [Fact(DisplayName = "An invocation id reused after the nonce window is charged again (red-team F1)")]
    public async Task ReusedIdAfterNonceWindow_IsCharged()
    {
        var verifier = new VerificationService(_bed.Keys, new RevocationService(_bed.Revocations), new InMemoryNonceStore(),
            nonceWindow: TimeSpan.FromMilliseconds(400), relationshipResolver: _bed.Keys, rootResolver: _bed.Keys,
            caveats: _bed.Registry, caveatHandlers: new[] { _bed.Ledger });
        var chain = await _bed.BuildChainAsync(agentBudget: 3);
        async Task<VerificationOutcome> InvokeWithIdAsync(string id, string action)
        {
            var invocation = _bed.Capabilities.CreateInvocation(chain.Agent, action);
            invocation.Id = id;
            invocation.Proof = await _bed.Signing.SignInvocationAsync(invocation, chain.AgentDid);
            return (await verifier.VerifyInvocationDetailedAsync(invocation, chain.Agent)).Outcome;
        }

        var ids = Enumerable.Range(0, 3).Select(_ => $"urn:uuid:{Guid.NewGuid()}").ToArray();
        foreach (var id in ids)
            (await InvokeWithIdAsync(id, "query")).Should().Be(VerificationOutcome.Valid);
        await Task.Delay(700);

        // New invocations reuse the approved ids with a costlier action after the nonces expired.
        foreach (var id in ids)
            (await InvokeWithIdAsync(id, "query-large")).Should().Be(VerificationOutcome.CaveatNotSatisfied,
                "the budget is spent; an old approval must not be reused for a new request");
    }

    [Fact(DisplayName = "A handler timeout (TaskCanceledException) still releases earlier allowances (red-team F2)")]
    public async Task HandlerCanceled_Releases()
    {
        var region = new ScriptedCaveatHandler("Region", _ => throw new TaskCanceledException("ledger timeout"));
        var bed = new CaveatTestBed(new InMemoryEpsilonLedger(), region);
        var chain = await bed.BuildChainAsync();
        var regional = await bed.Capabilities.DelegateCapabilityAsync(chain.Agent, chain.AgentDid, new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });

        var result = await bed.Verifier.VerifyInvocationDetailedAsync(await bed.InvokeAsync(regional, chain.AgentDid), regional);

        result.Outcome.Should().Be(VerificationOutcome.CouldNotVerify);
        bed.Ledger.Releases.Should().Be(1);
        var grants = (await bed.Verifier.VerifyCapabilityChainDetailedAsync(regional)).Caveats!;
        grants.Where(g => g.Caveat is EpsilonBudgetCaveat).Should().AllSatisfy(g => bed.Ledger.Spent(g.GrantKey).Should().Be(0));
    }

    [Fact(DisplayName = "A null decision from a handler denies")]
    public async Task NullDecision_Denies()
    {
        var bed = new CaveatTestBed(new ScriptedCaveatHandler("EpsilonBudget", _ => null!));
        var chain = await bed.BuildChainAsync();

        (await bed.Verifier.VerifyInvocationDetailedAsync(await bed.InvokeAsync(chain.Agent, chain.AgentDid), chain.Agent))
            .Outcome.Should().Be(VerificationOutcome.CaveatNotSatisfied);
    }
}
