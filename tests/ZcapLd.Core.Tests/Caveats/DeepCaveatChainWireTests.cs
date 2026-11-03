using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// A caveat chain of three delegations on the wire (PR #163 review follow-up). The leaf's proof embeds the
/// parent, whose proof embeds the grandparent, so after a JSON round trip the grandparent is a raw JSON
/// object inside a raw proof. The profile scan used to treat an embedded ancestor's own
/// <c>capabilityChain</c> entries as ordinary members and refused the grandparent's caveat as unsupported
/// vocabulary, so such chains verified only while they were still typed objects in the issuing process.
/// </summary>
public class DeepCaveatChainWireTests
{
    [Fact(DisplayName = "A three-link caveat chain verifies after a JSON round trip, and its invocation is enforced")]
    public async Task ThreeLinkCaveatChain_AfterJsonRoundTrip_VerifiesAndEnforces()
    {
        var bed = new CaveatTestBed();
        var chain = await bed.BuildChainAsync();
        var sub = bed.Keys.GenerateDidKey();
        var leaf = await bed.Capabilities.DelegateCapabilityAsync(chain.Agent, sub, new[] { "query" }, DateTime.UtcNow.AddHours(6),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 2 } });
        var wire = CaveatTestBed.RoundTrip(leaf);

        (await bed.Verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired);
        (await bed.Verifier.VerifyCapabilityChainDetailedAsync(wire)).Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired,
            "the grandparent's caveat sits inside the parent's serialized proof and must be admitted there");

        var invocation = await bed.InvokeAsync(wire, sub);
        (await bed.Verifier.VerifyInvocationDetailedAsync(invocation, wire)).Outcome.Should().Be(VerificationOutcome.Valid);
    }
}
