using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// #149 found that RDFC dropped caveat parameters no context defined, so they could be edited after
/// signing. These regressions edit every part of a signed caveat and require verification to fail;
/// none may return a valid or enforceable result (#157).
/// </summary>
public class CaveatTamperingTests
{
    private readonly CaveatTestBed _bed = new();

    private async Task<VerificationOutcome> VerifyChainAsync(Capability capability)
        => (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(capability)).Outcome;

    public static TheoryData<string, string, string> ParameterEdits => new()
    {
        // description, find, replace
        { "raise the budget", "\"maxEpsilon\":3,", "\"maxEpsilon\":4," },
        { "raise to the next double", "\"maxEpsilon\":3,", "\"maxEpsilon\":3.0000000000000004," },
        { "lower the budget", "\"maxEpsilon\":3,", "\"maxEpsilon\":2," },
    };

    [Theory(DisplayName = "Editing a signed parameter value breaks the signature")]
    [MemberData(nameof(ParameterEdits))]
    public async Task EditedParameter_InvalidSignature(string description, string find, string replace)
    {
        var chain = await _bed.BuildChainAsync();

        var outcome = await VerifyChainAsync(CapabilityJson.EditText(chain.Agent, find, replace));

        outcome.Should().Be(VerificationOutcome.InvalidSignature, description);
    }

    [Theory(DisplayName = "Spellings that sign like the original value are refused before the signature")]
    [InlineData("\"maxEpsilon\":3.0,")]
    [InlineData("\"maxEpsilon\":3.00000000000000000001,")]
    [InlineData("\"maxEpsilon\":3e0,")]
    [InlineData("\"maxEpsilon\":1e400,")]
    public async Task EquivalentSpelling_Refused(string replace)
    {
        var chain = await _bed.BuildChainAsync();

        var outcome = await VerifyChainAsync(CapabilityJson.EditText(chain.Agent, "\"maxEpsilon\":3,", replace));

        outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Changing the caveat type breaks the signature or is refused")]
    public async Task ChangedType_Refused()
    {
        var chain = await _bed.BuildChainAsync();

        var renamed = CapabilityJson.EditText(chain.Agent, "\"type\":\"EpsilonBudget\"}]", "\"type\":\"Region\"}]");
        (await VerifyChainAsync(renamed)).Should().BeOneOf(VerificationOutcome.MalformedCapability, VerificationOutcome.InvalidSignature);

        var renamedWithContext = CapabilityJson.Edit(chain.Agent, json =>
        {
            json["caveat"]![0]!["type"] = "Tag";
            json["caveat"]![0]!.AsObject().Remove("maxEpsilon");
            json["caveat"]![0]!["data"] = 3;
            json["@context"]![2] = CaveatTypeRegistry.GetContextUrl("Tag");
        });
        (await VerifyChainAsync(renamedWithContext)).Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "Adding an undeclared parameter is refused")]
    public async Task AddedParameter_Refused()
    {
        var chain = await _bed.BuildChainAsync();

        var outcome = await VerifyChainAsync(CapabilityJson.Edit(chain.Agent, json => json["caveat"]![0]!["maxEpsilonOverride"] = 100));

        outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Removing the caveat breaks the signature")]
    public async Task RemovedCaveat_InvalidSignature()
    {
        var chain = await _bed.BuildChainAsync();

        (await VerifyChainAsync(CapabilityJson.Edit(chain.Agent, json => json.Remove("caveat"))))
            .Should().Be(VerificationOutcome.InvalidSignature);
        (await VerifyChainAsync(CapabilityJson.Edit(chain.Agent, json =>
        {
            json.Remove("caveat");
            json["@context"]!.AsArray().RemoveAt(2);
        }))).Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "Editing the embedded ancestor's caveat breaks the signatures")]
    public async Task EditedEmbeddedAncestor_InvalidSignature()
    {
        var chain = await _bed.BuildChainAsync();

        var edited = CapabilityJson.Edit(chain.Agent, json =>
            json["proof"]!["capabilityChain"]![1]!["caveat"]![0]!["maxEpsilon"] = 1000);

        (await VerifyChainAsync(edited)).Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "#149 regression: the parameter value is in the signed N-Quads")]
    public async Task Parameter_IsInCanonicalNQuads()
    {
        var chain = await _bed.BuildChainAsync();
        var canonicalizer = new RdfcDocumentCanonicalizer(_bed.Registry);
        string NQuads(Capability capability)
            => Encoding.UTF8.GetString(canonicalizer.Canonicalize(ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability)));

        var original = NQuads(chain.Agent);
        var raised = NQuads(CapabilityJson.EditText(chain.Agent, "\"maxEpsilon\":3,", "\"maxEpsilon\":4,"));

        original.Should().Contain(
            "_:c14n0 <urn:zcap-dotnet:caveat:v1:EpsilonBudget#maxEpsilon> \"3\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .");
        original.Should().Contain("_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:zcap-dotnet:caveat:v1:EpsilonBudget> .");
        raised.Should().NotBe(original);
    }

    [Fact(DisplayName = "A tampered invocation never reaches the caveat handler")]
    public async Task TamperedInvocation_HandlerNotCalled()
    {
        var chain = await _bed.BuildChainAsync();
        var invocation = await _bed.InvokeAsync(chain.Agent, chain.AgentDid);
        invocation.Proof!.Created = ZcapTimestamps.Format(invocation.Proof.CreatedAt!.Value.AddSeconds(-1));

        (await _bed.Verifier.VerifyInvocationDetailedAsync(invocation, chain.Agent)).Outcome
            .Should().Be(VerificationOutcome.InvalidSignature);
        _bed.Ledger.Calls.Should().Be(0);
    }
}
