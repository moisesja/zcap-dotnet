using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Unknown types, missing handlers, malformed values, undefined vocabulary, duplicates, aliases and
/// bounds all fail closed (#157). Where the JSON is still signable, the variant is re-signed by the
/// real parent controller so the rejection cannot come from a broken signature.
/// </summary>
public class CaveatIntegrityTests
{
    private readonly CaveatTestBed _bed = new();

    // Re-signs an edited copy of the agent grant with the orchestrator's real key.
    private async Task<(Capability Capability, CaveatTestBed.Chain Chain)> SignedVariantAsync(Action<JsonObject> edit, bool resign = true)
    {
        var chain = await _bed.BuildChainAsync();
        var variant = CapabilityJson.Edit(chain.Agent, edit);
        if (resign)
        {
            variant.Proof = await RawProofSigner.SignCapabilityAsync(_bed.Keys, variant, chain.OrchestratorDid,
                new object[] { chain.Root.Id, chain.Orchestrator }, new RdfcDocumentCanonicalizer(_bed.Registry));
        }
        return (variant, chain);
    }

    private async Task<VerificationOutcome> ChainOutcomeAsync(Action<JsonObject> edit, bool resign = true)
        => (await _bed.Verifier.VerifyCapabilityChainDetailedAsync((await SignedVariantAsync(edit, resign)).Capability)).Outcome;

    private static JsonNode Budget(JsonNode? value) => new JsonObject { ["maxEpsilon"] = value, ["type"] = "EpsilonBudget" };

    [Fact(DisplayName = "Positive control: an unedited re-signed grant is accepted")]
    public async Task ResignedUnchanged_Accepted()
        => (await ChainOutcomeAsync(_ => { })).Should().Be(VerificationOutcome.CaveatEnforcementRequired);

    [Fact(DisplayName = "A caveat type the verifier has not registered is unsupported")]
    public async Task UnregisteredType_Unsupported()
    {
        var chain = await _bed.BuildChainAsync();
        var regional = await _bed.Capabilities.DelegateCapabilityAsync(chain.Agent, _bed.Keys.GenerateDidKey(), new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });
        var narrowRegistry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);
        var verifier = _bed.NewVerifier(new[] { _bed.Ledger }, narrowRegistry);

        (await verifier.VerifyCapabilityChainDetailedAsync(regional)).Outcome.Should().Be(VerificationOutcome.UnsupportedCaveat);
        (await ChainOutcomeAsync(json => json["caveat"]![0]!["type"] = "Nope", resign: false))
            .Should().Be(VerificationOutcome.UnsupportedCaveat);
    }

    [Fact(DisplayName = "A registered type without a handler is unsupported at invocation, before the nonce is used")]
    public async Task MissingHandler_UnsupportedAndNonceKept()
    {
        var chain = await _bed.BuildChainAsync();
        var tagged = await _bed.Capabilities.DelegateCapabilityAsync(chain.Agent, chain.AgentDid, new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new TagCaveat { Data = System.Text.Json.JsonDocument.Parse("\"x\"").RootElement } });
        var invocation = await _bed.InvokeAsync(tagged, chain.AgentDid);

        (await _bed.Verifier.VerifyInvocationDetailedAsync(invocation, tagged)).Outcome.Should().Be(VerificationOutcome.UnsupportedCaveat);
        _bed.Ledger.Calls.Should().Be(0);

        var tagHandler = new ScriptedCaveatHandler("Tag", _ => CaveatDecision.Satisfied);
        var complete = _bed.NewVerifier(new ICaveatHandler[] { _bed.Ledger, tagHandler });
        (await complete.VerifyInvocationDetailedAsync(invocation, tagged)).Outcome
            .Should().Be(VerificationOutcome.Valid, "the denied attempt must not have consumed the shared nonce");
    }

    public static TheoryData<string, string> InvalidBudgets => new()
    {
        { "negative", "-1" }, { "zero", "0" }, { "above bound", "1001" }, { "string", "\"3\"" },
        { "boolean", "true" }, { "object", "{\"value\":3}" }, { "array", "[3]" },
    };

    [Theory(DisplayName = "Invalid parameter values are refused even when validly signed")]
    [MemberData(nameof(InvalidBudgets))]
    public async Task InvalidValue_Malformed(string description, string json)
        => (await ChainOutcomeAsync(edit => edit["caveat"]![0]!["maxEpsilon"] = JsonNode.Parse(json)))
            .Should().Be(VerificationOutcome.MalformedCapability, description);

    [Fact(DisplayName = "A null or missing required parameter is refused")]
    public async Task NullOrMissingParameter_Malformed()
    {
        (await ChainOutcomeAsync(edit => edit["caveat"]![0]!["maxEpsilon"] = null)).Should().Be(VerificationOutcome.MalformedCapability);
        (await ChainOutcomeAsync(edit => edit["caveat"]![0]!.AsObject().Remove("maxEpsilon"))).Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Revocation, which skips caveat policy, still refuses an undeclared parameter")]
    public async Task UndeclaredParameter_RefusedOnRevocationPath()
    {
        // Revocation does not deserialize caveats, so only the declared-parameter check can catch this.
        var (variant, chain) = await SignedVariantAsync(edit => edit["caveat"]![0]!["maxEpsilonOverride"] = 100);
        var request = await _bed.Signing.SignRevocationAsync(variant.Id, chain.OrchestratorDid, variant.InvocationTarget);

        (await _bed.Verifier.RevokeCapabilityAsync(variant, request)).Should().BeFalse();
        (await _bed.Verifier.IsCapabilityRevokedAsync(variant.Id)).Should().BeFalse();
    }

    [Fact(DisplayName = "Positive control: revocation accepts the same re-signed grant without the extra parameter")]
    public async Task ResignedUnchanged_Revocable()
    {
        var (variant, chain) = await SignedVariantAsync(_ => { });
        var request = await _bed.Signing.SignRevocationAsync(variant.Id, chain.OrchestratorDid, variant.InvocationTarget);

        (await _bed.Verifier.RevokeCapabilityAsync(variant, request)).Should().BeTrue();
    }

    [Fact(DisplayName = "Undefined vocabulary: a caveat without its type context is refused even when signed")]
    public async Task MissingTypeContext_Malformed()
        => (await ChainOutcomeAsync(edit => edit["@context"]!.AsArray().RemoveAt(2))).Should().Be(VerificationOutcome.MalformedCapability);

    [Fact(DisplayName = "A caveat context of another profile version is refused")]
    public async Task OtherProfileVersion_Refused()
        => (await ChainOutcomeAsync(edit => edit["@context"]![2] = "urn:zcap-dotnet:caveat-context:v2:EpsilonBudget", resign: false))
            .Should().BeOneOf(VerificationOutcome.MalformedCapability, VerificationOutcome.UnsupportedCaveat);

    [Fact(DisplayName = "Ambiguous duplicates are refused")]
    public async Task Duplicates_Malformed()
    {
        (await ChainOutcomeAsync(edit => edit["caveat"] = new JsonArray(Budget(3), Budget(2))))
            .Should().Be(VerificationOutcome.MalformedCapability, "two caveats of one type could be read either way");

        var chain = await _bed.BuildChainAsync();
        var duplicateKey = CapabilityJson.Serialize(chain.Agent)
            .Replace("\"maxEpsilon\":3,", "\"maxEpsilon\":3,\"maxEpsilon\":300,", StringComparison.Ordinal);
        Capability? parsed = null;
        try { parsed = CapabilityJson.Parse(duplicateKey); } catch (System.Text.Json.JsonException) { }
        if (parsed is not null)
            (await _bed.Verifier.VerifyCapabilityChainDetailedAsync(parsed)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Theory(DisplayName = "Malformed caveat containers are refused")]
    [InlineData("[]")]
    [InlineData("{\"maxEpsilon\":3,\"type\":\"EpsilonBudget\"}")]
    [InlineData("[\"urn:example:caveat\"]")]
    [InlineData("null")]
    [InlineData("[{\"maxEpsilon\":3,\"type\":[\"EpsilonBudget\",\"Region\"]}]")]
    [InlineData("[{\"id\":\"urn:example:c\",\"maxEpsilon\":3,\"type\":\"EpsilonBudget\"}]")]
    [InlineData("[{\"@type\":\"EpsilonBudget\",\"maxEpsilon\":3}]")]
    public async Task MalformedContainer_Malformed(string caveat)
        => (await ChainOutcomeAsync(edit => edit["caveat"] = JsonNode.Parse(caveat), resign: false))
            .Should().BeOneOf(VerificationOutcome.MalformedCapability, VerificationOutcome.UnsupportedCaveat);

    [Fact(DisplayName = "Caveat JSON over 64 KiB is refused")]
    public async Task OversizedCaveats_Malformed()
        => (await ChainOutcomeAsync(edit =>
            {
                edit["caveat"]!.AsArray().Add(new JsonObject
                {
                    ["data"] = new JsonArray(Enumerable.Range(0, 20).Select(_ => (JsonNode?)new string('x', 4000)).ToArray()),
                    ["type"] = "Tag",
                });
                edit["@context"]!.AsArray().Add(CaveatTypeRegistry.GetContextUrl("Tag"));
            }, resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability);

    [Fact(DisplayName = "More than 16 caveats are refused")]
    public async Task TooManyCaveats_Malformed()
        => (await ChainOutcomeAsync(edit => edit["caveat"] = new JsonArray(Enumerable.Range(0, 17).Select(_ => Budget(1)).ToArray()), resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability);

    [Theory(DisplayName = "Caveat aliases and vocabulary outside a caveat entry are refused")]
    [InlineData("sec:caveat")]
    [InlineData("https://w3id.org/security#caveat")]
    [InlineData("urn:zcap-dotnet:caveat:v1:EpsilonBudget#maxEpsilon")]
    [InlineData("@included")]
    [InlineData("EpsilonBudget")]
    public async Task AliasKeys_Malformed(string key)
        => (await ChainOutcomeAsync(edit => edit[key] = new JsonArray(Budget(1000)), resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability);

    [Fact(DisplayName = "A caveat type used as the capability's type is refused")]
    public async Task CaveatTypeOnCapability_Malformed()
        => (await ChainOutcomeAsync(edit => edit["type"] = "EpsilonBudget", resign: false)).Should().Be(VerificationOutcome.MalformedCapability);

    [Fact(DisplayName = "A caveat nested anywhere but a capability's top level is refused")]
    public async Task NestedCaveat_Malformed()
    {
        (await ChainOutcomeAsync(edit => edit["proof"]!["caveat"] = new JsonArray(Budget(1000)), resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability);
        (await ChainOutcomeAsync(edit => edit["extra"] = new JsonObject { ["caveat"] = new JsonArray(Budget(1000)) }, resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "A root carrying a caveat is refused")]
    public async Task RootWithCaveat_Refused()
    {
        var chain = await _bed.BuildChainAsync();
        var root = CapabilityJson.Edit(chain.Root, json => json["caveat"] = new JsonArray(Budget(1)));
        _bed.Keys.RegisterRoot(root);

        var result = await _bed.Verifier.VerifyCapabilityChainDetailedAsync(chain.Agent);

        result.IsValid.Should().BeFalse();
        result.Outcome.Should().NotBe(VerificationOutcome.CaveatEnforcementRequired);
    }

    public static TheoryData<string, string> InvalidLiterals => new()
    {
        { "null member", "{\"a\":null}" },
        { "exponent", "1e-7" },
        { "below 0.0001", "0.00001" },
        { "above 2^53", "9007199254740994" },
        { "negative zero", "-0" },
        { "non-canonical", "2.50" },
        { "line separator", "\"a\\u2028b\"" },
        { "control character", "\"a\\u0001b\"" },
        { "too deep", "[[[[[[[[[1]]]]]]]]]" },
    };

    [Theory(DisplayName = "JSON literal rules hold inside parameter values")]
    [MemberData(nameof(InvalidLiterals))]
    public async Task InvalidLiteral_Malformed(string description, string data)
        => (await ChainOutcomeAsync(edit =>
            {
                edit["caveat"]!.AsArray().Add(new JsonObject { ["data"] = JsonNode.Parse(data), ["type"] = "Tag" });
                edit["@context"]!.AsArray().Add(CaveatTypeRegistry.GetContextUrl("Tag"));
            }, resign: false))
            .Should().Be(VerificationOutcome.MalformedCapability, description);

    [Fact(DisplayName = "A lone surrogate escape in a parameter value is refused")]
    public async Task LoneSurrogate_Refused()
    {
        var (variant, _) = await SignedVariantAsync(edit =>
        {
            edit["caveat"]!.AsArray().Add(new JsonObject { ["data"] = "PLACEHOLDER", ["type"] = "Tag" });
            edit["@context"]!.AsArray().Add(CaveatTypeRegistry.GetContextUrl("Tag"));
        }, resign: false);
        var withSurrogate = CapabilityJson.EditText(variant, "\"PLACEHOLDER\"", "\"\\ud800\"");

        var result = await _bed.Verifier.VerifyCapabilityChainDetailedAsync(withSurrogate);

        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    [Fact(DisplayName = "Positive control: valid literal values in a parameter are accepted")]
    public async Task ValidLiteral_Accepted()
        => (await ChainOutcomeAsync(edit =>
            {
                edit["caveat"]!.AsArray().Add(new JsonObject
                {
                    ["data"] = JsonNode.Parse("{\"b\":[0,0.0001,2.5,-3,9007199254740992,true,\"é😀<&>\"],\"a\":{\"x\":1}}"),
                    ["type"] = "Tag",
                });
                edit["@context"]!.AsArray().Add(CaveatTypeRegistry.GetContextUrl("Tag"));
            }))
            .Should().Be(VerificationOutcome.CaveatEnforcementRequired);
}
