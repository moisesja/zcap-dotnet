using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>Registration rules for custom caveat types and their generated contexts (#157).</summary>
public class CaveatTypeRegistryTests
{
    public sealed class ControllerParameterCaveat : Caveat
    {
        public override string Type => "ControllerParameter";

        [JsonPropertyName("controller")]
        public string Controller { get; init; } = "";
    }

    public sealed class CreatedParameterCaveat : Caveat
    {
        public override string Type => "CreatedParameter";

        [JsonPropertyName("created")]
        public string Created { get; init; } = "";
    }

    public sealed class ExtensionDataCaveat : Caveat
    {
        public override string Type => "ExtensionData";

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    public sealed class ColonParameterCaveat : Caveat
    {
        public override string Type => "ColonParameter";

        [JsonPropertyName("ex:limit")]
        public int Limit { get; init; }
    }

    public sealed class IdParameterCaveat : Caveat
    {
        public override string Type => "IdParameter";

        [JsonPropertyName("id")]
        public string Id { get; init; } = "";
    }

    public sealed class LegacyTypeAttributeCaveat : Caveat
    {
        // The pre-5.0 pattern: a [JsonPropertyName("type")] on the override must not become a parameter.
        [JsonPropertyName("type")]
        public override string Type => "LegacyTypeAttribute";

        [JsonPropertyName("limit")]
        public int Limit { get; init; }
    }

    [Fact(DisplayName = "Generated context pins the type IRI and every parameter as a JSON literal")]
    public void GeneratedContext_IsDeterministic()
    {
        var registry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);

        CaveatTypeRegistry.GetContextUrl("EpsilonBudget").Should().Be("urn:zcap-dotnet:caveat-context:v1:EpsilonBudget");
        registry.GetContextDocument("EpsilonBudget").Should().Be(
            "{\"@context\":{\"@protected\":true,\"EpsilonBudget\":{\"@context\":{\"@protected\":true," +
            "\"maxEpsilon\":{\"@id\":\"urn:zcap-dotnet:caveat:v1:EpsilonBudget#maxEpsilon\",\"@type\":\"@json\"}}," +
            "\"@id\":\"urn:zcap-dotnet:caveat:v1:EpsilonBudget\"}}}");
    }

    [Theory(DisplayName = "Invalid caveat type names are refused")]
    [InlineData("")]
    [InlineData("1Budget")]
    [InlineData("ex:Budget")]
    [InlineData("Epsilon Budget")]
    [InlineData("Épsilon")]
    public void Register_InvalidTypeName_Throws(string type)
    {
        var act = () => new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(type);

        act.Should().Throw<ArgumentException>();
    }

    [Theory(DisplayName = "Type names that are ZCAP or suite context terms are refused")]
    [InlineData("expires")]
    [InlineData("controller")]
    [InlineData("caveat")]
    [InlineData("proofPurpose")]
    [InlineData("Ed25519Signature2020")]
    public void Register_ReservedTypeName_Throws(string type)
    {
        var act = () => new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(type);

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "A name longer than 64 characters is refused")]
    public void Register_LongTypeName_Throws()
    {
        var act = () => new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(new string('a', 65));

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "Parameters that collide with ZCAP or suite context terms are refused")]
    public void Register_ReservedParameterNames_Throw()
    {
        new Action(() => new CaveatTypeRegistry().Register<ControllerParameterCaveat>("ControllerParameter"))
            .Should().Throw<ArgumentException>("controller is a protected zcap/v1 term");
        new Action(() => new CaveatTypeRegistry().Register<CreatedParameterCaveat>("CreatedParameter"))
            .Should().Throw<ArgumentException>("created is defined by the signature suite context");
        new Action(() => new CaveatTypeRegistry().Register<IdParameterCaveat>("IdParameter"))
            .Should().Throw<ArgumentException>("id would turn the caveat into a named node");
        new Action(() => new CaveatTypeRegistry().Register<ColonParameterCaveat>("ColonParameter"))
            .Should().Throw<ArgumentException>("a colon makes the name an IRI");
    }

    [Fact(DisplayName = "Classes that capture undeclared members are refused")]
    public void Register_ExtensionData_Throws()
    {
        var act = () => new CaveatTypeRegistry().Register<ExtensionDataCaveat>("ExtensionData");

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "An overriding Type property is never a parameter")]
    public void Register_TypeOverrideWithAttribute_IsNotAParameter()
    {
        var registry = new CaveatTypeRegistry().Register<LegacyTypeAttributeCaveat>("LegacyTypeAttribute");

        registry.GetContextDocument("LegacyTypeAttribute").Should().Contain("#limit").And.NotContain("#type");
    }

    [Fact(DisplayName = "Conflicting registrations are refused; repeating one is idempotent")]
    public void Register_Conflicts_Throw()
    {
        var registry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>("EpsilonBudget");

        registry.Register<EpsilonBudgetCaveat>("EpsilonBudget").Types.Should().Equal("EpsilonBudget");
        new Action(() => registry.Register<RegionCaveat>("EpsilonBudget")).Should().Throw<InvalidOperationException>();
        new Action(() => registry.Register<EpsilonBudgetCaveat>("Budget2")).Should().Throw<InvalidOperationException>();
    }

    [Fact(DisplayName = "A registry handed to a service is frozen")]
    public void Register_AfterUse_Throws()
    {
        var registry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>("EpsilonBudget");
        var keys = new InMemoryDidProvider();
        _ = new VerificationService(keys, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
            caveats: registry);

        var act = () => registry.Register<RegionCaveat>("Region");

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact(DisplayName = "Handlers must enforce a registered type, one handler per type")]
    public void Verifier_InvalidHandlers_Throw()
    {
        var keys = new InMemoryDidProvider();
        VerificationService Create(CaveatTypeRegistry? registry, params ICaveatHandler[] handlers)
            => new(keys, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
                caveats: registry, caveatHandlers: handlers);

        new Action(() => Create(null, new InMemoryEpsilonLedger())).Should().Throw<ArgumentException>();
        new Action(() => Create(new CaveatTypeRegistry().Register<RegionCaveat>("Region"), new InMemoryEpsilonLedger()))
            .Should().Throw<ArgumentException>();
        new Action(() => Create(CaveatTestBed.NewRegistry(), new InMemoryEpsilonLedger(), new InMemoryEpsilonLedger()))
            .Should().Throw<ArgumentException>();
    }
}
