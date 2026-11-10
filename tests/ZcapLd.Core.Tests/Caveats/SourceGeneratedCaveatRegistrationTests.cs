using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Cryptography;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Issue #154 — <see cref="CaveatTypeRegistry.Register{TCaveat}(string, JsonTypeInfo{TCaveat})"/>
/// takes source-generated metadata so a native AOT, trimmed or file-based application can register
/// caveats. Whichever overload registered a class, the generated context document, the wire bytes and
/// the verifier's reading of them must be identical.
/// </summary>
public partial class SourceGeneratedCaveatRegistrationTests
{
    /// <summary>The pre-5.0 pattern: a <c>[JsonPropertyName("type")]</c> on the override must not become a parameter.</summary>
    public sealed class LegacyTypeAttributeCaveat : Caveat
    {
        [JsonPropertyName("type")]
        public override string Type => "LegacyTypeAttribute";

        [JsonPropertyName("limit")]
        public int Limit { get; init; }
    }

    [JsonSerializable(typeof(EpsilonBudgetCaveat))]
    [JsonSerializable(typeof(RegionCaveat))]
    [JsonSerializable(typeof(TagCaveat))]
    [JsonSerializable(typeof(JcsTests.WindowCaveat))]
    [JsonSerializable(typeof(LegacyTypeAttributeCaveat))]
    internal sealed partial class CaveatJsonContext : JsonSerializerContext
    {
    }

    /// <summary>Serves the generated metadata for everything except <see cref="JcsTests.WindowBounds"/>.</summary>
    private sealed class WithoutBoundsResolver : IJsonTypeInfoResolver
    {
        public JsonTypeInfo? GetTypeInfo(Type type, JsonSerializerOptions options)
            => type == typeof(JcsTests.WindowBounds) ? null : ((IJsonTypeInfoResolver)CaveatJsonContext.Default).GetTypeInfo(type, options);
    }

    private static CaveatTypeRegistry Reflection() => CaveatTestBed.NewRegistry()
        .Register<JcsTests.WindowCaveat>("Window")
        .Register<LegacyTypeAttributeCaveat>("LegacyTypeAttribute");

    private static CaveatTypeRegistry Generated() => new CaveatTypeRegistry()
        .Register(EpsilonBudgetCaveat.TypeName, CaveatJsonContext.Default.EpsilonBudgetCaveat)
        .Register(RegionCaveat.TypeName, CaveatJsonContext.Default.RegionCaveat)
        .Register(TagCaveat.TypeName, CaveatJsonContext.Default.TagCaveat)
        .Register("Window", CaveatJsonContext.Default.WindowCaveat)
        .Register("LegacyTypeAttribute", CaveatJsonContext.Default.LegacyTypeAttributeCaveat);

    // ─── What the source generator emits for a Caveat subclass ────────────────

    [Fact(DisplayName = "The generator emits the overriding Type property (base [JsonIgnore] is not inherited) with its PropertyInfo as AttributeProvider")]
    public void Generator_EmitsTypeOverride_WithPropertyInfoAttributeProvider()
    {
        foreach (var info in new JsonTypeInfo[]
                 {
                     CaveatJsonContext.Default.EpsilonBudgetCaveat,
                     CaveatJsonContext.Default.WindowCaveat,
                     CaveatJsonContext.Default.LegacyTypeAttributeCaveat,
                 })
        {
            // The override is emitted under its JSON name; when that name is not "Type" the base's
            // ignored Caveat.Type is emitted as well (a getter-less placeholder), exactly as reflection does.
            var typeProperties = info.Properties.Where(p => p.Name == "Type" || p.Name == "type").ToList();
            typeProperties.Should().NotBeEmpty("the generator does not honour the base class's [JsonIgnore] on an override");
            typeProperties.Should().Contain(p => ((PropertyInfo)p.AttributeProvider!).DeclaringType == info.Type);
            typeProperties.Should().OnlyContain(p => p.AttributeProvider is PropertyInfo
                                                     && ((PropertyInfo)p.AttributeProvider).Name == nameof(Caveat.Type)
                                                     && typeof(Caveat).IsAssignableFrom(((PropertyInfo)p.AttributeProvider).DeclaringType),
                "the registration's modifier recognizes both through their PropertyInfo");
            info.Properties.Should().NotContain(p => p.AttributeProvider == null,
                "every generated property exposes its member, so the modifier never falls back");
        }

        // Without the registry's modifier the override would be a second, CLR-named member on the wire.
        JsonSerializer.Serialize(new EpsilonBudgetCaveat { MaxEpsilon = 1 }, CaveatJsonContext.Default.EpsilonBudgetCaveat)
            .Should().Be("""{"Type":"EpsilonBudget","maxEpsilon":1}""");
    }

    [Fact(DisplayName = "The typed overload drops the Type override and declares the same parameters as reflection")]
    public void Register_TypeInfo_DeclaresTheSameParameters()
    {
        var reflection = Reflection();
        var generated = Generated();
        foreach (var type in reflection.Types)
        {
            generated.TryGet(type, out var fromContext).Should().BeTrue();
            reflection.TryGet(type, out var fromReflection).Should().BeTrue();
            fromContext!.Parameters.Should().Equal(fromReflection!.Parameters);
            fromContext.Parameters.Should().NotContain(new[] { "Type", "type" });
            fromContext.ClrType.Should().Be(fromReflection.ClrType);
            fromContext.TypeInfo.OriginatingResolver.Should().BeOfType<CaveatJsonContext>();
            fromReflection.TypeInfo.OriginatingResolver.Should().BeOfType<DefaultJsonTypeInfoResolver>();
            generated.GetContextDocument(type).Should().Be(reflection.GetContextDocument(type));
        }

        generated.Types.Should().Equal(reflection.Types);
    }

    // ─── Byte identity across the two overloads ───────────────────────────────

    [Theory(DisplayName = "A caveat writes identical bytes whichever overload registered its class")]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Write_IsByteIdenticalAcrossOverloads(int index)
    {
        var caveat = Samples()[index];
        var fromReflection = CaveatCodec.Write(caveat, Reflection()).GetRawText();
        var fromContext = CaveatCodec.Write(caveat, Generated()).GetRawText();
        fromContext.Should().Be(fromReflection);
    }

    [Fact(DisplayName = "Delegation output is byte-identical and cross-verifies between a reflection and a generated registry")]
    public async Task DelegateCapabilityAsync_IsByteIdenticalAcrossOverloads()
    {
        var keys = new InMemoryDidProvider();
        var patient = keys.GenerateDidKey();
        var agent = keys.GenerateDidKey();
        var reflection = Reflection();
        var generated = Generated();
        var reflectionCapabilities = new CapabilityService(new SigningService(keys, keys, reflection), reflection);
        var generatedCapabilities = new CapabilityService(new SigningService(keys, keys, generated), generated);
        var root = await TestRoots.CreateAndRegisterRootAsync(reflectionCapabilities, keys, patient, CaveatTestBed.Target);
        var expires = DateTime.UtcNow.AddDays(1);
        var actions = new[] { "query" };

        var fromReflection = await reflectionCapabilities.DelegateCapabilityAsync(root, agent, actions, expires, caveats: Samples());
        var fromContext = await generatedCapabilities.DelegateCapabilityAsync(root, agent, actions, expires, caveats: Samples());

        // Each delegation draws a fresh urn:uuid id and stamps its own proof created instant; with those
        // aligned, everything the proof signs must match byte for byte.
        var unsignedFromReflection = CaveatTestBed.RoundTrip(fromReflection);
        var unsignedFromContext = CaveatTestBed.RoundTrip(fromContext);
        unsignedFromReflection.Proof = null;
        unsignedFromContext.Proof = null;
        unsignedFromContext.Id.Should().NotBe(unsignedFromReflection.Id);
        unsignedFromContext.Id = unsignedFromReflection.Id;
        JsonSerializer.SerializeToUtf8Bytes(unsignedFromContext, ZcapJsonOptions.Default)
            .Should().Equal(JsonSerializer.SerializeToUtf8Bytes(unsignedFromReflection, ZcapJsonOptions.Default));
        fromContext.AdditionalProperties!["caveat"].GetRawText().Should().Be(fromReflection.AdditionalProperties!["caveat"].GetRawText());

        foreach (var (capability, registry, signing) in new[]
                 {
                     (fromReflection, generated, new SigningService(keys, keys, generated)),
                     (fromContext, reflection, new SigningService(keys, keys, reflection)),
                 })
        {
            var handlers = new ICaveatHandler[]
            {
                new InMemoryEpsilonLedger(),
                new ScriptedCaveatHandler(RegionCaveat.TypeName, _ => CaveatDecision.Satisfied),
                new ScriptedCaveatHandler(TagCaveat.TypeName, _ => CaveatDecision.Satisfied),
                new ScriptedCaveatHandler("Window", _ => CaveatDecision.Satisfied),
            };
            var verifier = new VerificationService(keys, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
                relationshipResolver: keys, rootResolver: keys, caveats: registry, caveatHandlers: handlers);
            var presented = CaveatTestBed.RoundTrip(capability);
            var chain = await verifier.VerifyCapabilityChainDetailedAsync(presented);
            chain.Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired, chain.Message);
            chain.Caveats.Should().HaveCount(Samples().Length);

            var invocation = new CapabilityService(signing, registry).CreateInvocation(presented, "query");
            invocation.Proof = await signing.SignInvocationAsync(invocation, agent);
            var result = await verifier.VerifyInvocationDetailedAsync(CaveatTestBed.RoundTrip(invocation), presented);
            result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
            ((InMemoryEpsilonLedger)handlers[0]).Calls.Should().Be(1);
            handlers.Skip(1).Cast<ScriptedCaveatHandler>().Should().OnlyContain(h => h.Calls == 1);
            var read = capability.GetCaveats(registry);
            read.Should().HaveCount(Samples().Length);
            read.Select(c => c.GetType()).Should().Equal(Samples().Select(c => c.GetType()));
            var window = read.OfType<JcsTests.WindowCaveat>().Single();
            window.Bounds.Start.Should().Be("2026-01-01T00:00:00Z");
            window.Tags.Should().Equal("b", "a");
            read.Zip(Samples()).Should().OnlyContain(pair => pair.First.IsAttenuationOf(pair.Second) && pair.Second.IsAttenuationOf(pair.First));
        }
    }

    [Fact(DisplayName = "Omitting a required nested parameter is malformed under the generated metadata as well")]
    public void Materialize_RequiresRequiredParameters_UnderGeneratedMetadata()
    {
        var registry = Generated();
        var contexts = new[] { CaveatTypeRegistry.GetContextUrl("Window") };
        var missingBounds = JsonDocument.Parse("""[{"type":"Window","weight":1}]""").RootElement;
        var missingEnd = JsonDocument.Parse("""[{"type":"Window","bounds":{"start":"s"},"weight":1}]""").RootElement;

        foreach (var value in new[] { missingBounds, missingEnd })
        {
            var failure = CaveatCodec.TryRead(value, contexts, registry, materialize: true, out _);
            failure.Should().NotBeNull();
            failure!.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        }

        CaveatCodec.TryRead(JsonDocument.Parse("""[{"type":"Window","bounds":{"start":"s","end":"e","extra":1}}]""").RootElement,
                contexts, registry, materialize: true, out _)!
            .Outcome.Should().Be(VerificationOutcome.MalformedCapability, "unmapped members stay disallowed in nested objects");
    }

    // ─── Registration failures name their cause ───────────────────────────────

    [Fact(DisplayName = "Metadata whose resolver does not cover a nested parameter type fails at registration")]
    public void Register_TypeInfo_UncoveredNestedType_ThrowsAtRegistration()
    {
        // A context-produced JsonTypeInfo names the context as OriginatingResolver even when resolved
        // through a wrapper, so build one with no originating resolver: the registry then falls back to
        // the options' resolver, which serves the caveat class but not its nested WindowBounds.
        var options = new JsonSerializerOptions { TypeInfoResolver = new WithoutBoundsResolver() };
        var typeInfo = JsonTypeInfo.CreateJsonTypeInfo<JcsTests.WindowCaveat>(options);
        typeInfo.OriginatingResolver.Should().BeNull();
        ((IJsonTypeInfoResolver)options.TypeInfoResolver!).GetTypeInfo(typeof(JcsTests.WindowCaveat), options).Should().NotBeNull();

        var act = () => new CaveatTypeRegistry().Register("Window", typeInfo);

        act.Should().Throw<ArgumentException>()
            .WithMessage($"*{typeof(JcsTests.WindowCaveat).FullName}*")
            .WithMessage("*WindowBounds*")
            .WithMessage("*JsonSerializerContext*");
    }

    [Fact(DisplayName = "Metadata without a resolver is refused")]
    public void Register_TypeInfo_WithoutResolver_Throws()
    {
        var typeInfo = JsonTypeInfo.CreateJsonTypeInfo<EpsilonBudgetCaveat>(new JsonSerializerOptions());

        var act = () => new CaveatTypeRegistry().Register(EpsilonBudgetCaveat.TypeName, typeInfo);

        act.Should().Throw<ArgumentException>().WithMessage("*JsonSerializerContext*");
        new Action(() => new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName, null!))
            .Should().Throw<ArgumentNullException>();
    }

    [Fact(DisplayName = "The typed overload applies the same name and shape rules as the reflection overload")]
    public void Register_TypeInfo_AppliesTheRegistryRules()
    {
        var registry = Generated();

        new Action(() => registry.Register("EpsilonBudget", CaveatJsonContext.Default.EpsilonBudgetCaveat))
            .Should().NotThrow("re-registering the same pair is idempotent");
        new Action(() => registry.Register<EpsilonBudgetCaveat>("EpsilonBudget"))
            .Should().NotThrow("the overloads agree on a class already registered under that name");
        new Action(() => registry.Register("Budget2", CaveatJsonContext.Default.EpsilonBudgetCaveat))
            .Should().Throw<InvalidOperationException>();
        new Action(() => registry.Register("EpsilonBudget", CaveatJsonContext.Default.RegionCaveat))
            .Should().Throw<InvalidOperationException>();
        new Action(() => new CaveatTypeRegistry().Register("controller", CaveatJsonContext.Default.EpsilonBudgetCaveat))
            .Should().Throw<ArgumentException>();
        new Action(() => new CaveatTypeRegistry().Register("ex:Budget", CaveatJsonContext.Default.EpsilonBudgetCaveat))
            .Should().Throw<ArgumentException>();

        registry.Freeze();
        new Action(() => registry.Register("Other", CaveatJsonContext.Default.EpsilonBudgetCaveat))
            .Should().Throw<InvalidOperationException>();
    }

    [Fact(DisplayName = "IsAttenuationOf compares parameters through the metadata the typed overload registered")]
    public void IsAttenuationOf_UsesRegisteredMetadata()
    {
        Generated();
        var data = JsonDocument.Parse("""{"k":[1,2.5,{"n":"ünï"}]}""").RootElement;
        var same = JsonDocument.Parse("""{"k":[1,2.5,{"n":"ünï"}]}""").RootElement;
        var other = JsonDocument.Parse("""{"k":[1,2.50,{"n":"ünï"}]}""").RootElement;

        new TagCaveat { Data = data }.IsAttenuationOf(new TagCaveat { Data = same }).Should().BeTrue();
        new TagCaveat { Data = data }.IsAttenuationOf(new TagCaveat { Data = other }).Should().BeTrue("2.5 and 2.50 are the same number");
        new TagCaveat { Data = data }.IsAttenuationOf(new TagCaveat { Data = JsonDocument.Parse("{}").RootElement }).Should().BeFalse();
        new LegacyTypeAttributeCaveat { Limit = 1 }.IsAttenuationOf(new LegacyTypeAttributeCaveat { Limit = 1 }).Should().BeTrue();
        new LegacyTypeAttributeCaveat { Limit = 1 }.IsAttenuationOf(new LegacyTypeAttributeCaveat { Limit = 2 }).Should().BeFalse();
    }

    private static Caveat[] Samples() => new Caveat[]
    {
        new EpsilonBudgetCaveat { MaxEpsilon = 2.5 },
        new RegionCaveat { Allowed = new[] { "eu-west", "us-east" } },
        new TagCaveat { Data = JsonDocument.Parse("""{"z":[1,2.5,"ünï+<>&'"],"a":{"b":true}}""").RootElement },
        new JcsTests.WindowCaveat
        {
            Bounds = new JcsTests.WindowBounds { Start = "2026-01-01T00:00:00Z", End = "2026-02-01T00:00:00Z" },
            Tags = new[] { "b", "a" },
            Weight = 3,
        },
    };
}
