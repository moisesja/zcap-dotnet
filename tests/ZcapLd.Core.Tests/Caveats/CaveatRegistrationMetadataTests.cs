using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Issue #154 red-team follow-ups on <see cref="CaveatTypeRegistry.Register{TCaveat}(string, JsonTypeInfo{TCaveat})"/>:
/// a context generated with <c>UseStringEnumConverter</c> bakes string enums into its metadata, which the
/// reflection overload never applies, so a JIT delegator and an AOT verifier would write different bytes
/// (F1); and an <c>object</c>-typed parameter reads back as a <see cref="JsonElement"/>, whose metadata a
/// context listing only the caveat class does not generate (F5). Both are decided at registration.
/// </summary>
public partial class CaveatRegistrationMetadataTests
{
    public enum Mode
    {
        Low,
        High,
    }

    public sealed class ModeCaveat : Caveat
    {
        public override string Type => "Mode";

        [JsonPropertyName("mode")]
        public Mode Mode { get; init; }
    }

    public sealed class OptionalModeCaveat : Caveat
    {
        public override string Type => "OptionalMode";

        [JsonPropertyName("fallback")]
        public Mode? Fallback { get; init; }
    }

    /// <summary>A member-level converter is honoured by both overloads and so passes the probe.</summary>
    public sealed class LabelledModeCaveat : Caveat
    {
        public override string Type => "LabelledMode";

        [JsonPropertyName("mode")]
        [JsonConverter(typeof(JsonStringEnumConverter<Mode>))]
        public Mode Mode { get; init; }
    }

    /// <summary>A converter on the enum type is read by reflection and the generator alike (6.0.0 behaviour).</summary>
    [JsonConverter(typeof(JsonStringEnumConverter<Level>))]
    public enum Level
    {
        Bronze,
        Gold,
    }

    public sealed class LevelCaveat : Caveat
    {
        public override string Type => "Level";

        [JsonPropertyName("level")]
        public Level Level { get; init; }
    }

    public sealed class ObjectCaveat : Caveat
    {
        public override string Type => "Object";

        [JsonPropertyName("value")]
        public required object Value { get; init; }
    }

    [JsonSourceGenerationOptions(UseStringEnumConverter = true)]
    [JsonSerializable(typeof(ModeCaveat))]
    [JsonSerializable(typeof(OptionalModeCaveat))]
    internal sealed partial class StringEnumContext : JsonSerializerContext
    {
    }

    [JsonSerializable(typeof(ModeCaveat))]
    [JsonSerializable(typeof(OptionalModeCaveat))]
    [JsonSerializable(typeof(LabelledModeCaveat))]
    [JsonSerializable(typeof(LevelCaveat))]
    internal sealed partial class PlainContext : JsonSerializerContext
    {
    }

    /// <summary>Lists only the caveat class: no <see cref="JsonElement"/>, <c>string</c> or array metadata of its own.</summary>
    [JsonSerializable(typeof(ObjectCaveat))]
    internal sealed partial class ObjectOnlyContext : JsonSerializerContext
    {
    }

    // ─── F1: options-level enum converters are rejected at registration ──────

    [Fact(DisplayName = "A context with UseStringEnumConverter is refused for an enum parameter, naming the parameter and the enum")]
    public void Register_StringEnumContext_ThrowsNamingTheEnum()
    {
        // The converter is not observable through the metadata; only its output is.
        JsonSerializer.Serialize(new ModeCaveat { Mode = Mode.High }, StringEnumContext.Default.ModeCaveat)
            .Should().Contain("\"High\"");

        var act = () => new CaveatTypeRegistry().Register("Mode", StringEnumContext.Default.ModeCaveat);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*ModeCaveat.mode*")
            .WithMessage($"*{typeof(Mode).FullName}*")
            .WithMessage("*UseStringEnumConverter*");
    }

    [Fact(DisplayName = "A Nullable<enum> parameter is probed as well")]
    public void Register_StringEnumContext_NullableEnum_Throws()
    {
        var act = () => new CaveatTypeRegistry().Register("OptionalMode", StringEnumContext.Default.OptionalModeCaveat);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*OptionalModeCaveat.fallback*")
            .WithMessage($"*{typeof(Mode).FullName}*");
    }

    [Fact(DisplayName = "Through a plain context an enum parameter registers and writes the reflection overload's bytes")]
    public void Register_PlainContext_WritesTheSameBytesAsReflection()
    {
        var reflection = new CaveatTypeRegistry()
            .Register<ModeCaveat>("Mode")
            .Register<OptionalModeCaveat>("OptionalMode")
            .Register<LabelledModeCaveat>("LabelledMode");
        var generated = new CaveatTypeRegistry()
            .Register("Mode", PlainContext.Default.ModeCaveat)
            .Register("OptionalMode", PlainContext.Default.OptionalModeCaveat)
            .Register("LabelledMode", PlainContext.Default.LabelledModeCaveat);

        foreach (var caveat in new Caveat[]
                 {
                     new ModeCaveat { Mode = Mode.High },
                     new OptionalModeCaveat { Fallback = Mode.Low },
                     new OptionalModeCaveat(),
                     new LabelledModeCaveat { Mode = Mode.High },
                 })
        {
            var fromContext = CaveatCodec.Write(caveat, generated).GetRawText();
            fromContext.Should().Be(CaveatCodec.Write(caveat, reflection).GetRawText());
        }

        CaveatCodec.Write(new ModeCaveat { Mode = Mode.High }, generated).GetRawText().Should().Be("""{"mode":1,"type":"Mode"}""");
        CaveatCodec.Write(new OptionalModeCaveat { Fallback = Mode.Low }, generated).GetRawText()
            .Should().Be("""{"fallback":0,"type":"OptionalMode"}""");
        CaveatCodec.Write(new OptionalModeCaveat(), generated).GetRawText().Should().Be("""{"type":"OptionalMode"}""");
        // The member-level converter is part of the class, so both overloads write the string.
        CaveatCodec.Write(new LabelledModeCaveat { Mode = Mode.High }, generated).GetRawText()
            .Should().Be("""{"mode":"High","type":"LabelledMode"}""");
    }

    [Fact(DisplayName = "A [JsonConverter] on the enum type passes the probe and writes the same string under both overloads")]
    public void Register_EnumTypeLevelConverter_IsAcceptedByBothOverloads()
    {
        var reflection = new CaveatTypeRegistry().Register<LevelCaveat>("Level");
        var generated = new CaveatTypeRegistry().Register("Level", PlainContext.Default.LevelCaveat);

        var caveat = new LevelCaveat { Level = Level.Gold };
        CaveatCodec.Write(caveat, generated).GetRawText().Should().Be("""{"level":"Gold","type":"Level"}""");
        CaveatCodec.Write(caveat, reflection).GetRawText().Should().Be(CaveatCodec.Write(caveat, generated).GetRawText());
    }

    // ─── F5: object-typed parameters resolve JsonElement through Core's context ──

    [Fact(DisplayName = "An object parameter registered through a caveat-only context writes and reads back a string and a JsonElement")]
    public void Register_ObjectParameter_ContextWithoutJsonElement_RoundTrips()
    {
        var registry = new CaveatTypeRegistry().Register("Object", ObjectOnlyContext.Default.ObjectCaveat);
        registry.TryGet("Object", out var registration).Should().BeTrue();
        var options = registration!.TypeInfo.Options;

        ((IJsonTypeInfoResolver)ObjectOnlyContext.Default).GetTypeInfo(typeof(JsonElement), options)
            .Should().BeNull("the consumer context lists only the caveat class");
        options.GetTypeInfo(typeof(JsonElement)).OriginatingResolver.Should().BeSameAs(ZcapJsonContext.Default,
            "Core's generated context backs the registration for the DOM types the object converter needs");
        options.GetTypeInfo(typeof(ObjectCaveat)).OriginatingResolver.Should().BeSameAs(ObjectOnlyContext.Default,
            "the consumer's context is consulted first");

        var text = CaveatCodec.Write(new ObjectCaveat { Value = "plain" }, registry);
        text.GetRawText().Should().Be("""{"type":"Object","value":"plain"}""");
        var element = CaveatCodec.Write(
            new ObjectCaveat { Value = JsonDocument.Parse("""{"z":[1,2.5,"ünï+<>&'"],"a":{"b":true}}""").RootElement }, registry);
        element.GetRawText().Should().Be("""{"type":"Object","value":{"a":{"b":true},"z":[1,2.5,"ünï+<>&'"]}}""");

        foreach (var written in new[] { text, element })
        {
            var wrapped = JsonSerializer.SerializeToElement(new[] { written }, ZcapJsonOptions.TypeInfo<JsonElement[]>());
            CaveatCodec.TryRead(wrapped, new[] { registration.ContextUrl }, registry, materialize: true, out var entries)
                .Should().BeNull();
            var read = entries.Single().Value.Should().BeOfType<ObjectCaveat>().Subject;
            var value = read.Value.Should().BeOfType<JsonElement>().Subject;
            JsonElement.DeepEquals(value, written.GetProperty("value")).Should().BeTrue();
            read.IsAttenuationOf(read).Should().BeTrue();
        }

        // The same class through reflection resolves identically, so the overloads still agree.
        CaveatCodec.Write(new ObjectCaveat { Value = "plain" }, new CaveatTypeRegistry().Register<ObjectCaveat>("Object"))
            .GetRawText().Should().Be(text.GetRawText());
    }
}
