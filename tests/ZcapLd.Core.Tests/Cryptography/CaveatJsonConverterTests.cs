using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Issue #39 — verify the polymorphic Caveat converter preserves derived-class
/// fields through both the sign-time and verifier-time JSON paths. Without this
/// converter, STJ uses the static array element type when serializing
/// <c>Caveat[]</c>, silently dropping derived fields and making cross-language
/// signature verification fail at the chain link with the caveat.
/// </summary>
public class CaveatJsonConverterTests
{
    [Fact(DisplayName = "Issue #39 — single Caveat serializes with derived fields")]
    public void Serialize_DerivedCaveat_PreservesDerivedFields()
    {
        Caveat caveat = new ExpirationCaveat
        {
            Expires = new DateTime(2026, 12, 31, 23, 59, 59, DateTimeKind.Utc)
        };

        var json = JsonSerializer.Serialize(caveat, ZcapJsonOptions.Default);

        json.Should().Contain("\"type\":\"Expiration\"");
        json.Should().Contain("\"expires\":");
        // Without the converter, STJ would write only `{"type":"Expiration"}`.
    }

    [Fact(DisplayName = "Issue #39 — Caveat[] serializes each element with its derived fields")]
    public void Serialize_AsArray_PreservesDerivedFields()
    {
        var caveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = new DateTime(2026, 12, 31, 23, 59, 59, DateTimeKind.Utc) },
            new UsageCountCaveat { MaxUses = 5 },
            new ValidWhileTrueCaveat { Uri = "https://revocation.example.com/check/abc" }
        };

        var json = JsonSerializer.Serialize(caveats, ZcapJsonOptions.Default);

        json.Should().Contain("\"type\":\"Expiration\"");
        json.Should().Contain("\"expires\":");
        json.Should().Contain("\"type\":\"UsageCount\"");
        json.Should().Contain("\"maxUses\":5");
        json.Should().Contain("\"type\":\"ValidWhileTrue\"");
        json.Should().Contain("\"uri\":\"https://revocation.example.com/check/abc\"");
    }

    [Fact(DisplayName = "Issue #39 — UsageCountCaveat.CurrentUses is runtime state and stays out of the wire")]
    public void Serialize_UsageCount_OmitsCurrentUses()
    {
        Caveat caveat = new UsageCountCaveat { MaxUses = 10, CurrentUses = 7 };

        var json = JsonSerializer.Serialize(caveat, ZcapJsonOptions.Default);

        json.Should().Contain("\"maxUses\":10");
        // CurrentUses changes over the capability's lifetime; including it in
        // signed bytes would invalidate the signature on every increment.
        json.Should().NotContain("currentUses");
    }

    [Fact(DisplayName = "Deserialize known discriminator round-trips to concrete type with all fields")]
    public void Deserialize_KnownDiscriminator_ProducesConcreteType()
    {
        var json = "{\"type\":\"Expiration\",\"expires\":\"2026-12-31T23:59:59Z\"}";

        var caveat = JsonSerializer.Deserialize<Caveat>(json, ZcapJsonOptions.Default);

        caveat.Should().BeOfType<ExpirationCaveat>();
        caveat!.Type.Should().Be("Expiration");
        ((ExpirationCaveat)caveat).Expires.Should().Be(
            new DateTime(2026, 12, 31, 23, 59, 59, DateTimeKind.Utc));
    }

    [Fact(DisplayName = "Deserialize unknown discriminator throws JsonException with a registry-friendly hint")]
    public void Deserialize_UnknownDiscriminator_Throws()
    {
        var json = "{\"type\":\"NotARealCaveatType\",\"foo\":42}";

        var act = () => JsonSerializer.Deserialize<Caveat>(json, ZcapJsonOptions.Default);

        act.Should().Throw<JsonException>()
            .WithMessage("*NotARealCaveatType*")
            .WithMessage("*CaveatTypeRegistry*");
    }

    [Fact(DisplayName = "Deserialize without 'type' discriminator throws")]
    public void Deserialize_MissingDiscriminator_Throws()
    {
        var json = "{\"expires\":\"2026-12-31T23:59:59Z\"}";

        var act = () => JsonSerializer.Deserialize<Caveat>(json, ZcapJsonOptions.Default);

        act.Should().Throw<JsonException>().WithMessage("*type*");
    }

    [Theory(DisplayName = "Issue #45 — concrete Caveat round-trip preserves wire bytes (no duplicate Type/type keys)")]
    [InlineData(typeof(ExpirationCaveat), "{\"type\":\"Expiration\",\"expires\":\"2027-01-01T00:00:00Z\"}")]
    [InlineData(typeof(UsageCountCaveat), "{\"type\":\"UsageCount\",\"maxUses\":5}")]
    [InlineData(typeof(ValidWhileTrueCaveat), "{\"type\":\"ValidWhileTrue\",\"uri\":\"https://example.com/status\"}")]
    public void Caveat_Roundtrip_PreservesWireBytes(Type concreteType, string wireJson)
    {
        // Without [JsonPropertyName("type")] on the concrete override, STJ on .NET 10
        // catalogues the override as a separate property and emits the CLR name
        // ("Type") alongside the inherited ("type"). Both keys land on the wire,
        // JCS doesn't dedupe, and signature verification fails against any other
        // Data Integrity implementation. The fix is per-subclass attribute
        // re-declaration; this test guards against regression.
        var deserialized = JsonSerializer.Deserialize(wireJson, concreteType, ZcapJsonOptions.Default)!;
        var roundTripped = JsonSerializer.Serialize(deserialized, concreteType, ZcapJsonOptions.Default);

        roundTripped.Should().Be(wireJson,
            "wire bytes from a one-key body must round-trip byte-for-byte; duplicate " +
            "\"Type\"/\"type\" keys break cross-stack signature verification (#45).");
        roundTripped.Should().NotContain("\"Type\":",
            "uppercase \"Type\" key indicates STJ catalogued the abstract-base property and " +
            "the override as separate JsonPropertyInfo entries (#45 root cause).");
    }

    [Fact(DisplayName = "Round-trip: serialize then deserialize preserves derived-class state")]
    public void RoundTrip_PreservesDerivedFields()
    {
        Caveat[] original =
        {
            new ExpirationCaveat { Expires = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc) },
            new UsageCountCaveat { MaxUses = 3 },
            new ValidWhileTrueCaveat { Uri = "https://revocation.example.com/x" }
        };

        var json = JsonSerializer.Serialize(original, ZcapJsonOptions.Default);
        var deserialized = JsonSerializer.Deserialize<Caveat[]>(json, ZcapJsonOptions.Default);

        deserialized.Should().NotBeNull();
        deserialized!.Should().HaveCount(3);

        deserialized[0].Should().BeOfType<ExpirationCaveat>()
            .Which.Expires.Should().Be(new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc));
        deserialized[1].Should().BeOfType<UsageCountCaveat>()
            .Which.MaxUses.Should().Be(3);
        deserialized[2].Should().BeOfType<ValidWhileTrueCaveat>()
            .Which.Uri.Should().Be("https://revocation.example.com/x");
    }

    [Fact(DisplayName = "Custom caveat registered against Default registry round-trips through the converter")]
    public void RegisterCustomCaveat_RoundTrips()
    {
        // Use a discriminator unique to this test so re-runs in the same process
        // (xUnit doesn't tear down AppDomain) don't trip the conflict guard.
        var discriminator = $"TestCaveat-{Guid.NewGuid():N}";
        CaveatTypeRegistry.Default.Register<TestCustomCaveat>(discriminator);

        Caveat caveat = new TestCustomCaveat(discriminator) { Threshold = 42 };
        var json = JsonSerializer.Serialize(caveat, ZcapJsonOptions.Default);
        var roundTripped = JsonSerializer.Deserialize<Caveat>(json, ZcapJsonOptions.Default);

        roundTripped.Should().BeOfType<TestCustomCaveat>()
            .Which.Threshold.Should().Be(42);
    }

    [Fact(DisplayName = "Re-registering same discriminator with a different type throws")]
    public void Register_ConflictingType_Throws()
    {
        var discriminator = $"ConflictCaveat-{Guid.NewGuid():N}";
        CaveatTypeRegistry.Default.Register<TestCustomCaveat>(discriminator);

        var act = () => CaveatTypeRegistry.Default.Register<AnotherTestCaveat>(discriminator);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*'{discriminator}'*already registered*");
    }

    private sealed class TestCustomCaveat : Caveat
    {
        private readonly string _type;
        public TestCustomCaveat() : this("TestCaveat") { }
        public TestCustomCaveat(string type) { _type = type; }

        public override string Type => _type;

        [System.Text.Json.Serialization.JsonPropertyName("threshold")]
        public int Threshold { get; set; }

        public override bool IsSatisfied(InvocationContext context) => true;
    }

    private sealed class AnotherTestCaveat : Caveat
    {
        public override string Type => "Another";
        public override bool IsSatisfied(InvocationContext context) => true;
    }
}
