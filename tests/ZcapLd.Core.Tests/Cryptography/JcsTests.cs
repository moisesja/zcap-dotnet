using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Issue #154 — ZcapLd canonicalizes through NetCid's reflection-free <see cref="JsonElement"/> path
/// (<see cref="Jcs"/>). The bytes must be the ones 6.0.0 produced through the <see cref="JsonNode"/>
/// overload: the digests and context documents below were computed by running the 6.0.0 code
/// (commit 4f0cc8e, <c>RevocationScope.KeyFor</c>, <c>CaveatCodec.GrantKey</c>,
/// <c>CaveatTypeRegistry.GetContextDocument</c> and <c>CaveatCodec.Write</c>) in a throwaway worktree,
/// never from the code under test.
/// </summary>
public class JcsTests
{
    private const string UuidId = "urn:uuid:7e1f2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b";
    private const string RootId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocs";
    private const string UnicodeId = "https://example.com/zcaps/ünïcødé-☃-日本語";
    private const string RelaxedId = "https://example.com/zcaps/a+b<c>d&e'f";
    private const string DelegatedId = "urn:zcap:delegated:1";
    private const string Alice = "did:key:z6MkAlice";
    private const string Tenant = "did:web:issuer.example:tenant";

    /// <summary>Two parameters, one nested object and one array; registered only by these tests.</summary>
    public sealed class WindowCaveat : Caveat
    {
        public override string Type => "Window";

        [JsonPropertyName("bounds")]
        public required WindowBounds Bounds { get; init; }

        [JsonPropertyName("tags")]
        public string[]? Tags { get; init; }

        [JsonPropertyName("weight")]
        public int Weight { get; init; }
    }

    public sealed class WindowBounds
    {
        [JsonPropertyName("start")]
        public required string Start { get; init; }

        [JsonPropertyName("end")]
        public required string End { get; init; }
    }

    // ─── Node path equals NetCid's node overload ──────────────────────────────

    public static IEnumerable<object?[]> Nodes()
    {
        yield return new object?[] { null };
        yield return new object?[] { JsonValue.Create("plain") };
        yield return new object?[] { JsonValue.Create("ünïcødé ☃ 😀 日本語 " + "\u2028" + " a+b<c>d&e'f \"q\" \\ \t \n \u0001") };
        yield return new object?[] { JsonValue.Create(42) };
        yield return new object?[] { JsonValue.Create(-0) };
        yield return new object?[] { JsonValue.Create(long.MaxValue) };
        yield return new object?[] { JsonValue.Create(1.5) };
        yield return new object?[] { JsonValue.Create(1e21) };
        yield return new object?[] { JsonValue.Create(0.0001) };
        yield return new object?[] { JsonValue.Create(1e-7) };
        yield return new object?[] { JsonValue.Create(9007199254740992d) };
        yield return new object?[] { JsonValue.Create(3.14159m) };
        yield return new object?[] { JsonValue.Create(true) };
        yield return new object?[] { JsonValue.Create(false) };
        yield return new object?[] { new JsonArray() };
        yield return new object?[] { new JsonObject() };
        yield return new object?[]
        {
            new JsonObject
            {
                ["z"] = new JsonArray(1, 2.5, -3, true, false, null, new JsonObject { ["b"] = "c" }),
                ["a"] = new JsonObject { ["nested"] = new JsonObject { ["deep"] = new JsonArray(new JsonArray(new JsonArray())) } },
                ["é"] = "unicode key",
                ["key with \"quotes\" and \\"] = "escapes",
                ["null"] = null,
                ["empty"] = "",
                ["1"] = 1,
                ["10"] = 10,
                ["2"] = 2,
            },
        };
        yield return new object?[]
        {
            JsonNode.Parse("""{"numbers":[0,1,-1,1.0,1E2,1e-3,123456789012345678,0.1,1.7976931348623157E308,5e-324],"s":"😀"}"""),
        };
        yield return new object?[] { JsonNode.Parse("""[{"capabilityId":"urn:x","scope":"delegated:did:key:z6Mk"},"root"]""") };
    }

    [Theory]
    [MemberData(nameof(Nodes))]
    public void Canonicalize_Node_MatchesNetCidNodeOverload(JsonNode? node)
    {
        var expected = NetCid.JcsCanonicalizer.Canonicalize(node);
        Jcs.Canonicalize(node).Should().Equal(expected);
        Jcs.Canonicalize(Jcs.ToElement(node)).Should().Equal(expected);
    }

    [Fact]
    public void Canonicalize_Node_RejectsDepthBeyondNetCidLimitAsJcsFormat()
    {
        JsonNode deep = new JsonArray();
        var root = deep;
        for (var i = 0; i < 70; i++)
        {
            var next = new JsonArray();
            ((JsonArray)deep).Add(next);
            deep = next;
        }

        new Action(() => NetCid.JcsCanonicalizer.Canonicalize(root)).Should().Throw<NetCid.JcsFormatException>();
        new Action(() => Jcs.Canonicalize(root)).Should().Throw<NetCid.JcsFormatException>();
    }

    // ─── Pinned 6.0.0 bytes ───────────────────────────────────────────────────

    [Theory]
    [InlineData("root", UuidId, "be714b9c4b3d72f4fc2ac4d860a6fbf0879bf99513cacde39efd3bc749c37271")]
    [InlineData("root", RootId, "5e8e0f199b9285b49f67c51c2ae793cc275cc8e0771546102fb19b867182faf8")]
    [InlineData("root", UnicodeId, "52f8e52d0fd4bb9d451a8eb3f3ada795677966b90a76c10224ae57f958f646f2")]
    [InlineData("root", RelaxedId, "dfa7bbbbe3a73e8daf5a066d6db0bc5fa0d4715a7ddc548a42e14d6978ca4d9d")]
    [InlineData("root", DelegatedId, "f819770e15ceb0a638ab57380d0b696a3bd8cb0a9bfa7f807517ee44ed84eca1")]
    [InlineData("unscoped", UuidId, "380d373cf72fad811b71a855b9823f3e9d3c2491d59aa6982c05ba50d85c7825")]
    [InlineData("unscoped", RootId, "4bfa6b35c7050a8ca8bf14f5bb87ad1165ff1b64a3fbbe90bd00244e84cb62ab")]
    [InlineData("unscoped", UnicodeId, "82cc46d38c74348088658545a91cf94d74fcc065affeca5582961004e886ed84")]
    [InlineData("unscoped", RelaxedId, "351f0556dcb700f069e478fb5037114dc6212d3f1ac9416cbd7e7551b1ae19cf")]
    [InlineData("unscoped", DelegatedId, "8e13626bc938e27c3dc7e00667a4ab5dc179bb7f034ec6c1686a715896fad69d")]
    [InlineData("delegated:" + Alice, UuidId, "59b873b5bedd13d10ae61dfb56187fbf2a8d14b82bc1f4960db37c0bda5a9285")]
    [InlineData("delegated:" + Alice, RootId, "3438100513e9693f696d96861f6a82d8dc12608ada109201a7aee8732d2595a0")]
    [InlineData("delegated:" + Alice, UnicodeId, "e95b44e1f539c935a5da3409945d4a77cea60e623f719d9302786e19c29d432a")]
    [InlineData("delegated:" + Alice, RelaxedId, "6e19ed4d01568b786fb67ed3b9f677fd077c79e9725ddc0eb997e1e47695ab52")]
    [InlineData("delegated:" + Alice, DelegatedId, "1c9eb00b321c2aa6aba052fdcc85cfab96379d9b7374a6a511717f79e13ed3df")]
    [InlineData("delegated:" + Tenant, UuidId, "1dbab3c4e096360251af7a8ec8a6a4319bcebedbd554e20cee348454e47342a6")]
    [InlineData("delegated:" + Tenant, RootId, "f5901a840e87675df917822362a1845aa94024d0477489d9a23e03e8a2c3b9f9")]
    [InlineData("delegated:" + Tenant, UnicodeId, "4af75f24c3128d000b8ff09f92b9d5d23ea7680cc5bee96f5aa0aef1be50dfaf")]
    [InlineData("delegated:" + Tenant, RelaxedId, "521ffa07a3ea36c13ca71d0dde079fb694aae8b6dffc87b7d7b0e8982074e6a4")]
    [InlineData("delegated:" + Tenant, DelegatedId, "ce192005d39b2936c0c30ba6ae68f385d6e1853e67b061ddbe394176a7c3371d")]
    public void RevocationScope_KeyFor_IsPinnedTo600(string scope, string id, string expected)
        => RevocationScope.Parse(scope).KeyFor(id).Should().Be(expected);

    [Fact]
    public void CaveatCodec_GrantKey_IsPinnedTo600()
    {
        var ids = new[] { UuidId, RootId, UnicodeId, RelaxedId, DelegatedId };
        CaveatCodec.GrantKey(ids.Take(1)).Should().Be("1c9a174a3476b331a58909f0dccc4899a9a1132fed446ca26b1b16ed6f6e01ae");
        CaveatCodec.GrantKey(ids.Take(2)).Should().Be("671229425d2dc07044521ec7bb12d01ae014a8298fc034665ce63443a80acd62");
        CaveatCodec.GrantKey(ids).Should().Be("cae664c62aca2d3bb94a74a69193f3e0bd7e1cf6b56535004b880def070424cf");
        CaveatCodec.GrantKey(new[] { UnicodeId, RelaxedId }).Should().Be("da4ab219e8b11326e612ec49e95ae2a757400702badc7240f81c6ad9da725271");
    }

    [Theory]
    [InlineData(EpsilonBudgetCaveat.TypeName,
        """{"@context":{"@protected":true,"EpsilonBudget":{"@context":{"@protected":true,"maxEpsilon":{"@id":"urn:zcap-dotnet:caveat:v1:EpsilonBudget#maxEpsilon","@type":"@json"}},"@id":"urn:zcap-dotnet:caveat:v1:EpsilonBudget"}}}""")]
    [InlineData(RegionCaveat.TypeName,
        """{"@context":{"@protected":true,"Region":{"@context":{"@protected":true,"allowed":{"@id":"urn:zcap-dotnet:caveat:v1:Region#allowed","@type":"@json"}},"@id":"urn:zcap-dotnet:caveat:v1:Region"}}}""")]
    [InlineData(TagCaveat.TypeName,
        """{"@context":{"@protected":true,"Tag":{"@context":{"@protected":true,"data":{"@id":"urn:zcap-dotnet:caveat:v1:Tag#data","@type":"@json"}},"@id":"urn:zcap-dotnet:caveat:v1:Tag"}}}""")]
    [InlineData("Window",
        """{"@context":{"@protected":true,"Window":{"@context":{"@protected":true,"bounds":{"@id":"urn:zcap-dotnet:caveat:v1:Window#bounds","@type":"@json"},"tags":{"@id":"urn:zcap-dotnet:caveat:v1:Window#tags","@type":"@json"},"weight":{"@id":"urn:zcap-dotnet:caveat:v1:Window#weight","@type":"@json"}},"@id":"urn:zcap-dotnet:caveat:v1:Window"}}}""")]
    public void CaveatTypeRegistry_GetContextDocument_IsPinnedTo600(string type, string expected)
        => Registry().GetContextDocument(type).Should().Be(expected);

    [Fact]
    public void CaveatCodec_Write_IsPinnedTo600()
    {
        var registry = Registry();
        var window = new WindowCaveat
        {
            Bounds = new WindowBounds { Start = "2026-01-01T00:00:00Z", End = "2026-02-01T00:00:00Z" },
            Tags = new[] { "b", "a", "ünï+<>&'" },
            Weight = 3,
        };
        CaveatCodec.Write(window, registry).GetRawText().Should().Be(
            """{"bounds":{"end":"2026-02-01T00:00:00Z","start":"2026-01-01T00:00:00Z"},"tags":["b","a","ünï+<>&'"],"type":"Window","weight":3}""");
        CaveatCodec.Write(new RegionCaveat { Allowed = new[] { "eu-west", "us-east" } }, registry).GetRawText()
            .Should().Be("""{"allowed":["eu-west","us-east"],"type":"Region"}""");
        CaveatCodec.Write(new EpsilonBudgetCaveat { MaxEpsilon = 2.5 }, registry).GetRawText()
            .Should().Be("""{"maxEpsilon":2.5,"type":"EpsilonBudget"}""");
    }

    [Fact]
    public void CaveatCodec_Write_OmitsNullParametersAndRoundTrips()
    {
        var registry = Registry();
        var window = new WindowCaveat { Bounds = new WindowBounds { Start = "s", End = "e" }, Weight = 0 };
        var element = CaveatCodec.Write(window, registry);
        element.GetRawText().Should().Be("""{"bounds":{"end":"e","start":"s"},"type":"Window","weight":0}""");
        Encoding.UTF8.GetString(Jcs.Canonicalize(element)).Should().Be(element.GetRawText());
    }

    private static CaveatTypeRegistry Registry() => CaveatTestBed.NewRegistry().Register<WindowCaveat>("Window");
}
