using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Issue #154 — the source-generated <see cref="ZcapJsonContext"/> and the union converters on
/// <see cref="Capability.Context"/> / <see cref="Proof.CapabilityChain"/> must produce the bytes the
/// 6.0.0 reflection serializer produced. Three option sets are compared over rich fixtures:
/// <list type="bullet">
/// <item><b>Legacy</b>: reflection only, with the #154 converters stripped from the two union members,
/// which is exactly the 6.0.0 serializer (the reflection object converter dispatching on runtime type).</item>
/// <item><b>Context-only</b>: <see cref="ZcapJsonContext.Default"/> as the sole resolver, which is what a
/// native AOT, trimmed or file-based application gets.</item>
/// <item><b>Shared</b>: <see cref="ZcapJsonOptions.Default"/>, the combined resolver every service uses.</item>
/// </list>
/// </summary>
public class SourceGeneratedJsonTests
{
    private const string ZcapContext = "https://w3id.org/zcap/v1";
    private const string SuiteContext = "https://w3id.org/security/suites/ed25519-2020/v1";
    private const string RootId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocs";

    private static readonly JsonSerializerOptions Legacy = Configure(new JsonSerializerOptions
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver
        {
            Modifiers =
            {
                static info =>
                {
                    foreach (var property in info.Properties)
                    {
                        if (property.Name is "@context" or "capabilityChain")
                            property.CustomConverter = null; // 6.0.0: the reflection object converter.
                    }
                }
            }
        }
    });

    private static readonly JsonSerializerOptions ContextOnly = Configure(new JsonSerializerOptions
    {
        TypeInfoResolver = ZcapJsonContext.Default
    });

    private static readonly JsonSerializerOptions Shared = ZcapJsonOptions.Default;

    private static JsonSerializerOptions Configure(JsonSerializerOptions options)
    {
        options.WriteIndented = false;
        options.PropertyNamingPolicy = null;
        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        options.AllowDuplicateProperties = false;
        return options;
    }

    // ─── Fixtures ────────────────────────────────────────────────────────────

    private static Capability Root() => new()
    {
        Id = RootId,
        Context = ZcapContext,
        Controller = "did:key:z6MkAlice",
        InvocationTarget = "https://example.com/docs",
    };

    private static Dictionary<string, JsonElement> RichExtensionData() => new(StringComparer.Ordinal)
    {
        ["nested"] = JsonDocument.Parse("""{"a":[1,2.5,-3,true,false,null,{"b":"c"}],"empty":{},"list":[]}""").RootElement.Clone(),
        ["unicode"] = JsonDocument.Parse("\"ünïcødé ☃ 😀 日本語\"").RootElement.Clone(),
        ["relaxed"] = JsonDocument.Parse("\"+<>&' \\\"quoted\\\" back\\\\slash \\u0001 tab\\t\"").RootElement.Clone(),
        ["explicitNull"] = JsonDocument.Parse("null").RootElement.Clone(),
        ["number"] = JsonDocument.Parse("1e-07").RootElement.Clone(),
    };

    private static Proof DelegationProof(object[] chain, Dictionary<string, JsonElement>? extra = null) => new()
    {
        Type = "Ed25519Signature2020",
        Created = "2026-04-29T12:00:00.000000Z",
        ProofPurpose = Proof.CapabilityDelegationPurpose,
        VerificationMethod = "did:key:z6MkAlice#z6MkAlice",
        CapabilityChain = chain,
        ProofValue = "z3FXQ4example",
        AdditionalProperties = extra,
    };

    private static Capability Middle() => new()
    {
        Id = "urn:uuid:11111111-1111-1111-1111-111111111111",
        Context = new object[] { ZcapContext, SuiteContext },
        Controller = new[] { "did:key:z6MkBob" },
        InvocationTarget = "https://example.com/docs/folder",
        AllowedAction = new[] { "read", "write" },
        Expires = "2027-01-01T00:00:00.000000Z",
        ParentCapability = RootId,
        Proof = DelegationProof(new object[] { RootId }),
    };

    /// <summary>Every modeled field, both array forms, a mixed chain and adversarial extension data.</summary>
    private static Capability Leaf()
    {
        var middle = Middle();
        var proofExtra = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["nonce"] = JsonDocument.Parse("\"n-0S6_WzA2Mj\"").RootElement.Clone(),
            ["domain"] = JsonDocument.Parse("\"example.com\"").RootElement.Clone(),
        };
        var chain = new object[]
        {
            RootId,
            JsonDocument.Parse($"\"{middle.Id}\"").RootElement.Clone(),
            middle,                                                        // embedded Capability
            JsonDocument.Parse("""{"id":"urn:zcap:el","@context":"x"}""").RootElement.Clone(),
            JsonNode.Parse("""{"id":"urn:zcap:node"}""")!,                 // JsonNode entry
            null!,                                                         // kept as JSON null
        };
        return new Capability
        {
            Id = "urn:uuid:22222222-2222-2222-2222-222222222222",
            Context = new object[] { ZcapContext, SuiteContext },
            Controller = new[] { "did:key:z6MkCarol", "did:key:z6MkDave" },
            InvocationTarget = "https://example.com/docs/folder/file?x=1&y=2",
            AllowedAction = new[] { "read" },
            Expires = "2026-12-31T23:59:59.000000Z",
            ParentCapability = middle.Id,
            Proof = ProofSet.FromValues(new[]
            {
                DelegationProof(chain, proofExtra),
                new Proof
                {
                    Type = "EcdsaSecp256r1Signature2019",
                    Created = "2026-04-29T12:00:01.000000Z",
                    ProofPurpose = "assertionMethod",
                    VerificationMethod = "did:key:zDnaeExample#zDnaeExample",
                    ProofValue = "zAssertion",
                },
            }, asArray: true),
            AdditionalProperties = RichExtensionData(),
        };
    }

    private static Invocation DelegatedInvocation() => new()
    {
        Id = "urn:uuid:33333333-3333-3333-3333-333333333333",
        Capability = InvocationCapability.FromCapability(Leaf()),
        CapabilityAction = "read",
        InvocationTarget = "https://example.com/docs/folder/file?x=1&y=2",
        Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:02.000000Z",
            ProofPurpose = Proof.CapabilityInvocationPurpose,
            VerificationMethod = "did:key:z6MkCarol#z6MkCarol",
            ProofValue = "zInvocation",
            Capability = InvocationCapability.FromCapability(Leaf()),
            InvocationTarget = "https://example.com/docs/folder/file?x=1&y=2",
            CapabilityAction = "read",
        },
    };

    private static Invocation RootInvocation() => new()
    {
        Id = "urn:uuid:44444444-4444-4444-4444-444444444444",
        Capability = RootId,
        CapabilityAction = "revoke",
        InvocationTarget = "https://example.com/docs",
        Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:03.000000Z",
            ProofPurpose = Proof.CapabilityRevocationPurpose,
            VerificationMethod = "did:key:z6MkAlice#z6MkAlice",
            ProofValue = "zRevocation",
            Capability = RootId,
            InvocationTarget = "https://example.com/docs",
            CapabilityAction = "revoke",
            AdditionalProperties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["revocationReason"] = JsonDocument.Parse("\"key compromised\"").RootElement.Clone(),
                ["revocationMetadata"] = JsonDocument.Parse("""{"ticket":"T-1","by":"ops"}""").RootElement.Clone(),
            },
        },
    };

    private static RevocationRequest RevocationRequestFixture() => new()
    {
        CapabilityId = "urn:uuid:22222222-2222-2222-2222-222222222222",
        Scope = RevocationScope.Delegated("did:key:z6MkBob"),
        RootCapabilityId = RootId,
        RevokedBy = "did:key:z6MkBob",
        ExpiresAt = new DateTime(2026, 12, 31, 23, 59, 59, DateTimeKind.Utc),
        Reason = "rotated",
        Metadata = new Dictionary<string, string> { ["ticket"] = "T-1" },
    };

    private static RevocationRecord RevocationRecordFixture() => new()
    {
        CapabilityId = RootId,
        Scope = RevocationScope.Root,
        RevokedBy = "did:key:z6MkAlice",
        RevokedAt = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc),
        Metadata = new Dictionary<string, string> { ["ticket"] = "T-2" },
    };

    private static Capability WithContext(object context)
    {
        var capability = Root();
        capability.Context = context;
        return capability;
    }

    public static TheoryData<string, object> ContextShapes() => new()
    {
        { "string", ZcapContext },
        { "object[] of strings", new object[] { ZcapContext, SuiteContext } },
        { "string[]", new[] { ZcapContext, SuiteContext } },
        { "List<object>", new List<object> { ZcapContext, SuiteContext } },
        { "List<string>", new List<string> { ZcapContext } },
        { "JsonElement array", JsonDocument.Parse($"[\"{ZcapContext}\",{{\"inline\":\"https://example.com/#\"}}]").RootElement.Clone() },
        { "JsonElement string", JsonDocument.Parse($"\"{ZcapContext}\"").RootElement.Clone() },
        { "JsonArray", new JsonArray(ZcapContext, SuiteContext) },
        { "JsonObject", new JsonObject { ["@vocab"] = "https://example.com/#", ["n"] = 1 } },
        { "object[] mixed", new object[] { ZcapContext, JsonNode.Parse("""{"a":"b"}""")!, JsonDocument.Parse("[1,\"two\"]").RootElement.Clone(), new[] { "nested" }, null! } },
        { "Dictionary<string, object>", new Dictionary<string, object> { ["@vocab"] = "https://example.com/#", ["list"] = new object[] { "a", new[] { "b" } } } },
        { "nested object[][]", new object[] { new object[] { ZcapContext }, new object[] { } } },
    };

    // ─── Byte identity ───────────────────────────────────────────────────────

    private static byte[] Bytes<T>(T value, JsonSerializerOptions options) => JsonSerializer.SerializeToUtf8Bytes(value, options);

    private static byte[] AssertIdentical<T>(T value)
    {
        var legacy = Bytes(value, Legacy);
        var generated = Bytes(value, ContextOnly);
        var shared = Bytes(value, Shared);
        Encoding.UTF8.GetString(generated).Should().Be(Encoding.UTF8.GetString(legacy), "the generated context must write the 6.0.0 bytes");
        generated.Should().Equal(legacy);
        shared.Should().Equal(legacy);
        return legacy;
    }

    private static void AssertRoundTrips<T>(T value)
    {
        var expected = AssertIdentical(value);
        foreach (var options in new[] { Legacy, ContextOnly, Shared })
        {
            var parsed = JsonSerializer.Deserialize<T>(expected, options)!;
            Bytes(parsed, Legacy).Should().Equal(expected);
            Bytes(parsed, ContextOnly).Should().Equal(expected);
            Bytes(parsed, Shared).Should().Equal(expected);
        }
    }

    [Fact(DisplayName = "#154 — a root capability serializes to the same bytes under reflection, the context and the shared options")]
    public void Root_IsByteIdentical() => AssertRoundTrips(Root());

    [Fact(DisplayName = "#154 — a delegated capability with every field, array forms and a mixed chain is byte-identical and round-trips")]
    public void Leaf_IsByteIdentical() => AssertRoundTrips(Leaf());

    [Fact(DisplayName = "#154 — a leaf matches a hand-built wire expectation (property order, null handling, relaxed escaping)")]
    public void Leaf_MatchesHandBuiltExpectation()
    {
        var middle = Middle();
        // Non-ASCII text is written however the shared encoder writes it; the point here is ordering, nulls
        // and that +<>&' stay literal.
        var unicode = JsonEncodedText.Encode("ünïcødé ☃ 😀 日本語", JavaScriptEncoder.UnsafeRelaxedJsonEscaping).Value;
        var middleJson = $$$"""{"id":"{{{middle.Id}}}","@context":["{{{ZcapContext}}}","{{{SuiteContext}}}"],"controller":["did:key:z6MkBob"],"invocationTarget":"https://example.com/docs/folder","allowedAction":["read","write"],"expires":"2027-01-01T00:00:00.000000Z","parentCapability":"{{{RootId}}}","proof":{"type":"Ed25519Signature2020","created":"2026-04-29T12:00:00.000000Z","proofPurpose":"capabilityDelegation","verificationMethod":"did:key:z6MkAlice#z6MkAlice","capabilityChain":["{{{RootId}}}"],"proofValue":"z3FXQ4example"}}""";
        var expected =
            $$$"""{"id":"urn:uuid:22222222-2222-2222-2222-222222222222","@context":["{{{ZcapContext}}}","{{{SuiteContext}}}"],"controller":["did:key:z6MkCarol","did:key:z6MkDave"],"invocationTarget":"https://example.com/docs/folder/file?x=1&y=2","allowedAction":["read"],"expires":"2026-12-31T23:59:59.000000Z","parentCapability":"{{{middle.Id}}}","proof":[{"type":"Ed25519Signature2020","created":"2026-04-29T12:00:00.000000Z","proofPurpose":"capabilityDelegation","verificationMethod":"did:key:z6MkAlice#z6MkAlice","capabilityChain":["{{{RootId}}}","{{{middle.Id}}}",{{{middleJson}}},{"id":"urn:zcap:el","@context":"x"},{"id":"urn:zcap:node"},null],"proofValue":"z3FXQ4example","nonce":"n-0S6_WzA2Mj","domain":"example.com"},{"type":"EcdsaSecp256r1Signature2019","created":"2026-04-29T12:00:01.000000Z","proofPurpose":"assertionMethod","verificationMethod":"did:key:zDnaeExample#zDnaeExample","proofValue":"zAssertion"}],"nested":{"a":[1,2.5,-3,true,false,null,{"b":"c"}],"empty":{},"list":[]},"unicode":"{{{unicode}}}","relaxed":"+<>&' \"quoted\" back\\slash \u0001 tab\t","explicitNull":null,"number":1e-07}""";

        Encoding.UTF8.GetString(Bytes(Leaf(), ContextOnly)).Should().Be(expected);
        Encoding.UTF8.GetString(Bytes(Leaf(), Legacy)).Should().Be(expected);
    }

    [Fact(DisplayName = "#154 — a delegated invocation embedding the full capability is byte-identical and round-trips")]
    public void DelegatedInvocation_IsByteIdentical() => AssertRoundTrips(DelegatedInvocation());

    [Fact(DisplayName = "#154 — a root revocation invocation with signed reason/metadata is byte-identical and round-trips")]
    public void RootInvocation_IsByteIdentical() => AssertRoundTrips(RootInvocation());

    [Fact(DisplayName = "#154 — a bare proof set in array form is byte-identical and round-trips")]
    public void ProofSet_IsByteIdentical() => AssertRoundTrips(Leaf().Proof!);

    [Fact(DisplayName = "#154 — a bare proof with chain and extension data is byte-identical and round-trips")]
    public void Proof_IsByteIdentical() => AssertRoundTrips(Leaf().Proof!.Primary);

    [Fact(DisplayName = "#154 — RevocationRequest and RevocationRecord are byte-identical and round-trip")]
    public void RevocationModels_AreByteIdentical()
    {
        AssertRoundTrips(RevocationRequestFixture());
        AssertRoundTrips(RevocationRecordFixture());
        AssertIdentical(RevocationScope.Delegated("did:key:z6MkBob"));
    }

    [Theory(DisplayName = "#154 — every @context CLR shape writes the 6.0.0 bytes")]
    [MemberData(nameof(ContextShapes))]
    public void ContextShape_IsByteIdentical(string shape, object context)
    {
        shape.Should().NotBeEmpty();
        AssertRoundTrips(WithContext(context));
    }

    [Fact(DisplayName = "#154 — the collection and DOM types the services serialize are byte-identical")]
    public void CollectionAndDomTypes_AreByteIdentical()
    {
        var proofElement = JsonDocument.Parse(Bytes(Leaf().Proof!.Primary, Shared)).RootElement.Clone();
        var fields = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var property in proofElement.EnumerateObject())
            fields[property.Name] = property.Value;
        fields["@context"] = JsonDocument.Parse($"[\"{ZcapContext}\"]").RootElement.Clone();

        AssertIdentical(fields);
        AssertIdentical(new Dictionary<string, object> { ["@id"] = RootId, ["p"] = new Dictionary<string, string> { ["@id"] = RootId } });
        AssertIdentical(new Dictionary<string, string> { ["k"] = "+<>&'" });
        AssertIdentical<IDictionary<string, string>>(new Dictionary<string, string> { ["k"] = "v" });
        AssertIdentical(new[] { ZcapContext, SuiteContext });
        AssertIdentical<IEnumerable<string>>(new List<string> { ZcapContext });
        AssertIdentical<IReadOnlyList<string>>(new[] { ZcapContext });
        AssertIdentical(new List<object> { "a", null!, new object[] { "b" }, JsonDocument.Parse("1").RootElement.Clone() });
        AssertIdentical<object>(Leaf());
        AssertIdentical<object>(new JsonObject { ["@context"] = new JsonArray(ZcapContext), ["id"] = "urn:x" });
        AssertIdentical<JsonNode>(new JsonArray(1, "two", null));
        AssertIdentical(new[] { proofElement, JsonDocument.Parse("null").RootElement.Clone() });
        AssertIdentical<IEnumerable<JsonElement>>(new SortedDictionary<string, JsonElement> { ["b"] = proofElement, ["a"] = proofElement }.Values);
        AssertIdentical(RichExtensionData());
        AssertIdentical("+<>&' ünï");
        AssertIdentical<object>("+<>&' ünï");
    }

    // ─── Read semantics ─────────────────────────────────────────────────────

    [Fact(DisplayName = "#154 — a deserialized @context is a JsonElement under every options, and JSON null reads to null")]
    public void Context_ReadsToJsonElement()
    {
        foreach (var options in new[] { Legacy, ContextOnly, Shared })
        {
            var single = JsonSerializer.Deserialize<Capability>($$"""{"id":"urn:x","@context":"{{ZcapContext}}"}""", options)!;
            single.Context.Should().BeOfType<JsonElement>().Which.ValueKind.Should().Be(JsonValueKind.String);

            var array = JsonSerializer.Deserialize<Capability>($$"""{"id":"urn:x","@context":["{{ZcapContext}}",{"a":1}]}""", options)!;
            array.Context.Should().BeOfType<JsonElement>().Which.ValueKind.Should().Be(JsonValueKind.Array);

            var number = JsonSerializer.Deserialize<Capability>("""{"id":"urn:x","@context":42}""", options)!;
            number.Context.Should().BeOfType<JsonElement>().Which.GetInt32().Should().Be(42);

            var nulled = JsonSerializer.Deserialize<Capability>("""{"id":"urn:x","@context":null}""", options)!;
            nulled.Context.Should().BeNull();
            JsonSerializer.Serialize(nulled, options).Should().Be("""{"id":"urn:x","controller":"","invocationTarget":""}""");

            var absent = JsonSerializer.Deserialize<Capability>("""{"id":"urn:x"}""", options)!;
            absent.Context.Should().Be(ZcapContext);
        }
    }

    [Fact(DisplayName = "#154 — deserialized capabilityChain entries are JsonElements (JSON null entries read to null) under every options")]
    public void CapabilityChain_ReadsToJsonElements()
    {
        const string json = """{"type":"t","capabilityChain":["urn:a",{"id":"urn:b"},null,7]}""";
        foreach (var options in new[] { Legacy, ContextOnly, Shared })
        {
            var proof = JsonSerializer.Deserialize<Proof>(json, options)!;
            proof.CapabilityChain.Should().HaveCount(4);
            proof.CapabilityChain![0].Should().BeOfType<JsonElement>().Which.GetString().Should().Be("urn:a");
            proof.CapabilityChain[1].Should().BeOfType<JsonElement>().Which.GetProperty("id").GetString().Should().Be("urn:b");
            proof.CapabilityChain[2].Should().BeNull();
            proof.CapabilityChain[3].Should().BeOfType<JsonElement>().Which.GetInt32().Should().Be(7);

            JsonSerializer.Deserialize<Proof>("""{"type":"t","capabilityChain":null}""", options)!.CapabilityChain.Should().BeNull();
            JsonSerializer.Deserialize<Proof>("""{"type":"t"}""", options)!.CapabilityChain.Should().BeNull();

            var act = () => JsonSerializer.Deserialize<Proof>("""{"type":"t","capabilityChain":"urn:a"}""", options);
            act.Should().Throw<JsonException>();
        }
    }

    [Fact(DisplayName = "#154 — duplicate JSON properties are rejected under every options")]
    public void DuplicateProperties_AreRejected()
    {
        foreach (var options in new[] { Legacy, ContextOnly, Shared })
        {
            var modeled = () => JsonSerializer.Deserialize<Capability>("""{"id":"urn:a","id":"urn:b"}""", options);
            modeled.Should().Throw<JsonException>();

            var extension = () => JsonSerializer.Deserialize<Capability>("""{"id":"urn:a","x":1,"x":2}""", options);
            extension.Should().Throw<JsonException>();

            var chain = () => JsonSerializer.Deserialize<Proof>("""{"capabilityChain":[{"id":"a","id":"b"}]}""", options);
            chain.Should().Throw<JsonException>();

            var context = () => JsonSerializer.Deserialize<Capability>("""{"@context":{"a":1,"a":2}}""", options);
            context.Should().Throw<JsonException>();
        }
    }

    // ─── Resolver contract ──────────────────────────────────────────────────

    private sealed class UnsupportedContext
    {
        public string Url { get; set; } = "https://example.com/ctx";
    }

    [Fact(DisplayName = "#154 — without reflection an unsupported @context CLR type fails naming the member, the type and the supported shapes")]
    public void UnsupportedContextType_WithoutReflection_Throws()
    {
        var capability = WithContext(new UnsupportedContext());

        var act = () => JsonSerializer.Serialize(capability, ContextOnly);
        act.Should().Throw<NotSupportedException>()
            .Which.Message.Should().Contain("Capability.Context")
            .And.Contain(typeof(UnsupportedContext).FullName)
            .And.Contain("string, a JsonElement, a JsonNode");

        // The shared options keep the reflection fallback in this JIT process (D1), so today's behaviour holds.
        JsonSerializer.Serialize(capability, Shared)
            .Should().Be($$"""{"id":"{{RootId}}","@context":{"Url":"https://example.com/ctx"},"controller":"did:key:z6MkAlice","invocationTarget":"https://example.com/docs"}""");
        JsonSerializer.Serialize(capability, Shared).Should().Be(JsonSerializer.Serialize(capability, Legacy));

        var proof = new Proof { CapabilityChain = new object[] { RootId, new UnsupportedContext() } };
        var chain = () => JsonSerializer.Serialize(proof, ContextOnly);
        chain.Should().Throw<NotSupportedException>().Which.Message.Should().Contain("Proof.CapabilityChain");
    }

    [Fact(DisplayName = "#154 — ZcapJsonOptions.Default resolves zcap's types through the generated context and keeps the reflection fallback when enabled")]
    public void SharedOptions_ResolveThroughGeneratedContext()
    {
        JsonSerializer.IsReflectionEnabledByDefault.Should().BeTrue("the test process is a JIT application");

        foreach (var type in new[]
                 {
                     typeof(Capability), typeof(Proof), typeof(ProofSet), typeof(ControllerSet), typeof(Invocation),
                     typeof(InvocationCapability), typeof(RevocationRequest), typeof(RevocationRecord), typeof(RevocationScope),
                     typeof(JsonElement), typeof(JsonElement[]), typeof(IEnumerable<JsonElement>), typeof(JsonNode), typeof(JsonObject),
                     typeof(JsonArray), typeof(Dictionary<string, JsonElement>), typeof(Dictionary<string, object>),
                     typeof(Dictionary<string, string>), typeof(IDictionary<string, string>), typeof(IReadOnlyDictionary<string, string>),
                     typeof(string), typeof(string[]), typeof(List<string>), typeof(IReadOnlyList<string>), typeof(IEnumerable<string>),
                     typeof(object), typeof(object[]), typeof(List<object>),
                 })
        {
            Shared.GetTypeInfo(type).OriginatingResolver.Should().BeSameAs(ZcapJsonContext.Default, $"{type} must not depend on reflection");
            ZcapJsonContext.Default.GetTypeInfo(type).Should().NotBeNull();
        }

        Shared.GetTypeInfo(typeof(UnsupportedContext)).OriginatingResolver.Should().BeOfType<DefaultJsonTypeInfoResolver>();
        ZcapJsonContext.Default.GetTypeInfo(typeof(UnsupportedContext)).Should().BeNull();

        // The typed accessor binds to the shared options, so the relaxed encoder applies; the context's own
        // typeinfos bind to the context's options and the default encoder, which would change signed bytes.
        ZcapJsonOptions.TypeInfo<Capability>().Options.Should().BeSameAs(Shared);
        var relaxed = WithContext("+<>&'");
        JsonSerializer.Serialize(relaxed, ZcapJsonOptions.TypeInfo<Capability>()).Should().Contain("\"@context\":\"+<>&'\"");
        JsonSerializer.Serialize(relaxed, ZcapJsonContext.Default.Capability).Should().Contain("\"@context\":\"\\u002B\\u003C\\u003E\\u0026\\u0027\"");

        // A copy (CaveatCodec makes one) keeps the resolver and the settings.
        var copy = new JsonSerializerOptions(Shared);
        copy.TypeInfoResolver.Should().BeSameAs(Shared.TypeInfoResolver);
        copy.Encoder.Should().BeSameAs(JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
        copy.AllowDuplicateProperties.Should().BeFalse();
        copy.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);
    }

    [Fact(DisplayName = "#154 — the generated context's own options mirror the shared settings the attribute can express")]
    public void GeneratedContextOptions_MirrorSharedSettings()
    {
        var generated = ZcapJsonContext.Default.Options;
        generated.WriteIndented.Should().BeFalse();
        generated.PropertyNamingPolicy.Should().BeNull();
        generated.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);
        generated.AllowDuplicateProperties.Should().BeFalse();
    }
}
