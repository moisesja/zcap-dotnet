using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Xunit;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// The adapter's source-generated serializer metadata (#154): Core's models resolve through Core's
/// generated context (the single source of truth for the signed wire shape) and only the two HTTP
/// contract types through <see cref="ZcapAspNetCoreJsonContext"/>; the endpoint round-trips through
/// generated metadata alone, as it must under native AOT; and malformed bodies, including duplicate
/// keys at every nesting the contract reaches, are a 400, never a 500 (lesson 2026-11-10).
/// </summary>
public sealed class SourceGeneratedJsonTests
    : IClassFixture<RevocationEndpointIntegrationTests.RevocationApiFactory>
{
    private readonly RevocationEndpointIntegrationTests.RevocationApiFactory _factory;

    public SourceGeneratedJsonTests(RevocationEndpointIntegrationTests.RevocationApiFactory factory)
        => _factory = factory;

    /// <summary>
    /// Core's generated context, which is internal to Core: the resolver <see cref="ZcapJsonOptions.Default"/>
    /// reports as the origin of a Core model's metadata.
    /// </summary>
    private static IJsonTypeInfoResolver CoreContext
        => ZcapJsonOptions.Default.GetTypeInfo(typeof(Capability)).OriginatingResolver!;

    /// <summary>
    /// The shared settings with generated metadata only (no reflection resolver), which is what
    /// <see cref="ZcapJsonOptions.Default"/> degrades to where reflection-based serialization is disabled.
    /// </summary>
    private static JsonSerializerOptions ContextOnlyOptions() => new(ZcapJsonOptions.Default)
    {
        TypeInfoResolver = JsonTypeInfoResolver.Combine(CoreContext, ZcapAspNetCoreJsonContext.Default)
    };

    [Fact]
    public void CoreContext_IsCoresGeneratedContext_NotReflection()
    {
        CoreContext.GetType().FullName.Should().Be("ZcapLd.Core.Cryptography.ZcapJsonContext");
        CoreContext.Should().BeAssignableTo<JsonSerializerContext>();
    }

    [Theory]
    [InlineData(typeof(Capability))]
    [InlineData(typeof(Proof))]
    [InlineData(typeof(ProofSet))]
    [InlineData(typeof(ControllerSet))]
    [InlineData(typeof(Invocation))]
    [InlineData(typeof(InvocationCapability))]
    [InlineData(typeof(RevocationRequest))]
    public void AdapterOptions_ResolveCoreModelsThroughCoresContext(Type type)
    {
        var info = ZcapAspNetCoreJsonOptions.Default.GetTypeInfo(type);

        info.OriginatingResolver.Should().BeSameAs(CoreContext,
            "the adapter's context also carries metadata for the embedded Core models, but Core's resolver is first");
        info.OriginatingResolver.Should().NotBeSameAs(ZcapAspNetCoreJsonContext.Default);
    }

    [Theory]
    [InlineData(typeof(SignedRevocationHttpRequest))]
    [InlineData(typeof(RevocationStatusHttpResponse))]
    public void AdapterOptions_ResolveContractTypesThroughTheAdaptersContext(Type type)
    {
        ZcapAspNetCoreJsonOptions.Default.GetTypeInfo(type).OriginatingResolver
            .Should().BeSameAs(ZcapAspNetCoreJsonContext.Default);
    }

    [Fact]
    public void AdapterOptions_ChainIsCoreContextThenAdapterContextThenCoresRemainder()
    {
        var chain = ZcapAspNetCoreJsonOptions.Default.TypeInfoResolverChain;
        var core = ZcapJsonOptions.Default.TypeInfoResolverChain;

        chain[0].Should().BeSameAs(CoreContext);
        chain[1].Should().BeSameAs(ZcapAspNetCoreJsonContext.Default);
        // Whatever Core combines after its context (the reflection resolver in a JIT process, nothing
        // under native AOT) follows unchanged, so a consumer type still resolves as it does with the
        // shared options, and the adapter's context is consulted before it in both modes.
        chain.Skip(2).Should().Equal(core.Skip(1));
        chain.Should().HaveCount(core.Count + 1);
        core[0].Should().BeSameAs(CoreContext);
    }

    [Fact]
    public void AdapterOptions_CopyTheSharedSettingsAndAreReadOnly()
    {
        var options = ZcapAspNetCoreJsonOptions.Default;

        options.IsReadOnly.Should().BeTrue();
        options.Encoder.Should().BeSameAs(ZcapJsonOptions.Default.Encoder);
        options.AllowDuplicateProperties.Should().BeFalse();
        options.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.WhenWritingNull);
        options.WriteIndented.Should().BeFalse();
        options.PropertyNamingPolicy.Should().BeNull();
        ZcapAspNetCoreJsonOptions.Request.Options.Should().BeSameAs(options);
        ZcapAspNetCoreJsonOptions.Response.Options.Should().BeSameAs(options);
    }

    [Fact]
    public void ContextOnlyOptions_SerializeTheRequestByteIdenticallyToTheSharedOptions()
    {
        var did = new InMemoryDidProvider();
        var rootDid = did.GenerateDidKey();
        var payload = new SignedRevocationHttpRequest
        {
            Capability = new Capability
            {
                Id = "urn:uuid:7b1c2d3e-0000-4000-8000-000000000001",
                Controller = new[] { rootDid, "did:example:other" },
                InvocationTarget = "https://example.com/resource?x=a+b&y=<c>",
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["note"] = JsonDocument.Parse("{\"k\":[1,\"it's\"]}").RootElement
                }
            },
            SignedRevocation = new Invocation { Id = "urn:uuid:7b1c2d3e-0000-4000-8000-000000000002" }
        };

        var generated = JsonSerializer.Serialize(payload, ContextOnlyOptions());
        var shared = JsonSerializer.Serialize(payload, ZcapJsonOptions.Default);

        generated.Should().Be(shared);
        generated.Should().Contain("a+b&y=<c>", "the relaxed encoder is copied, not the context's default");
    }

    [Fact]
    public async Task Post_SignedRevocation_RoundTripsThroughGeneratedMetadataOnly()
    {
        var http = _factory.CreateClient();
        var did = new InMemoryDidProvider();
        var signing = new SigningService(did, did);
        var capabilities = new CapabilityService(signing);
        var rootDid = did.GenerateDidKey();
        var childDid = did.GenerateDidKey();

        var root = await capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/source-generated", new[] { "read", "write" });
        _factory.RootResolver.Register(root);
        var delegated = await capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        var signed = await signing.SignRevocationAsync(
            delegated.Id, rootDid, delegated.InvocationTarget, reason: "rotation");

        var options = ContextOnlyOptions();
        var body = JsonSerializer.Serialize(
            new SignedRevocationHttpRequest { Capability = delegated, SignedRevocation = signed }, options);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var response = await http.PostAsync($"/zcaps/revocations/{Uri.EscapeDataString(delegated.Id)}", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        var json = await response.Content.ReadAsStringAsync();
        // Written through the adapter's options: null members omitted, no indentation.
        json.Should().Be($"{{\"capabilityId\":\"{delegated.Id}\",\"isRevoked\":true}}");
        var status = JsonSerializer.Deserialize<RevocationStatusHttpResponse>(json, options)!;
        status.CapabilityId.Should().Be(delegated.Id);
        status.IsRevoked.Should().BeTrue();
    }

    /// <summary>
    /// Raw strings on purpose: a <c>JsonObject</c> cannot represent a duplicate key, so a body built from
    /// the DOM could never exercise the rejection. Every nesting the contract reaches has its own
    /// converter (extension data, the <c>@context</c> union, the proof set, the chain union, the
    /// embedded invocation), and each must surface as a 400.
    /// </summary>
    [Theory]
    [InlineData("top level", """{"capability":{"id":"urn:uuid:a"},"capability":{"id":"urn:uuid:b"}}""")]
    [InlineData("capability member", """{"capability":{"id":"urn:uuid:a","id":"urn:uuid:b"},"signedRevocation":{}}""")]
    [InlineData("capability extension data", """{"capability":{"id":"urn:uuid:a","x":1,"x":2},"signedRevocation":{}}""")]
    [InlineData("capability @context", """{"capability":{"@context":{"a":1,"a":2},"id":"urn:uuid:a"},"signedRevocation":{}}""")]
    [InlineData("proof", """{"capability":{"id":"urn:uuid:a","proof":{"type":"x","type":"y"}},"signedRevocation":{}}""")]
    [InlineData("proof set member", """{"capability":{"id":"urn:uuid:a","proof":[{"type":"x","type":"y"}]},"signedRevocation":{}}""")]
    [InlineData("capability chain entry", """{"capability":{"id":"urn:uuid:a","proof":{"capabilityChain":["urn:r",{"id":"x","id":"y"}]}},"signedRevocation":{}}""")]
    [InlineData("signed revocation member", """{"capability":{"id":"urn:uuid:a"},"signedRevocation":{"id":"urn:uuid:i","id":"urn:uuid:j"}}""")]
    [InlineData("embedded invocation capability", """{"capability":{"id":"urn:uuid:a"},"signedRevocation":{"capability":{"id":"x","id":"y"}}}""")]
    [InlineData("signed revocation proof", """{"capability":{"id":"urn:uuid:a"},"signedRevocation":{"proof":{"nonce":"1","nonce":"2"}}}""")]
    public async Task Post_DuplicateJsonProperty_Returns400NotA500(string nesting, string body)
    {
        var http = _factory.CreateClient();
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var response = await http.PostAsync("/zcaps/revocations/urn:uuid:a", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            $"a duplicate key at the {nesting} is malformed input, rejected before any verification");
        // The message as a JSON string, the wire shape TypedResults.BadRequest(string) has always written.
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        (await response.Content.ReadAsStringAsync()).Should().Be("\"Request body is not valid JSON.\"");
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{"capability":"urn:uuid:a","signedRevocation":{}}""")]
    [InlineData("""{"capability":{"id":"urn:uuid:a"},"signedRevocation":{"capability":1}}""")]
    public async Task Post_MalformedBody_Returns400NotA500(string body)
    {
        var http = _factory.CreateClient();
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var response = await http.PostAsync("/zcaps/revocations/urn:uuid:a", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        (await response.Content.ReadAsStringAsync()).Should().StartWith("\"");
    }
}
