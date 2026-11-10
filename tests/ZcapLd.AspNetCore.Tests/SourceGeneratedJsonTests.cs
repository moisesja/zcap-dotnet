using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
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
        ZcapAspNetCoreJsonOptions.Response.Options.Should().BeSameAs(ZcapAspNetCoreJsonOptions.ResponseDefault);
    }

    /// <summary>
    /// 6.0.0 answered with <c>TypedResults.Ok</c> through the host's default <c>JsonOptions</c>: the
    /// relaxed encoder (ASP.NET Core's default), every member written including nulls. The response
    /// options copy the adapter's options and only lift the null omission (red-team F3).
    /// </summary>
    [Fact]
    public void ResponseOptions_CopyTheAdapterOptionsAndWriteNullMembers()
    {
        var options = ZcapAspNetCoreJsonOptions.ResponseDefault;

        options.Should().NotBeSameAs(ZcapAspNetCoreJsonOptions.Default);
        options.IsReadOnly.Should().BeTrue();
        options.DefaultIgnoreCondition.Should().Be(JsonIgnoreCondition.Never);
        options.Encoder.Should().BeSameAs(ZcapJsonOptions.Default.Encoder);
        options.TypeInfoResolverChain.Should().Equal(ZcapAspNetCoreJsonOptions.Default.TypeInfoResolverChain);
        options.GetTypeInfo(typeof(RevocationStatusHttpResponse)).OriginatingResolver
            .Should().BeSameAs(ZcapAspNetCoreJsonContext.Default);
    }

    /// <summary>
    /// The exact 6.0.0 body, captured by executing <c>TypedResults.Ok</c> against the 4f0cc8e demo host:
    /// <c>+&lt;&gt;&amp;'</c> and BMP non-ASCII unescaped, a supplementary-plane character as a UTF-16
    /// escape pair, every null member present.
    /// </summary>
    [Fact]
    public void ResponseOptions_WriteThe600BodyShapeAndEscaping()
    {
        var response = new RevocationStatusHttpResponse { CapabilityId = "urn:x:a+b<c>&'d ünï 😀", IsRevoked = true };

        var json = JsonSerializer.Serialize(response, ZcapAspNetCoreJsonOptions.Response);

        json.Should().Be(
            """{"capabilityId":"urn:x:a+b<c>&'d ünï \uD83D\uDE00","isRevoked":true,"rootCapabilityId":null,"revokedBy":null,"revokedAt":null,"expiresAt":null,"reason":null,"metadata":null}""");
    }

    /// <summary>
    /// The same over HTTP: a root id keeps <c>'()!~*</c> unencoded (<c>encodeURIComponent</c> leaves
    /// them), and 6.0.0 wrote them verbatim.
    /// </summary>
    [Fact]
    public async Task Post_RootRevocation_BodyIsThe600Shape()
    {
        var http = _factory.CreateClient();
        var did = new InMemoryDidProvider();
        var signing = new SigningService(did, did);
        var capabilities = new CapabilityService(signing);
        var rootDid = did.GenerateDidKey();
        var root = await capabilities.CreateRootCapabilityAsync(rootDid, "https://example.com/it's-(a)!~*");
        _factory.RootResolver.Register(root);
        var signed = await signing.SignRevocationAsync(root.Id, rootDid, root.InvocationTarget);
        var body = JsonSerializer.Serialize(
            new SignedRevocationHttpRequest { Capability = root, SignedRevocation = signed }, ContextOnlyOptions());
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var response = await http.PostAsync($"/zcaps/revocations/{Uri.EscapeDataString(root.Id)}", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        root.Id.Should().Be("urn:zcap:root:https%3A%2F%2Fexample.com%2Fit's-(a)!~*");
        (await response.Content.ReadAsStringAsync()).Should().Be(
            """{"capabilityId":"urn:zcap:root:https%3A%2F%2Fexample.com%2Fit's-(a)!~*","isRevoked":true,"rootCapabilityId":null,"revokedBy":null,"revokedAt":null,"expiresAt":null,"reason":null,"metadata":null}""");
    }

    /// <summary>
    /// The <c>RequestDelegate</c> mapping declares what the Delegate overload inferred (red-team F4):
    /// the accepted JSON body, no cookie-authentication redirect (a 401/403 stays a status code), and
    /// the three response types.
    /// </summary>
    [Fact]
    public void Endpoint_DeclaresAcceptsNoCookieRedirectAndProducesMetadata()
    {
        var endpoint = _factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(e => e.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName == "ZcapRevokeCapability");

        endpoint.RoutePattern.RawText.Should().Be("/zcaps/revocations/{*capabilityId}");
        endpoint.Metadata.GetMetadata<IDisableCookieRedirectMetadata>().Should().NotBeNull();
        var accepts = endpoint.Metadata.GetMetadata<IAcceptsMetadata>()!;
        accepts.RequestType.Should().Be(typeof(SignedRevocationHttpRequest));
        accepts.ContentTypes.Should().Equal("application/json");
        accepts.IsOptional.Should().BeFalse();
        endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>()
            .Select(m => (m.StatusCode, m.Type))
            .Should().Equal((200, typeof(RevocationStatusHttpResponse)), (400, typeof(string)), (403, null));
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
        // The 6.0.0 shape: every member, null ones included, no indentation (red-team F3; an earlier
        // revision of this test pinned the null-omitting body, which was the regression).
        json.Should().Be(
            $"{{\"capabilityId\":\"{delegated.Id}\",\"isRevoked\":true,\"rootCapabilityId\":null,\"revokedBy\":null," +
            "\"revokedAt\":null,\"expiresAt\":null,\"reason\":null,\"metadata\":null}");
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
