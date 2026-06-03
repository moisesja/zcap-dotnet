using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// End-to-end HTTP coverage for the signed revocation endpoint, run against the demo host via
/// <see cref="WebApplicationFactory{TEntryPoint}"/>. Proves authentication (proof-of-possession),
/// authorization, route/body binding, and — critically — that an embedded capability carrying a
/// typed caveat round-trips through the endpoint's JSON deserialization without canonical drift.
/// </summary>
public sealed class RevocationEndpointIntegrationTests : IClassFixture<RevocationEndpointIntegrationTests.RevocationApiFactory>
{
    private readonly RevocationApiFactory _factory;

    public RevocationEndpointIntegrationTests(RevocationApiFactory factory) => _factory = factory;

    /// <summary>Boots the demo host but swaps the SQLite store for an in-memory one (no DB file).</summary>
    public sealed class RevocationApiFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRevocationStore>();
                services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
            });
        }
    }

    /// <summary>Client-side signing stack (holds private keys); the server only verifies.</summary>
    private sealed class Client
    {
        public InMemoryDidProvider Did { get; } = new();
        public SigningService Signing { get; }
        public CapabilityService Capabilities { get; }

        public Client()
        {
            Signing = new SigningService(Did, Did);
            Capabilities = new CapabilityService(Signing);
        }
    }

    [Fact]
    public async Task Post_ValidSignedRevocation_Returns200AndRevokes()
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // The root controller is an up-chain delegator and signs the revocation.
        var signed = await client.Signing.SignRevocationAsync(
            delegated.Id, rootDid, delegated.InvocationTarget, reason: "rotation");

        var response = await PostRevocationAsync(http, delegated.Id, delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var status = await GetStatusAsync(http, delegated.Id);
        status.IsRevoked.Should().BeTrue();
        status.RevokedBy.Should().Be(rootDid);
    }

    [Fact]
    public async Task Post_UnauthorizedSigner_Returns403AndDoesNotRevoke()
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();
        var malloryDid = client.Did.GenerateDidKey(); // a real, resolvable key — just not in the chain

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var signed = await client.Signing.SignRevocationAsync(delegated.Id, malloryDid, delegated.InvocationTarget);

        var response = await PostRevocationAsync(http, delegated.Id, delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task Post_ForgedForeignKey_Returns403AndDoesNotRevoke()
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();
        var malloryDid = client.Did.GenerateDidKey();

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // Mallory signs with her own key, then claims the root controller's verification method.
        var forged = await client.Signing.SignRevocationAsync(delegated.Id, malloryDid, delegated.InvocationTarget);
        forged.Proof!.VerificationMethod = await client.Did.GetVerificationMethodAsync(rootDid);

        var response = await PostRevocationAsync(http, delegated.Id, delegated, forged);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task Post_RouteBodyIdMismatch_Returns400()
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var signed = await client.Signing.SignRevocationAsync(delegated.Id, rootDid, delegated.InvocationTarget);

        var response = await PostRevocationAsync(http, "urn:uuid:some-other-id", delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Post_CapabilityWithTypedCaveat_RoundTripsAndRevokes()
    {
        // Guards the endpoint's JSON-converter wiring: an embedded capability carrying a typed
        // caveat must deserialize with its derived fields intact, otherwise canonical bytes drift
        // and the (legitimate) delegation proof fails verification — looking like an auth failure.
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5),
            caveats: new Caveat[] { new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(3) } });

        var signed = await client.Signing.SignRevocationAsync(delegated.Id, rootDid, delegated.InvocationTarget);

        var response = await PostRevocationAsync(http, delegated.Id, delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task Get_Status_ReflectsRevocation()
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var childDid = client.Did.GenerateDidKey();

        var root = await client.Capabilities.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // Unknown capability → not revoked.
        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeFalse();

        var signed = await client.Signing.SignRevocationAsync(delegated.Id, childDid, delegated.InvocationTarget);
        (await PostRevocationAsync(http, delegated.Id, delegated, signed)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeTrue();
    }

    private static async Task<HttpResponseMessage> PostRevocationAsync(
        HttpClient client, string routeCapabilityId, Capability capability, Invocation signedRevocation)
    {
        var payload = new SignedRevocationHttpRequest { Capability = capability, SignedRevocation = signedRevocation };
        var json = JsonSerializer.Serialize(payload, ZcapJsonOptions.Default);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await client.PostAsync($"/zcaps/revocations/{Uri.EscapeDataString(routeCapabilityId)}", content);
    }

    private static async Task<RevocationStatusHttpResponse> GetStatusAsync(HttpClient client, string capabilityId)
    {
        var response = await client.GetAsync($"/zcaps/revocations/{Uri.EscapeDataString(capabilityId)}");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<RevocationStatusHttpResponse>(
            json, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }
}
