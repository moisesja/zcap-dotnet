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
/// authorization, route/body binding, and rejection of unsupported caveats after HTTP deserialization.
/// Capability-id cases (Issue #155) run on both the in-memory TestServer and real Kestrel: only Kestrel
/// populates <c>IHttpRequestFeature.RawTarget</c>, so the two hosts exercise different id-recovery paths.
/// </summary>
public sealed class RevocationEndpointIntegrationTests
    : IClassFixture<RevocationEndpointIntegrationTests.RevocationApiFactory>,
      IClassFixture<RevocationEndpointIntegrationTests.KestrelRevocationApiFactory>
{
    private readonly RevocationApiFactory _factory;
    private readonly KestrelRevocationApiFactory _kestrel;

    public RevocationEndpointIntegrationTests(RevocationApiFactory factory, KestrelRevocationApiFactory kestrel)
    {
        _factory = factory;
        _kestrel = kestrel;
    }

    public enum Host
    {
        TestServer,
        Kestrel
    }

    /// <summary>Boots the demo host but swaps the SQLite store for an in-memory one (no DB file).</summary>
    public class RevocationApiFactory : WebApplicationFactory<Program>
    {
        /// <summary>
        /// Server-side root resolver: a spec-exact delegation chain references the root by id only, so
        /// the verifier must resolve it to authorize a delegated revocation (Issue #50), and a root
        /// revocation is authorized against the resolved root (Issue #155). Tests register the root
        /// they create here before posting. Shared across the class (tests run sequentially).
        /// </summary>
        public InMemoryRootCapabilityResolver RootResolver { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRevocationStore>();
                services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
                services.RemoveAll<IRootCapabilityResolver>();
                services.AddSingleton<IRootCapabilityResolver>(RootResolver);
            });
        }
    }

    /// <summary>
    /// The same host on real Kestrel. The TestServer leaves <c>IHttpRequestFeature.RawTarget</c> empty,
    /// so only Kestrel exercises raw-target id recovery; the TestServer exercises the route-value fallback.
    /// </summary>
    public sealed class KestrelRevocationApiFactory : RevocationApiFactory
    {
        public KestrelRevocationApiFactory() => UseKestrel();
    }

    private RevocationApiFactory Factory(Host host) => host == Host.Kestrel ? _kestrel : _factory;

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
        _factory.RootResolver.Register(root); // server resolves the root a spec-exact chain references by id
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // The root controller is an up-chain delegator and signs the revocation.
        var signed = await client.Signing.SignRevocationAsync(
            delegated.Id, rootDid, delegated.InvocationTarget, reason: "rotation");

        var response = await PostRevocationAsync(http, delegated.Id, delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var status = await GetStatusAsync(http, delegated.Id);
        status.IsRevoked.Should().BeTrue();
        // The anonymous status endpoint intentionally returns only {capabilityId, isRevoked}; it no
        // longer leaks operational metadata (RevokedBy/Reason/RootCapabilityId) to unauthenticated callers.
        status.RevokedBy.Should().BeNull();
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

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("[{\"type\":\"UsageCount\",\"maxUses\":1}]")]
    public async Task Post_UnsupportedCaveat_Returns403WithoutRecording(string caveat)
    {
        var http = _factory.CreateClient();
        var client = new Client();
        var owner = client.Did.GenerateDidKey();
        var root = await client.Capabilities.CreateRootCapabilityAsync(owner, "https://example.com/resource");
        _factory.RootResolver.Register(root);
        var leaf = await client.Capabilities.DelegateCapabilityAsync(
            root, client.Did.GenerateDidKey(), ["read"], DateTime.UtcNow.AddDays(1));
        var signed = await client.Signing.SignRevocationAsync(leaf.Id, owner, leaf.InvocationTarget);
        using var doc = JsonDocument.Parse(caveat);
        leaf.AdditionalProperties = new() { ["caveat"] = doc.RootElement.Clone() };

        (await PostRevocationAsync(http, leaf.Id, leaf, signed)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStatusAsync(http, leaf.Id)).IsRevoked.Should().BeFalse();

        leaf.AdditionalProperties.Remove("caveat");
        (await PostRevocationAsync(http, leaf.Id, leaf, signed)).StatusCode.Should().Be(HttpStatusCode.OK);
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
        _factory.RootResolver.Register(root); // server resolves the root a spec-exact chain references by id
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // Unknown capability → not revoked.
        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeFalse();

        var signed = await client.Signing.SignRevocationAsync(delegated.Id, childDid, delegated.InvocationTarget);
        (await PostRevocationAsync(http, delegated.Id, delegated, signed)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await GetStatusAsync(http, delegated.Id)).IsRevoked.Should().BeTrue();
    }

    // ----- Issue #155: the capability id must be decoded exactly once -----
    //
    // A root id is urn:zcap:root: + encodeURIComponent(target), so it already carries percent-escapes
    // and reaches the server encoded twice. ASP.NET Core decodes the path once (keeping %2F) before
    // routing; decoding the route value again turned every root id into a different id.

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Post_RootControllerRevokesRoot_Returns200AndStatusReflectsIt(Host host)
    {
        var http = Factory(host).CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var root = await client.Capabilities.CreateRootCapabilityAsync(rootDid, $"https://example.com/root-revoke/{host}");
        Factory(host).RootResolver.Register(root);
        root.Id.Should().Contain("%3A%2F%2F", "a spec root id carries one level of encoding before the URL adds another");

        var signed = await client.Signing.SignRevocationAsync(root.Id, rootDid, root.InvocationTarget);
        var response = await PostRevocationAsync(http, root.Id, root, signed);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var status = await GetStatusAsync(http, root.Id);
        status.IsRevoked.Should().BeTrue();
        status.CapabilityId.Should().Be(root.Id);
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Get_UnrevokedRoot_EchoesExactIdAndIsNotRevoked(Host host)
    {
        var http = Factory(host).CreateClient();
        var client = new Client();
        var root = await client.Capabilities.CreateRootCapabilityAsync(
            client.Did.GenerateDidKey(), $"https://example.com/root-unrevoked/{host}");

        var status = await GetStatusAsync(http, root.Id);

        status.IsRevoked.Should().BeFalse();
        status.CapabilityId.Should().Be(root.Id);
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Get_RootRevokedInProcess_ReportsRevoked(Host host)
    {
        // The fail-open case from the issue: the record is stored under the true id by any path other
        // than this endpoint (in process, another node sharing the store), and GET must find it.
        var http = Factory(host).CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var root = await client.Capabilities.CreateRootCapabilityAsync(rootDid, $"https://example.com/root-in-process/{host}");
        Factory(host).RootResolver.Register(root);

        var verifier = Factory(host).Services.GetRequiredService<IVerificationService>();
        var signed = await client.Signing.SignRevocationAsync(root.Id, rootDid, root.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(root, signed)).Should().BeTrue();

        var status = await GetStatusAsync(http, root.Id);
        status.IsRevoked.Should().BeTrue();
        status.CapabilityId.Should().Be(root.Id);
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Get_IdWithLiteralPercentEscape_EchoesExactlyAndDoesNotCollide(Host host)
    {
        var http = Factory(host).CreateClient();
        var id = $"urn:example:{host}:a%41b";
        await RevokeDirectlyInStoreAsync(host, id);

        var status = await GetStatusAsync(http, id);
        status.IsRevoked.Should().BeTrue();
        status.CapabilityId.Should().Be(id);

        // The double-decoded form is a different id and must not share the record.
        var other = await GetStatusAsync(http, $"urn:example:{host}:aAb");
        other.IsRevoked.Should().BeFalse();
        other.CapabilityId.Should().Be($"urn:example:{host}:aAb");
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Get_RootFormId_UnaffectedByRevocationOfItsDecodedTwin(Host host)
    {
        // urn:zcap:root:https%3A%2F%2F… and urn:zcap:root:https://… are distinct ids. Before the fix both
        // were looked up under the second.
        var http = Factory(host).CreateClient();
        var decodedTwin = $"urn:zcap:root:https://collide-{host}.example";
        var rootForm = $"urn:zcap:root:https%3A%2F%2Fcollide-{host}.example";
        await RevokeDirectlyInStoreAsync(host, decodedTwin);

        var status = await GetStatusAsync(http, rootForm);

        status.IsRevoked.Should().BeFalse();
        status.CapabilityId.Should().Be(rootForm);
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Post_RootRouteWithDelegatedBody_Returns400(Host host)
    {
        var http = Factory(host).CreateClient();
        var client = new Client();
        var rootDid = client.Did.GenerateDidKey();
        var root = await client.Capabilities.CreateRootCapabilityAsync(rootDid, $"https://example.com/root-mismatch/{host}");
        var delegated = await client.Capabilities.DelegateCapabilityAsync(
            root, client.Did.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(5));
        var signed = await client.Signing.SignRevocationAsync(delegated.Id, rootDid, delegated.InvocationTarget);

        var response = await PostRevocationAsync(http, root.Id, delegated, signed);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Post_ImpostorRootWithForeignController_Returns403AndDoesNotRevoke(Host host)
    {
        // Root revocation over HTTP must authorize against the server's trusted root, never the body's
        // copy: a root-only chain has no delegation proof, so a body root naming the attacker as
        // controller would otherwise let anyone revoke a known root id.
        var http = Factory(host).CreateClient();
        var client = new Client();
        var ownerDid = client.Did.GenerateDidKey();
        var malloryDid = client.Did.GenerateDidKey();
        var root = await client.Capabilities.CreateRootCapabilityAsync(ownerDid, $"https://example.com/root-impostor/{host}");
        Factory(host).RootResolver.Register(root);

        var impostor = new Capability
        {
            Context = root.Context,
            Id = root.Id,
            Controller = malloryDid,
            InvocationTarget = root.InvocationTarget
        };
        var signed = await client.Signing.SignRevocationAsync(impostor.Id, malloryDid, impostor.InvocationTarget);

        var response = await PostRevocationAsync(http, root.Id, impostor, signed);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStatusAsync(http, root.Id)).IsRevoked.Should().BeFalse();
    }

    [Theory]
    [InlineData(Host.TestServer)]
    [InlineData(Host.Kestrel)]
    public async Task Post_DelegatedShapedBodyBorrowingRootId_Returns403AndDoesNotRevoke(Host host)
    {
        // Root-ness is decided by the server's resolver, not by the body: an attacker who controls a
        // registered root presents the victim root's id as a validly signed delegation under their own
        // chain. The victim's id must still be anchored to the victim's root.
        var http = Factory(host).CreateClient();
        var client = new Client();
        var attackerDid = client.Did.GenerateDidKey();
        var victimDid = client.Did.GenerateDidKey();
        var attackerRoot = await client.Capabilities.CreateRootCapabilityAsync(attackerDid, $"https://attacker.example/{host}");
        var victimRoot = await client.Capabilities.CreateRootCapabilityAsync(victimDid, $"https://victim.example/{host}");
        Factory(host).RootResolver.Register(attackerRoot);
        Factory(host).RootResolver.Register(victimRoot);

        var forged = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = victimRoot.Id,
            Controller = attackerDid,
            InvocationTarget = attackerRoot.InvocationTarget,
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1)),
            ParentCapability = attackerRoot.Id
        };
        forged.Proof = await client.Signing.SignCapabilityAsync(
            forged, attackerDid, "capabilityDelegation", new object[] { attackerRoot.Id });
        var signed = await client.Signing.SignRevocationAsync(forged.Id, attackerDid, forged.InvocationTarget);

        var response = await PostRevocationAsync(http, victimRoot.Id, forged, signed);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStatusAsync(http, victimRoot.Id)).IsRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task Get_IdContainingSlash_OnKestrel_EchoesExactlyWhateverTheClientEncoding()
    {
        var http = _kestrel.CreateClient();
        const string id = "https://issuer.example/zcaps/42";
        await RevokeDirectlyInStoreAsync(Host.Kestrel, id);

        // encodeURIComponent form, raw slashes, and lowercase escapes all name the same id.
        foreach (var path in new[]
                 {
                     "/zcaps/revocations/" + Uri.EscapeDataString(id),
                     "/zcaps/revocations/https://issuer.example/zcaps/42",
                     "/zcaps/revocations/https%3a%2f%2fissuer.example%2fzcaps%2f42",
                 })
        {
            var status = await GetStatusByPathAsync(http, path);
            status.IsRevoked.Should().BeTrue(path);
            status.CapabilityId.Should().Be(id, path);
        }
    }

    [Fact]
    public async Task Get_RootFormAndDecodedTwin_OnKestrel_KeepDistinctStatus()
    {
        var http = _kestrel.CreateClient();
        const string rootForm = "urn:zcap:root:https%3A%2F%2Fcollide-both.example";
        const string decodedTwin = "urn:zcap:root:https://collide-both.example";
        await RevokeDirectlyInStoreAsync(Host.Kestrel, rootForm);

        var twin = await GetStatusAsync(http, decodedTwin);
        twin.IsRevoked.Should().BeFalse();
        twin.CapabilityId.Should().Be(decodedTwin);

        var root = await GetStatusAsync(http, rootForm);
        root.IsRevoked.Should().BeTrue();
        root.CapabilityId.Should().Be(rootForm);
    }

    [Fact]
    public async Task Post_IdContainingSlash_OnKestrel_PassesRouteBodyCheck()
    {
        var http = _kestrel.CreateClient();
        const string id = "https://issuer.example/zcaps/77";
        var capability = new Capability
        {
            Id = id,
            Controller = "did:example:owner",
            InvocationTarget = "https://issuer.example/resource"
        };

        // Unsigned request: the route/body id check runs before verification, so passing it yields 403
        // (verification fails), not 400.
        var response = await PostRevocationAsync(http, id, capability, new Invocation());

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Get_WithQueryString_OnKestrel_IgnoresTheQuery()
    {
        var http = _kestrel.CreateClient();
        var client = new Client();
        var root = await client.Capabilities.CreateRootCapabilityAsync(
            client.Did.GenerateDidKey(), "https://example.com/root-query");
        await RevokeDirectlyInStoreAsync(Host.Kestrel, root.Id);

        var status = await GetStatusByPathAsync(http, "/zcaps/revocations/" + Uri.EscapeDataString(root.Id) + "?trace=1");

        status.IsRevoked.Should().BeTrue();
        status.CapabilityId.Should().Be(root.Id);
    }

    [Fact]
    public async Task Get_IdContainingSlash_OnTestServer_WorksWithRawSlashes()
    {
        // Without a raw target the endpoint uses the route value, in which an encoded '/' stays %2F; raw
        // slashes pass through unchanged, so such ids remain addressable on that host.
        var http = _factory.CreateClient();
        const string id = "https://issuer.example/zcaps/43";
        await RevokeDirectlyInStoreAsync(Host.TestServer, id);

        var status = await GetStatusByPathAsync(http, "/zcaps/revocations/https://issuer.example/zcaps/43");

        status.IsRevoked.Should().BeTrue();
        status.CapabilityId.Should().Be(id);
    }

    /// <summary>Records a revocation under the true id, as any in-process or shared-store path would.</summary>
    private Task RevokeDirectlyInStoreAsync(Host host, string capabilityId)
        => Factory(host).Services.GetRequiredService<IRevocationStore>().UpsertAsync(new RevocationRecord
        {
            CapabilityId = capabilityId,
            RevokedBy = "did:example:owner",
            RevokedAt = DateTime.UtcNow
        });

    private static async Task<HttpResponseMessage> PostRevocationAsync(
        HttpClient client, string routeCapabilityId, Capability capability, Invocation signedRevocation)
    {
        var payload = new SignedRevocationHttpRequest { Capability = capability, SignedRevocation = signedRevocation };
        var json = JsonSerializer.Serialize(payload, ZcapJsonOptions.Default);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await client.PostAsync($"/zcaps/revocations/{Uri.EscapeDataString(routeCapabilityId)}", content);
    }

    private static Task<RevocationStatusHttpResponse> GetStatusAsync(HttpClient client, string capabilityId)
        => GetStatusByPathAsync(client, $"/zcaps/revocations/{Uri.EscapeDataString(capabilityId)}");

    private static async Task<RevocationStatusHttpResponse> GetStatusByPathAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<RevocationStatusHttpResponse>(
            json, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }
}
