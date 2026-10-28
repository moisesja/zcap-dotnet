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
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// The caveat extension profile (#157) through the DI surface and the signed revocation endpoint:
/// <c>AddZcapCaveatType</c> enables it for signing, delegation and verification, and
/// <c>AddZcapCaveatHandler</c> supplies the resource's enforcement.
/// </summary>
public sealed class CaveatDependencyInjectionTests : IClassFixture<CaveatDependencyInjectionTests.CaveatApiFactory>
{
    private readonly CaveatApiFactory _factory;

    public CaveatDependencyInjectionTests(CaveatApiFactory factory) => _factory = factory;

    /// <summary>The demo host with EpsilonBudget registered and an in-memory store.</summary>
    public sealed class CaveatApiFactory : WebApplicationFactory<Program>
    {
        public InMemoryRootCapabilityResolver RootResolver { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
            => builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRevocationStore>();
                services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
                services.RemoveAll<IRootCapabilityResolver>();
                services.AddSingleton<IRootCapabilityResolver>(RootResolver);
                services.AddZcapCaveatType<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);
            });
    }

    private static (ServiceProvider Provider, InMemoryDidProvider Keys, InMemoryEpsilonLedger Ledger) Build(bool withCaveats)
    {
        var keys = new InMemoryDidProvider();
        var ledger = new InMemoryEpsilonLedger();
        var services = new ServiceCollection();
        services.AddZcapServices();
        services.AddZcapDidResolver(_ => keys);
        services.AddZcapDidSigner(_ => keys);
        services.AddZcapRootCapabilityResolver(_ => keys);
        if (withCaveats)
        {
            services.AddZcapCaveatType<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);
            services.AddZcapCaveatType<RegionCaveat>(RegionCaveat.TypeName);
            services.AddZcapCaveatHandler(_ => ledger);
        }
        return (services.BuildServiceProvider(), keys, ledger);
    }

    [Fact(DisplayName = "DI: registered caveat types are issued, verified and enforced")]
    public async Task Di_IssuesVerifiesAndEnforces()
    {
        var (provider, keys, ledger) = Build(withCaveats: true);
        var capabilities = provider.GetRequiredService<ICapabilityService>();
        var signing = provider.GetRequiredService<ISigningService>();
        var verifier = provider.GetRequiredService<IVerificationService>();
        var owner = keys.GenerateDidKey();
        var agent = keys.GenerateDidKey();
        var root = keys.RegisterRoot(await capabilities.CreateRootCapabilityAsync(owner, "https://di.example/fhir"));
        var grant = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "query" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 1 } });
        async Task<VerificationOutcome> InvokeAsync()
        {
            var invocation = capabilities.CreateInvocation(grant, "query");
            invocation.Proof = await signing.SignInvocationAsync(invocation, agent);
            return (await verifier.VerifyInvocationDetailedAsync(invocation, grant)).Outcome;
        }

        (await InvokeAsync()).Should().Be(VerificationOutcome.Valid);
        (await InvokeAsync()).Should().Be(VerificationOutcome.CaveatNotSatisfied);
        ledger.Calls.Should().Be(2);
    }

    [Fact(DisplayName = "DI: a registered type without a handler is unsupported at invocation")]
    public async Task Di_MissingHandler_Unsupported()
    {
        var (provider, keys, _) = Build(withCaveats: true);
        var capabilities = provider.GetRequiredService<ICapabilityService>();
        var signing = provider.GetRequiredService<ISigningService>();
        var owner = keys.GenerateDidKey();
        var agent = keys.GenerateDidKey();
        var root = keys.RegisterRoot(await capabilities.CreateRootCapabilityAsync(owner, "https://di.example/region"));
        var grant = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "query" }, DateTime.UtcNow.AddHours(1),
            caveats: new Caveat[] { new RegionCaveat { Allowed = new[] { "us" } } });
        var invocation = capabilities.CreateInvocation(grant, "query");
        invocation.Proof = await signing.SignInvocationAsync(invocation, agent);

        (await provider.GetRequiredService<IVerificationService>().VerifyInvocationDetailedAsync(invocation, grant)).Outcome
            .Should().Be(VerificationOutcome.UnsupportedCaveat);
    }

    [Fact(DisplayName = "DI: without AddZcapCaveatType the services keep the standard profile")]
    public async Task Di_WithoutCaveatTypes_RejectsCaveats()
    {
        var (provider, keys, _) = Build(withCaveats: false);
        var capabilities = provider.GetRequiredService<ICapabilityService>();
        var root = keys.RegisterRoot(await capabilities.CreateRootCapabilityAsync(keys.GenerateDidKey(), "https://di.example/plain"));

        var act = () => capabilities.DelegateCapabilityAsync(root, keys.GenerateDidKey(), new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 1 } });

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact(DisplayName = "DI: the registry is frozen once the ZCAP services are resolved")]
    public void Di_RegistryFrozenAfterResolution()
    {
        var (provider, _, _) = Build(withCaveats: true);
        _ = provider.GetRequiredService<IVerificationService>();

        var act = () => provider.GetRequiredService<CaveatTypeRegistry>().Register<TagCaveat>(TagCaveat.TypeName);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact(DisplayName = "Endpoint: a caveat-bearing capability is revocable; a tampered one is refused")]
    public async Task Endpoint_RevokesCaveatBearingCapability()
    {
        var http = _factory.CreateClient();
        var keys = new InMemoryDidProvider();
        var registry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);
        var signing = new SigningService(keys, keys, registry);
        var capabilities = new CapabilityService(signing, registry);
        var owner = keys.GenerateDidKey();
        var root = _factory.RootResolver.Register(await capabilities.CreateRootCapabilityAsync(owner, "https://endpoint.example/fhir"));
        var grant = await capabilities.DelegateCapabilityAsync(root, keys.GenerateDidKey(), new[] { "query" },
            DateTime.UtcNow.AddHours(1), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 2 } });
        var raised = JsonSerializer.Deserialize<Capability>(
            JsonSerializer.Serialize(grant, ZcapJsonOptions.Default).Replace("\"maxEpsilon\":2,", "\"maxEpsilon\":20,"),
            ZcapJsonOptions.Default)!;

        var tampered = await PostAsync(http, raised, await signing.SignRevocationAsync(grant.Id, owner, grant.InvocationTarget));
        var genuine = await PostAsync(http, grant, await signing.SignRevocationAsync(grant.Id, owner, grant.InvocationTarget));

        tampered.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        genuine.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, Capability capability, Invocation signedRevocation)
    {
        var json = JsonSerializer.Serialize(
            new SignedRevocationHttpRequest { Capability = capability, SignedRevocation = signedRevocation }, ZcapJsonOptions.Default);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await client.PostAsync($"/zcaps/revocations/{Uri.EscapeDataString(capability.Id)}", content);
    }
}
