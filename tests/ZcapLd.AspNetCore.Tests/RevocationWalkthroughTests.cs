using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.RevocationEndpointsDemo;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// Runs the demo's <c>--walkthrough</c> (<see cref="RevocationWalkthrough"/>) against the demo host booted
/// by <see cref="WebApplicationFactory{TEntryPoint}"/>, and pins the <c>200 / 403 / 200 / 403 Revoked</c>
/// sequence the README promises (#166).
/// <para>
/// Unlike <see cref="RevocationEndpointIntegrationTests"/>, this class does <b>not</b> replace the demo's
/// <see cref="IRootCapabilityResolver"/>. That test's factory swaps in its own resolver and registers roots
/// through it, which is why #166's first finding went unnoticed: the demo shipped with an empty resolver
/// and nothing in the demo itself seeded it, so every delegated invocation and revocation was refused
/// while the test suite stayed green. Here the only replacement is the <see cref="IRevocationStore"/>
/// (so no SQLite file is written); the root reaches the verifier the way the demo provisions it, through
/// <see cref="RevocationWalkthrough.ProvisionAsync"/> and the host's own
/// <see cref="InMemoryRootCapabilityResolver"/>. The second test shows that without that provisioning
/// the same chain is refused at the first step.
/// </para>
/// Each test boots its own factory: the walkthrough registers its root in the host's resolver, so a shared
/// host would leak state between tests.
/// </summary>
public sealed class RevocationWalkthroughTests
{
    /// <summary>Boots the demo host as shipped, except for the revocation store (in-memory, no DB file).</summary>
    private sealed class DemoHostFactory : WebApplicationFactory<Program>
    {
        private readonly string? _environment;

        /// <param name="environment">The hosting environment; null keeps the factory default (Development).</param>
        public DemoHostFactory(string? environment = null) => _environment = environment;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            if (_environment is not null)
            {
                builder.UseEnvironment(_environment);
            }

            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRevocationStore>();
                services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
                // Deliberately no IRootCapabilityResolver replacement: see the class remarks.
            });
        }
    }

    [Fact]
    public async Task Walkthrough_ProvisionsItsRootAndShows_200_403_200_403Revoked()
    {
        using var factory = new DemoHostFactory();
        factory.Services.GetRequiredService<IHostEnvironment>().IsDevelopment()
            .Should().BeTrue("WebApplicationFactory boots the host in Development, where the 403 body carries the outcome");
        factory.Services.GetRequiredService<IRootCapabilityResolver>()
            .Should().BeOfType<InMemoryRootCapabilityResolver>("the test must run against the demo's own resolver");

        var output = new StringWriter();
        var provisioned = await RevocationWalkthrough.ProvisionAsync(factory.Services);
        var results = await RevocationWalkthrough.RunAsync(factory.CreateClient(), provisioned, output);

        results.Should().HaveCount(4);
        results.Select(r => r.ActualStatus).Should().Equal(
            HttpStatusCode.OK, HttpStatusCode.Forbidden, HttpStatusCode.OK, HttpStatusCode.Forbidden);
        RevocationWalkthrough.AllMatched(results).Should().BeTrue(Report(results));

        results[0].Path.Should().Be(DemoResource.ReportPath);
        results[1].Path.Should().Be(RevocationWalkthrough.RevocationPath(provisioned.Delegated));
        results[2].Path.Should().Be(results[1].Path);
        results[3].Path.Should().Be(DemoResource.ReportPath);

        // Step 2: the stranger's revocation is refused without a body (nothing to disclose, nothing recorded).
        results[1].ResponseBody.Should().BeEmpty();

        // Step 3: the owner's revocation is accepted and reported as recorded.
        using (var status = JsonDocument.Parse(results[2].ResponseBody))
        {
            status.RootElement.GetProperty("isRevoked").GetBoolean().Should().BeTrue();
            status.RootElement.GetProperty("capabilityId").GetString().Should().Be(provisioned.Delegated.Id);
        }

        // Step 4: the fresh invocation is refused as Revoked, and Development discloses that outcome.
        using (var denial = JsonDocument.Parse(results[3].ResponseBody))
        {
            denial.RootElement.GetProperty("outcome").GetString().Should().Be(nameof(VerificationOutcome.Revoked));
        }

        // The printed transcript names every step and its verdict.
        var printed = output.ToString();
        foreach (var step in results)
        {
            printed.Should().Contain(step.Name);
        }

        printed.Should().Contain("as expected (200)").And.Contain("as expected (403)").And.NotContain("UNEXPECTED");
    }

    [Fact]
    public async Task Walkthrough_WithoutProvisioningTheRoot_IsRefusedAtTheFirstStep()
    {
        // A fresh host: its resolver is empty because nothing ran ProvisionAsync. The same client-side chain
        // the walkthrough builds is then unverifiable, which is exactly what the shipped demo did before #166.
        using var factory = new DemoHostFactory();
        var http = factory.CreateClient();

        var keyring = new DemoKeyring();
        var signing = new SigningService(keyring, new DidKeyResolver());
        var capabilities = new CapabilityService(signing);
        var ownerDid = keyring.GenerateDidKey();
        var agentDid = keyring.GenerateDidKey();
        var root = await capabilities.CreateRootCapabilityAsync(ownerDid, DemoResource.ReportTarget, new[] { DemoResource.ReadAction });
        var delegated = await capabilities.DelegateCapabilityAsync(
            root, agentDid, new[] { DemoResource.ReadAction }, DateTime.UtcNow.AddDays(1));
        // NOT registered with the host's resolver.

        var invocation = await signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), DemoResource.ReadAction, DemoResource.ReportTarget, agentDid);
        using var content = new StringContent(invocation.ToJsonString(ZcapJsonOptions.Default), Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(DemoResource.ReportPath, content);
        var body = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        using var denial = JsonDocument.Parse(body);
        var outcome = denial.RootElement.GetProperty("outcome").GetString();
        outcome.Should().NotBe(nameof(VerificationOutcome.Revoked), "nothing was revoked; the root simply cannot be resolved");
        // An unobtainable root is a configuration gap on the verifier, not a proven-invalid capability, so
        // the library reports it as CouldNotVerify (pinned by VerificationResultTests
        // .ChainDetailed_DelegatedWithUnobtainableRoot_ReturnsCouldNotVerify). The walkthrough test above
        // runs the identical client stack with the root registered and gets 200, so registration is the
        // only difference.
        outcome.Should().Be(nameof(VerificationOutcome.CouldNotVerify),
            "the chain references the root by id and the host's empty resolver cannot obtain it");
    }

    // ----- Regression (PR #167 review): duplicate JSON properties are a 400, never a 500 -----
    //
    // ZcapJsonOptions.Default rejects duplicate properties, but when the target is a JsonObject the
    // rejection surfaces as ArgumentException (OrderedDictionary.Add inside JsonObjectConverter), not
    // JsonException. The protected endpoint caught only JsonException, so an unauthenticated body with a
    // repeated key produced an HTTP 500 (and, in Development, the exception page). The body must be built
    // from a string: a JsonObject cannot represent duplicate keys.

    [Theory]
    [InlineData("Development", "{\"id\":\"x\",\"id\":\"y\"}")]
    [InlineData("Development", "{\"proof\":{\"id\":\"x\",\"id\":\"y\"}}")]
    [InlineData("Production", "{\"id\":\"x\",\"id\":\"y\"}")]
    [InlineData("Production", "{\"proof\":{\"id\":\"x\",\"id\":\"y\"}}")]
    public async Task ReadReport_WithDuplicateJsonProperties_Returns400(string environment, string body)
    {
        using var factory = new DemoHostFactory(environment);
        factory.Services.GetRequiredService<IHostEnvironment>().EnvironmentName.Should().Be(environment);
        var http = factory.CreateClient();

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(DemoResource.ReportPath, content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "a duplicate property is malformed input, rejected before any verification, and must not become a 500");
        (await response.Content.ReadAsStringAsync()).Should().NotContain("Exception",
            "no exception detail may leak, in any environment");
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task ReadReport_WithMalformedBody_Returns400OrEmpty403ByEnvironment(string environment)
    {
        using var factory = new DemoHostFactory(environment);
        var http = factory.CreateClient();

        // Not an object at all: 400 everywhere.
        using var array = new StringContent("[1,2]", Encoding.UTF8, "application/json");
        (await http.PostAsync(DemoResource.ReportPath, array)).StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // A well-formed object that is not a valid invocation: 403, with the outcome only in Development.
        using var bogus = new StringContent("{\"id\":\"urn:x\"}", Encoding.UTF8, "application/json");
        using var denied = await http.PostAsync(DemoResource.ReportPath, bogus);
        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var deniedBody = await denied.Content.ReadAsStringAsync();
        if (environment == "Development")
        {
            deniedBody.Should().Contain("\"outcome\"");
        }
        else
        {
            deniedBody.Should().BeEmpty("outside Development the denial reason is not disclosed");
        }
    }

    private static string Report(IEnumerable<RevocationWalkthrough.StepResult> results)
        => string.Join("; ", results.Select(r => $"{r.Name}: expected {(int)r.ExpectedStatus}, got {(int)r.ActualStatus} {r.ResponseBody}"));
}
