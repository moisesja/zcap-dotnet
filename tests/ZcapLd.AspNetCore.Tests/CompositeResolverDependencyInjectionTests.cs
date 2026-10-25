using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using Xunit;
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;
using CompositeDidResolver = ZcapLd.Core.Services.CompositeDidResolver; // NetDid ships a same-named type

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// Issue #148 through the DI surface: <c>AddZcapServices()</c> + <c>AddZcapDidResolver(composite)</c>
/// with NO explicit <see cref="IVerificationRelationshipResolver"/> registration must yield a verifier
/// that authorizes non-did:key controllers via the composite's registered adapter (the path a host
/// relies on), fail closed for a key-only adapter, and still let an explicit registration win.
/// </summary>
public sealed class CompositeResolverDependencyInjectionTests
{
    private const string Target = "https://api.example.com/di-composite";

    private readonly InMemoryDidProvider _signerKeys = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _capabilities;
    private readonly InMemoryRootCapabilityResolver _roots = new();

    public CompositeResolverDependencyInjectionTests()
    {
        _signing = new SigningService(_signerKeys, _signerKeys);
        _capabilities = new CapabilityService(_signing);
    }

    private ServiceProvider Build(
        IDidResolver didWebAdapter,
        IVerificationRelationshipResolver? explicitResolver = null,
        ILogger<VerificationService>? logger = null)
    {
        var composite = new CompositeDidResolver();
        composite.Register("did:key:", new DidKeyResolver());
        composite.Register(StaticDidWebAdapter.MethodPrefix, didWebAdapter);

        var services = new ServiceCollection();
        services.AddZcapServices();
        services.AddZcapDidResolver(_ => composite);
        services.AddZcapRootCapabilityResolver(_ => _roots);
        if (explicitResolver is not null)
            services.AddSingleton(explicitResolver);
        if (logger is not null)
            services.AddSingleton(logger);
        return services.BuildServiceProvider();
    }

    private async Task<(Capability Root, Invocation Invocation)> OwnerInvocationAsync(DidWebIdentity owner, string target)
    {
        var root = _roots.Register(await _capabilities.CreateRootCapabilityAsync(owner.Did, target, new[] { "read" }));
        var invocation = _capabilities.CreateInvocation(root, "read");
        invocation.Proof = await _signing.SignInvocationAsync(invocation, owner.Did);
        return (root, invocation);
    }

    [Fact]
    public async Task AddZcapDidResolver_WithComposite_SelfProvidesControllerAuthorization()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var web = new StaticDidWebAdapter(alice.Document);
        using var provider = Build(web);
        provider.GetService<IVerificationRelationshipResolver>().Should().BeNull(
            "no explicit relationship resolver is registered; the composite must self-provide");
        var (root, invocation) = await OwnerInvocationAsync(alice, Target + "/self-provide");

        var result = await provider.GetRequiredService<IVerificationService>()
            .VerifyInvocationDetailedAsync(invocation, root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        web.RelationshipCalls.Should().ContainSingle().Which.Controller.Should().Be(alice.Did);
    }

    [Fact]
    public async Task AddZcapDidResolver_WithKeyOnlyAdapterInComposite_FailsClosed()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var keyOnly = new StaticDidWebAdapter(alice.Document);
        var logger = new CapturingLogger();
        using var provider = Build(keyOnly.AsKeyOnly(), logger: logger);
        var (root, invocation) = await OwnerInvocationAsync(alice, Target + "/key-only");

        var result = await provider.GetRequiredService<IVerificationService>()
            .VerifyInvocationDetailedAsync(invocation, root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        keyOnly.KeyResolutions.Should().BeGreaterThan(0, "the key resolved; authority was still not inferred from it");
        // Pins the composite's own fail-closed branch (not the did:key default's methodNotSupported):
        // the DI-built verifier logged the key-only misconfiguration at Warning with internalError.
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("could not be resolved") &&
            e.Message.Contains("internalError"));
    }

    [Fact]
    public async Task ExplicitlyRegisteredRelationshipResolver_TakesPrecedenceOverComposite()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var web = new StaticDidWebAdapter(alice.Document); // would authorize
        using var provider = Build(web, new DenyAllRelationshipResolver());
        var (root, invocation) = await OwnerInvocationAsync(alice, Target + "/precedence");

        var result = await provider.GetRequiredService<IVerificationService>()
            .VerifyInvocationDetailedAsync(invocation, root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        web.RelationshipCalls.Should().BeEmpty("the explicit registration replaces the composite for relationship checks");
    }

    private sealed class CapturingLogger : ILogger<VerificationService>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class DenyAllRelationshipResolver : IVerificationRelationshipResolver
    {
        public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
            string controllerDid, string verificationMethodDidUrl,
            VerificationRelationship relationship, CancellationToken ct = default) =>
            Task.FromResult(VerificationRelationshipAuthorizationResult.NotAuthorized());
    }
}
