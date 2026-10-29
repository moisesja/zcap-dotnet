using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;
using CompositeDidResolver = ZcapLd.Core.Services.CompositeDidResolver; // NetDid ships a same-named type

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Issue #148: <see cref="CompositeDidResolver"/> implements <see cref="IVerificationRelationshipResolver"/>
/// and routes controller authorization to the adapter registered for the <em>controller's</em> DID
/// method, so a verifier built on the composite authorizes non-did:key controllers without separate
/// wiring. Two layers: (1) direct routing semantics on the composite, including the two fail-closed
/// outcomes; (2) the real <see cref="VerificationService"/> over a composite of
/// <see cref="DidKeyResolver"/> + a non-did:key adapter (<see cref="StaticDidWebAdapter"/>) across
/// invocation, delegation-chain and revocation paths, authorized and wrong-purpose.
/// <para>
/// Guard: the verifier's <c>didResolver</c> is always the composite with a real
/// <see cref="DidKeyResolver"/> child — never <see cref="InMemoryDidProvider"/>, whose own
/// relationship implementation would bypass the composite. The provider is used only to hold signing
/// keys. Roots are supplied via <see cref="InMemoryRootCapabilityResolver"/> because the composite is
/// not an <see cref="IRootCapabilityResolver"/>.
/// </para>
/// </summary>
public class CompositeDidResolverTests
{
    private readonly InMemoryDidProvider _signerKeys = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _capabilities;
    private readonly InMemoryRootCapabilityResolver _roots = new();

    public CompositeDidResolverTests()
    {
        _signing = new SigningService(_signerKeys, _signerKeys);
        _capabilities = new CapabilityService(_signing);
    }

    // Root ids derive from the invocation target, so every root in a test needs a distinct target.
    private static string Target(string name) => $"https://api.example.com/composite/{name}";

    private static CompositeDidResolver Compose(IDidResolver? didWebAdapter = null)
    {
        var composite = new CompositeDidResolver();
        composite.Register("did:key:", new DidKeyResolver()); // real did:key documents, not the signer backend
        if (didWebAdapter is not null)
            composite.Register(StaticDidWebAdapter.MethodPrefix, didWebAdapter);
        return composite;
    }

    private VerificationService Verifier(
        CompositeDidResolver composite,
        ILogger<VerificationService>? logger = null,
        IVerificationRelationshipResolver? explicitRelationshipResolver = null) =>
        new(composite,
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(),
            nonceWindow: null,
            logger: logger,
            relationshipResolver: explicitRelationshipResolver,
            rootResolver: _roots);

    private async Task<Capability> RootAsync(ControllerSet controller, string target) =>
        _roots.Register(await _capabilities.CreateRootCapabilityAsync(controller, target, new[] { "read" }));

    private Task<Capability> DelegateAsync(Capability parent, string delegatee, string signerDid) =>
        _capabilities.DelegateCapabilityAsync(
            parent, delegatee, new[] { "read" }, expires: DateTime.UtcNow.AddDays(1), signerDid: signerDid);

    private async Task<Invocation> InvokeAsync(Capability capability, string signerDid)
    {
        var invocation = _capabilities.CreateInvocation(capability, "read");
        invocation.Proof = await _signing.SignInvocationAsync(invocation, signerDid);
        return invocation;
    }

    // ─── Direct routing semantics ─────────────────────────────────────────────────────

    [Fact]
    public async Task RelationshipCheck_RoutesByControllerMethod_NotByVerificationMethod_AndForwardsArguments()
    {
        var web = new RecordingDualResolver();
        var key = new RecordingDualResolver();
        var composite = new CompositeDidResolver();
        composite.Register("did:key:", key);
        composite.Register("did:web:", web);
        using var cts = new CancellationTokenSource();

        // Controller is did:web, the method it authorizes is did:key (cross-DID reference): the
        // controller's document is the authority, so the did:web adapter must answer.
        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:web:alice.example", "did:key:z6MkDevice#z6MkDevice",
            VerificationRelationship.CapabilityDelegation, cts.Token);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
        web.Calls.Should().ContainSingle().Which.Should().Be(
            ("did:web:alice.example", "did:key:z6MkDevice#z6MkDevice", VerificationRelationship.CapabilityDelegation, cts.Token));
        key.Calls.Should().BeEmpty("routing is by controller, not by the verification method's DID");
    }

    [Fact]
    public async Task RelationshipCheck_ForwardsControllerVerbatim_NoFragmentStripping()
    {
        // Key resolution strips '#…' before routing; the controller is a DID and is forwarded as-is so
        // a non-DID controller value is judged by the method adapter rather than silently normalized.
        var web = new RecordingDualResolver();
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", web);

        await composite.IsAuthorizedForRelationshipAsync(
            "did:web:alice.example#key-1", "#key-1", VerificationRelationship.CapabilityInvocation);

        web.Calls.Should().ContainSingle().Which.Controller.Should().Be("did:web:alice.example#key-1");
    }

    [Fact]
    public async Task RelationshipCheck_FirstMatchingRegistrationWins()
    {
        var broad = new RecordingDualResolver();
        var narrow = new RecordingDualResolver();
        var composite = new CompositeDidResolver();
        composite.Register("did:", broad);
        composite.Register("did:web:", narrow);

        await composite.IsAuthorizedForRelationshipAsync(
            "did:web:alice.example", "#key-1", VerificationRelationship.CapabilityInvocation);

        broad.Calls.Should().ContainSingle();
        narrow.Calls.Should().BeEmpty("registration order decides, same as key resolution");
    }

    [Fact]
    public async Task RelationshipCheck_PredicateRegistration_Routes()
    {
        var web = new RecordingDualResolver();
        var composite = new CompositeDidResolver();
        composite.Register(did => did.EndsWith(".example", StringComparison.Ordinal), web);

        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:web:alice.example", "#key-1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
        web.Calls.Should().ContainSingle();
    }

    [Fact]
    public async Task RelationshipCheck_UnregisteredControllerMethod_FailsClosedAsMethodNotSupported()
    {
        var composite = Compose();

        // No throw: the controller string is attacker-supplied, so this must be a tri-state denial the
        // verifier logs at Debug, not an exception that aborts the multi-controller loop.
        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:example:nobody", "did:key:z6MkX#z6MkX", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be("methodNotSupported");
        result.Message.Should().Contain("did:example:nobody");
    }

    [Fact]
    public async Task RelationshipCheck_KeyOnlyAdapter_FailsClosedAsInternalError_WithoutConsultingKeyResolution()
    {
        var keyOnly = new RecordingKeyOnlyResolver();
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", keyOnly);

        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:web:alice.example", "did:web:alice.example#key-1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be("internalError",
            "a key-only adapter is an operator misconfiguration and must surface at Warning via the verifier's severity seam");
        result.Message.Should().Contain("IVerificationRelationshipResolver");
        keyOnly.KeyResolutions.Should().Be(0, "authority is never inferred from the ability to resolve a key");
    }

    [Theory]
    [InlineData(null, "#key-1")]
    [InlineData("", "#key-1")]
    [InlineData("   ", "#key-1")]
    [InlineData("did:web:alice.example", null)]
    [InlineData("did:web:alice.example", "")]
    [InlineData("did:web:alice.example", " ")]
    public async Task RelationshipCheck_NullOrWhitespaceArguments_Throw(string? controller, string? verificationMethod)
    {
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", new RecordingDualResolver());

        var act = () => composite.IsAuthorizedForRelationshipAsync(
            controller!, verificationMethod!, VerificationRelationship.CapabilityInvocation);

        await act.Should().ThrowAsync<ArgumentException>("matches the interface contract and DefaultVerificationRelationshipResolver");
    }

    [Fact]
    public async Task KeyResolution_UnregisteredMethod_ThrowsCapabilityValidationException()
    {
        // The DID comes from a presented proof's verificationMethod, so an unknown method must be the
        // Debug-classified validation exception (as DidKeyResolver throws), not InvalidOperationException
        // which the verifier would log at Warning — an anonymous Warning-flood vector.
        var composite = Compose();

        var act = () => composite.ResolvePublicKeyAsync("did:example:nobody#key-1");

        (await act.Should().ThrowAsync<CapabilityValidationException>())
            .WithMessage("*No IDidResolver registered*");
    }

    [Fact]
    public async Task RelationshipCheck_ThrowingAdapter_MapsToInternalError_InsteadOfPropagating()
    {
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", new ThrowingRelationshipResolver(
            new HttpRequestException("host unreachable"), throwSynchronously: true));

        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:web:down.example", "#key-1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be("internalError");
        result.Message.Should().Contain("HttpRequestException").And.Contain("host unreachable");
    }

    [Fact]
    public async Task RelationshipCheck_CallerCancellation_Propagates()
    {
        // Only cancellation requested through the CALLER's token is not a resolver fault.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", new ThrowingRelationshipResolver(new OperationCanceledException(cts.Token)));

        var act = () => composite.IsAuthorizedForRelationshipAsync(
            "did:web:down.example", "#key-1", VerificationRelationship.CapabilityInvocation, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "the caller cancelled; the composite must not turn that into a denial");
    }

    [Fact]
    public async Task RelationshipCheck_AdapterTimeout_MapsToInternalError()
    {
        // HttpClient.Timeout raises TaskCanceledException (an OperationCanceledException) while the
        // caller's token is NOT cancelled. That is an adapter fault, not caller cancellation
        // (PR #151 review): it must be a denial for this controller, not an escaping exception.
        var composite = new CompositeDidResolver();
        composite.Register("did:web:", new ThrowingRelationshipResolver(
            new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout elapsing.")));

        var result = await composite.IsAuthorizedForRelationshipAsync(
            "did:web:down.example", "#key-1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be("internalError");
        result.Message.Should().Contain("TaskCanceledException");
    }

    // ─── Through VerificationService: invocation ───────────────────────────────────────

    [Fact]
    public async Task RootInvocation_DidWebOwner_ThroughComposite_IsValid()
    {
        // The #148 regression: before the fix the verifier fell back to the did:key-only default and
        // denied this with UnauthorizedController.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var web = new StaticDidWebAdapter(alice.Document);
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(alice.Did, Target("owner"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, alice.Did), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        web.RelationshipCalls.Should().ContainSingle().Which.Should().Be(
            (alice.Did, alice.MethodId, VerificationRelationship.CapabilityInvocation));
    }

    [Fact]
    public async Task RootInvocation_KeyOnlyDidWebAdapter_FailsClosed_AndLogsWarning()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var root = await RootAsync(alice.Did, Target("key-only"));
        var invocation = await InvokeAsync(root, alice.Did);

        // Sanity: the identical invocation is valid when the did:web adapter is relationship-aware.
        var honest = new StaticDidWebAdapter(alice.Document);
        (await Verifier(Compose(honest)).VerifyInvocationDetailedAsync(invocation, root))
            .Outcome.Should().Be(VerificationOutcome.Valid);

        // Key-only view: the signer's key resolves (the signature gate is reached and passes) but no
        // authority may be inferred from that — the composite fails closed and the misconfiguration
        // surfaces at Warning through the verifier's existing severity seam.
        var keyOnly = new StaticDidWebAdapter(alice.Document);
        var logger = new CapturingLogger<VerificationService>();
        var result = await Verifier(Compose(keyOnly.AsKeyOnly()), logger)
            .VerifyInvocationDetailedAsync(invocation, root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        keyOnly.KeyResolutions.Should().BeGreaterThan(0, "the signature was verified with the key this adapter resolved");
        keyOnly.RelationshipCalls.Should().BeEmpty("a key-only view cannot be asked about relationships");
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("could not be resolved") &&
            e.Message.Contains("internalError") &&
            e.Message.Contains("IVerificationRelationshipResolver"));
    }

    [Fact]
    public async Task RootInvocation_DidWebKeyListedOnlyUnderDelegation_IsRejected()
    {
        // Wrong purpose: the key may delegate but not invoke.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example",
            capabilityInvocation: false, capabilityDelegation: true);
        var verifier = Verifier(Compose(new StaticDidWebAdapter(alice.Document)));
        var root = await RootAsync(alice.Did, Target("wrong-purpose-invoke"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, alice.Did), root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
    }

    [Fact]
    public async Task CrossDidReference_DidWebControllerAuthorizesDidKeyMethod_RoutedToDidWebAdapter()
    {
        // The signer is a real did:key (key resolved by the DidKeyResolver child); the controller is a
        // did:web organisation whose document references that did:key method. Authorization must be
        // routed by the controller to the did:web adapter — not to the did:key child.
        var device = _signerKeys.GenerateDidKey();
        var deviceMethod = await _signerKeys.GetVerificationMethodAsync(device);
        const string org = "did:web:org.example";
        var web = new StaticDidWebAdapter(DidWebIdentities.Referencing(org, deviceMethod));
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(org, Target("cross-did"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, device), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        web.RelationshipCalls.Should().ContainSingle().Which.Should().Be(
            (org, deviceMethod, VerificationRelationship.CapabilityInvocation));
        web.KeyResolutions.Should().Be(0, "the did:key method's key is resolved by the did:key child");
    }

    [Fact]
    public async Task MultiController_SecondControllerAuthorizes_LoopContinuesPastFirstDenial()
    {
        // [did:web owner, did:key bob]; bob invokes. The first controller's adapter answers
        // NotAuthorized and the verifier must continue to bob — the reason the composite returns a
        // result instead of throwing.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var bob = _signerKeys.GenerateDidKey();
        var web = new StaticDidWebAdapter(alice.Document);
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(new[] { alice.Did, bob }, Target("multi"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, bob), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        web.RelationshipCalls.Should().ContainSingle(c =>
            c.Controller == alice.Did && c.Relationship == VerificationRelationship.CapabilityInvocation,
            "the first controller was consulted through the composite before the loop moved on");
    }

    [Fact]
    public async Task MultiController_ThrowingFirstControllerAdapter_LoopContinues_LogsWarning()
    {
        // A did:web host outage must deny that controller and move on, not lock out the did:key
        // co-controller by aborting the whole verification as CouldNotVerify.
        var bob = _signerKeys.GenerateDidKey();
        var logger = new CapturingLogger<VerificationService>();
        var composite = Compose(new ThrowingRelationshipResolver(new HttpRequestException("host unreachable")));
        var verifier = Verifier(composite, logger);
        var root = await RootAsync(new[] { "did:web:down.example", bob }, Target("multi-throwing"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, bob), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("could not be resolved") &&
            e.Message.Contains("HttpRequestException"));
    }

    [Fact]
    public async Task MultiController_DidWebAdapterHttpTimeout_LoopContinues_LogsWarning()
    {
        // PR #151 review (P2): a real HttpClient.Timeout on the did:web adapter raises
        // TaskCanceledException while the caller's token is NOT cancelled. It must deny that controller
        // and move on to bob, not abort the whole verification as CouldNotVerify.
        var bob = _signerKeys.GenerateDidKey();
        var logger = new CapturingLogger<VerificationService>();
        var timingOut = new HttpTimeoutRelationshipResolver();
        var verifier = Verifier(Compose(timingOut), logger);
        var root = await RootAsync(new[] { "did:web:down.example", bob }, Target("multi-http-timeout"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, bob), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        timingOut.ObservedException.Should().BeOfType<TaskCanceledException>("the genuine HttpClient timeout exception was raised");
        timingOut.CallerCancellationRequested.Should().BeFalse("the timeout is the adapter's, not the caller's");
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("could not be resolved") &&
            e.Message.Contains("TaskCanceledException"));
    }

    [Fact]
    public async Task RootInvocation_DidWebAdapterHttpTimeout_IsUnauthorizedController_NotCouldNotVerify()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:down.example");
        var timingOut = new HttpTimeoutRelationshipResolver(keys: new StaticDidWebAdapter(alice.Document));
        var verifier = Verifier(Compose(timingOut));
        var root = await RootAsync(alice.Did, Target("http-timeout"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, alice.Did), root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController,
            "an adapter timeout denies that controller; it is not an aborted verification");
    }

    [Fact]
    public async Task RootInvocation_ThrowingControllerAdapter_IsUnauthorizedController_NotCouldNotVerify()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:down.example");
        var logger = new CapturingLogger<VerificationService>();
        var faulting = new ThrowingRelationshipResolver(
            new HttpRequestException("host unreachable"), keys: new StaticDidWebAdapter(alice.Document));
        var verifier = Verifier(Compose(faulting), logger);
        var root = await RootAsync(alice.Did, Target("throwing"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, alice.Did), root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController,
            "an adapter fault denies that controller; it is not an aborted verification");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("HttpRequestException"));
    }

    [Fact]
    public async Task Invocation_SignerOfUnregisteredMethod_FailsClosed_WithoutWarning()
    {
        // The proof's verificationMethod is attacker-chosen. An unknown method on the KEY path must
        // not reach the Warning channel (anonymous flood vector); it is an expected denial.
        var bob = _signerKeys.GenerateDidKey();
        _signerKeys.GenerateAndRegisterKeyPair("did:example:eve");
        var logger = new CapturingLogger<VerificationService>();
        var verifier = Verifier(Compose(), logger);
        var root = await RootAsync(bob, Target("unregistered-signer"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, "did:example:eve"), root);

        result.IsValid.Should().BeFalse();
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning);
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Debug);
    }

    [Fact]
    public async Task MultiController_UnregisteredFirstController_LoopContinues_LogsDebugOnly()
    {
        var bob = _signerKeys.GenerateDidKey();
        var logger = new CapturingLogger<VerificationService>();
        var verifier = Verifier(Compose(), logger);
        var root = await RootAsync(new[] { "did:example:unregistered", bob }, Target("multi-unregistered"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, bob), root);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Debug && e.Message.Contains("could not be resolved") && e.Message.Contains("methodNotSupported"));
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task RootInvocation_UnregisteredControllerMethod_FailsClosed_LogsDebugWithCompositeMessage()
    {
        // The controller comes from the presented capability, so an unroutable method is an expected,
        // attacker-drivable denial: Debug (not Warning), carrying the composite's diagnostic.
        var bob = _signerKeys.GenerateDidKey();
        var logger = new CapturingLogger<VerificationService>();
        var verifier = Verifier(Compose(), logger);
        var root = await RootAsync("did:example:nobody", Target("unregistered"));

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(root, bob), root);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Debug &&
            e.Message.Contains("could not be resolved") &&
            e.Message.Contains("No IDidResolver is registered"));
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning && e.Message.Contains("could not be resolved"));
    }

    [Fact]
    public async Task ExplicitRelationshipResolver_TakesPrecedenceOverComposite_InBothDirections()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var root = await RootAsync(alice.Did, Target("precedence"));
        var invocation = await InvokeAsync(root, alice.Did);

        // Composite would DENY (alice's document grants no relationships) — explicit AUTHORIZES.
        var denying = new StaticDidWebAdapter(
            alice.Document with { CapabilityInvocation = null, CapabilityDelegation = null });
        var explicitAllow = new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.Authorized);
        var allowed = await Verifier(Compose(denying), explicitRelationshipResolver: explicitAllow)
            .VerifyInvocationDetailedAsync(invocation, root);
        allowed.Outcome.Should().Be(VerificationOutcome.Valid, allowed.Message);
        explicitAllow.Calls.Should().NotBeEmpty();
        denying.RelationshipCalls.Should().BeEmpty("an explicit resolver replaces the composite for relationship checks");

        // Composite would AUTHORIZE — explicit DENIES.
        var authorizing = new StaticDidWebAdapter(alice.Document);
        var explicitDeny = new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.NotAuthorized);
        var denied = await Verifier(Compose(authorizing), explicitRelationshipResolver: explicitDeny)
            .VerifyInvocationDetailedAsync(invocation, root);
        denied.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        explicitDeny.Calls.Should().NotBeEmpty();
        authorizing.RelationshipCalls.Should().BeEmpty();
    }

    // ─── Through VerificationService: delegation chains ────────────────────────────────

    [Fact]
    public async Task DelegationChain_DidWebOwnerToDidKeyDelegatee_ThroughComposite_IsValid()
    {
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var bob = _signerKeys.GenerateDidKey();
        var web = new StaticDidWebAdapter(alice.Document);
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(alice.Did, Target("chain"));
        var delegated = await DelegateAsync(root, bob, signerDid: alice.Did);

        var chain = await verifier.VerifyCapabilityChainDetailedAsync(delegated);
        chain.Outcome.Should().Be(VerificationOutcome.Valid, chain.Message);

        var invocation = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(delegated, bob), delegated);
        invocation.Outcome.Should().Be(VerificationOutcome.Valid, invocation.Message);

        web.RelationshipCalls.Should().Contain(c =>
            c.Controller == alice.Did && c.Relationship == VerificationRelationship.CapabilityDelegation);
    }

    [Fact]
    public async Task DelegationChain_DidWebDelegatee_InvokesThroughComposite_IsValid()
    {
        // Both ends of the chain are non-did:key: the delegation check (alice, capabilityDelegation) and
        // the invocation check (carol, capabilityInvocation) are routed to the did:web adapter.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var carol = DidWebIdentities.Create(_signerKeys, "did:web:carol.example");
        var web = new StaticDidWebAdapter(alice.Document, carol.Document);
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(alice.Did, Target("chain-web-delegatee"));
        var delegated = await DelegateAsync(root, carol.Did, signerDid: alice.Did);

        var result = await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(delegated, carol.Did), delegated);

        result.Outcome.Should().Be(VerificationOutcome.Valid, result.Message);
        web.RelationshipCalls.Should().Contain((alice.Did, alice.MethodId, VerificationRelationship.CapabilityDelegation));
        web.RelationshipCalls.Should().Contain((carol.Did, carol.MethodId, VerificationRelationship.CapabilityInvocation));
    }

    [Fact]
    public async Task DelegationChain_DidWebSignerListedOnlyUnderInvocation_IsRejected()
    {
        // Wrong purpose: alice may invoke but not delegate, so her delegation to bob is unauthorized on
        // the chain path and on the delegated-invocation path.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example",
            capabilityInvocation: true, capabilityDelegation: false);
        var bob = _signerKeys.GenerateDidKey();
        var verifier = Verifier(Compose(new StaticDidWebAdapter(alice.Document)));
        var root = await RootAsync(alice.Did, Target("wrong-purpose-delegate"));
        var delegated = await DelegateAsync(root, bob, signerDid: alice.Did);

        (await verifier.VerifyCapabilityChainDetailedAsync(delegated))
            .Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
        (await verifier.VerifyInvocationDetailedAsync(await InvokeAsync(delegated, bob), delegated))
            .Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
    }

    // ─── Through VerificationService: revocation ──────────────────────────────────────

    [Fact]
    public async Task Revocation_ThroughComposite_DelegationPurposeRequired()
    {
        // Revocation is a capabilityDelegation action. Carol's did:web document lists her key only
        // under capabilityInvocation, so she cannot revoke her own grant; Dave (both relationships) can.
        var alice = DidWebIdentities.Create(_signerKeys, "did:web:alice.example");
        var carol = DidWebIdentities.Create(_signerKeys, "did:web:carol.example",
            capabilityInvocation: true, capabilityDelegation: false);
        var dave = DidWebIdentities.Create(_signerKeys, "did:web:dave.example");
        var web = new StaticDidWebAdapter(alice.Document, carol.Document, dave.Document);
        var verifier = Verifier(Compose(web));
        var root = await RootAsync(alice.Did, Target("revoke"));
        var toCarol = await DelegateAsync(root, carol.Did, signerDid: alice.Did);
        var toDave = await DelegateAsync(root, dave.Did, signerDid: alice.Did);

        var carolRequest = await _signing.SignRevocationAsync(toCarol.Id, carol.Did, toCarol.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(toCarol, carolRequest, root)).Should().BeFalse(
            "a key authorized only for capabilityInvocation cannot revoke");
        (await verifier.IsCapabilityRevokedAsync(toCarol.Id, RevocationScope.Delegated(alice.Did))).Should().BeFalse();
        web.RelationshipCalls.Should().Contain(c =>
            c.Controller == carol.Did && c.Relationship == VerificationRelationship.CapabilityDelegation);

        var daveRequest = await _signing.SignRevocationAsync(toDave.Id, dave.Did, toDave.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(toDave, daveRequest, root)).Should().BeTrue();
        (await verifier.IsCapabilityRevokedAsync(toDave.Id, RevocationScope.Delegated(alice.Did))).Should().BeTrue();
    }
}

/// <summary>
/// Composite child implementing both zcap <see cref="IDidResolver"/> and
/// <see cref="IVerificationRelationshipResolver"/>; records relationship calls (including the
/// cancellation token) and returns a fixed decision. Key methods return placeholder material.
/// </summary>
internal sealed class RecordingDualResolver : IDidResolver, IVerificationRelationshipResolver
{
    private readonly AuthorizationDecision _decision;

    public RecordingDualResolver(AuthorizationDecision decision = AuthorizationDecision.Authorized) =>
        _decision = decision;

    public List<(string Controller, string VerificationMethod, VerificationRelationship Relationship, CancellationToken Ct)> Calls { get; } = new();

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod) =>
        Task.FromResult(new ResolvedKey(new byte[32], "Ed25519VerificationKey2020"));

    public Task<string> GetVerificationMethodAsync(string did) => Task.FromResult($"{did}#key-1");

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        Calls.Add((controllerDid, verificationMethodDidUrl, relationship, ct));
        return Task.FromResult(_decision switch
        {
            AuthorizationDecision.Authorized => VerificationRelationshipAuthorizationResult.Authorized(),
            AuthorizationDecision.ControllerNotResolvable =>
                VerificationRelationshipAuthorizationResult.NotResolvable("notFound", "test"),
            _ => VerificationRelationshipAuthorizationResult.NotAuthorized()
        });
    }
}

/// <summary>
/// Relationship-aware composite child whose relationship check faults with a configured exception
/// (faulted task by default, or a synchronous throw); key methods are delegated to <c>keys</c>.
/// </summary>
internal sealed class ThrowingRelationshipResolver : IDidResolver, IVerificationRelationshipResolver
{
    private readonly Exception _exception;
    private readonly bool _throwSynchronously;
    private readonly IDidResolver _keys;

    public ThrowingRelationshipResolver(Exception exception, bool throwSynchronously = false, IDidResolver? keys = null)
    {
        _exception = exception;
        _throwSynchronously = throwSynchronously;
        _keys = keys ?? new RecordingKeyOnlyResolver();
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod) =>
        _keys.ResolvePublicKeyAsync(didOrVerificationMethod);

    public Task<string> GetVerificationMethodAsync(string did) => _keys.GetVerificationMethodAsync(did);

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        if (_throwSynchronously)
            throw _exception;
        return Task.FromException<VerificationRelationshipAuthorizationResult>(_exception);
    }
}

/// <summary>
/// Relationship-aware composite child whose relationship check performs a real <see cref="HttpClient"/>
/// request with a 20 ms <see cref="HttpClient.Timeout"/> through a handler that never answers in time,
/// so the exception is the genuine <see cref="TaskCanceledException"/> HttpClient raises on its own
/// timeout while the caller's token is not cancelled. Records what it observed for assertions.
/// </summary>
internal sealed class HttpTimeoutRelationshipResolver : IDidResolver, IVerificationRelationshipResolver
{
    private readonly HttpClient _http = new(new DelayingHandler()) { Timeout = TimeSpan.FromMilliseconds(20) };
    private readonly IDidResolver _keys;

    public HttpTimeoutRelationshipResolver(IDidResolver? keys = null) => _keys = keys ?? new RecordingKeyOnlyResolver();

    public Exception? ObservedException { get; private set; }
    public bool? CallerCancellationRequested { get; private set; }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod) =>
        _keys.ResolvePublicKeyAsync(didOrVerificationMethod);

    public Task<string> GetVerificationMethodAsync(string did) => _keys.GetVerificationMethodAsync(did);

    public async Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        try
        {
            using var response = await _http.GetAsync("https://down.example/.well-known/did.json", ct);
            throw new InvalidOperationException("the delaying handler must never answer within the timeout");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            ObservedException = ex;
            CallerCancellationRequested = ct.IsCancellationRequested;
            throw;
        }
    }

    private sealed class DelayingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}

/// <summary>Composite child that resolves keys only; counts key resolutions.</summary>/// <summary>Composite child that resolves keys only; counts key resolutions.</summary>
internal sealed class RecordingKeyOnlyResolver : IDidResolver
{
    public int KeyResolutions { get; private set; }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        KeyResolutions++;
        return Task.FromResult(new ResolvedKey(new byte[32], "Ed25519VerificationKey2020"));
    }

    public Task<string> GetVerificationMethodAsync(string did) => Task.FromResult($"{did}#key-1");
}
