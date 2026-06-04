using FluentAssertions;
using Microsoft.Extensions.Logging;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Controller-document authorization (Issue #65, downstream of net-did#71 / 1.3.1).
/// <para>
/// <c>VerificationService</c> now authorizes a proof's verification method by resolving the
/// <em>controller's</em> DID document through an <see cref="IVerificationRelationshipResolver"/>
/// and confirming the method appears in the correct verification relationship
/// (<c>capabilityInvocation</c> for invocations, <c>capabilityDelegation</c> for delegations).
/// </para>
/// <para>
/// Two layers of coverage: (1) <b>policy</b> — proof-purpose → relationship mapping, multi-controller
/// OR-semantics, and fail-closed tri-state handling — exercised with a recording fake resolver;
/// (2) <b>end-to-end</b> — the real <see cref="DefaultVerificationRelationshipResolver"/> over a
/// hand-built controller document, proving cross-DID references (Break A) and per-purpose key
/// separation (Break B) against net-did's actual primitive.
/// </para>
/// </summary>
public class ControllerDocumentAuthorizationTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;

    private const string Target = "https://api.example.com/resource";

    public ControllerDocumentAuthorizationTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService BuildVerifier(
        IVerificationRelationshipResolver relationshipResolver,
        ILogger<VerificationService>? logger = null) =>
        new VerificationService(
            _didProvider,
            new CaveatProcessor(),
            VerificationService.CreateDefaultSuiteProvider(),
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(),
            SigningService.CreateDefaultCanonicalizerProvider(),
            nonceWindow: null,
            logger: logger,
            relationshipResolver: relationshipResolver);

    private async Task<Invocation> SignedInvocationAsync(Capability capability, string signerDid, string action)
    {
        var invocation = new Invocation
        {
            Capability = capability.Id,
            CapabilityAction = action,
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, signerDid);
        return invocation;
    }

    // ─── Policy: proof-purpose → relationship, OR-semantics, tri-state ───────────────

    [Fact]
    public async Task RootInvocation_ResolverAuthorizesForInvocation_Succeeds()
    {
        var alice = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(alice, Target, new[] { "read" });
        var resolver = new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.Authorized);
        var verifier = BuildVerifier(resolver);

        var invocation = await SignedInvocationAsync(root, alice, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeTrue();

        // The invocation path MUST consult capabilityInvocation (not any other relationship).
        resolver.Calls.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(
                (Controller: alice, Vm: invocation.Proof!.VerificationMethod,
                 Relationship: VerificationRelationship.CapabilityInvocation));
    }

    [Fact]
    public async Task RootInvocation_ResolverDenies_Fails()
    {
        var alice = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(alice, Target, new[] { "read" });
        var verifier = BuildVerifier(new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.NotAuthorized));

        var invocation = await SignedInvocationAsync(root, alice, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeFalse();
    }

    [Fact]
    public async Task RootInvocation_ControllerNotResolvable_FailsClosed_AndLogsWarning()
    {
        var alice = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(alice, Target, new[] { "read" });
        var logger = new CapturingLogger<VerificationService>();
        var verifier = BuildVerifier(
            new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.ControllerNotResolvable),
            logger);

        var invocation = await SignedInvocationAsync(root, alice, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeFalse(
            "an unresolvable controller fails closed");
        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Warning && e.Message.Contains("could not be resolved"),
            "the operator must see an infrastructure/config fault, not a silent denial (Issue #64)");
    }

    [Fact]
    public async Task RootInvocation_MultiController_AuthorizedByAnyControllerInSet()
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(new[] { alice, bob }, Target, new[] { "read" });

        // Only the SECOND controller authorizes; OR-semantics must still succeed.
        var resolver = new RecordingRelationshipResolver((controller, _, _) =>
            controller == bob ? AuthorizationDecision.Authorized : AuthorizationDecision.NotAuthorized);
        var verifier = BuildVerifier(resolver);

        var invocation = await SignedInvocationAsync(root, bob, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeTrue();
        resolver.Calls.Select(c => c.Controller).Should().Contain(new[] { alice, bob });
    }

    [Fact]
    public async Task Delegation_ConsultsCapabilityDelegationRelationship()
    {
        var alice = _didProvider.GenerateDidKey();
        var carol = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(alice, Target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, carol, new[] { "read" }, expires: DateTime.UtcNow.AddDays(1), signerDid: alice);

        var resolver = new RecordingRelationshipResolver((_, _, _) => AuthorizationDecision.Authorized);
        var verifier = BuildVerifier(resolver);

        (await verifier.VerifyCapabilityChainAsync(delegated)).Should().BeTrue();

        // The delegation proof (signed by the parent's controller) MUST be checked against
        // capabilityDelegation — the relationship that governs handing out authority.
        resolver.Calls.Should().Contain(
            c => c.Relationship == VerificationRelationship.CapabilityDelegation && c.Controller == alice);
    }

    // ─── End-to-end with the REAL DefaultVerificationRelationshipResolver ────────────

    [Fact]
    public async Task RootInvocation_ControllerDidDiffersFromKeyDid_AuthorizedViaReference()
    {
        // Break A: the signer is a real did:key (so the signature verifies), but the capability's
        // controller is a DIFFERENT did:web DID whose document references that did:key under
        // capabilityInvocation. String matching would reject this; document resolution authorizes it.
        var alice = _didProvider.GenerateDidKey();
        var aliceVm = await _didProvider.GetVerificationMethodAsync(alice);
        const string controller = "did:web:example.com";

        var controllerDoc = new DidDocument
        {
            Id = controller,
            CapabilityInvocation = new[] { VerificationRelationshipEntry.FromReference(aliceVm) }
        };
        var verifier = BuildVerifier(new DefaultVerificationRelationshipResolver(
            new StaticDidDocumentResolver((controller, controllerDoc))));

        var root = await _capabilityService.CreateRootCapabilityAsync(controller, Target, new[] { "read" });
        var invocation = await SignedInvocationAsync(root, alice, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeTrue(
            "the controller's document authorizes this verification method for capabilityInvocation");
    }

    [Fact]
    public async Task RootInvocation_KeyAuthorizedForDelegationOnly_InvocationRejected()
    {
        // Break B: same VM, but the controller lists it under capabilityDelegation ONLY.
        // An invocation must consult capabilityInvocation and therefore be rejected — proving the
        // per-purpose key separation DID Core defines is honored.
        var alice = _didProvider.GenerateDidKey();
        var aliceVm = await _didProvider.GetVerificationMethodAsync(alice);
        const string controller = "did:web:example.com";

        var controllerDoc = new DidDocument
        {
            Id = controller,
            CapabilityDelegation = new[] { VerificationRelationshipEntry.FromReference(aliceVm) }
            // CapabilityInvocation intentionally absent.
        };
        var verifier = BuildVerifier(new DefaultVerificationRelationshipResolver(
            new StaticDidDocumentResolver((controller, controllerDoc))));

        var root = await _capabilityService.CreateRootCapabilityAsync(controller, Target, new[] { "read" });
        var invocation = await SignedInvocationAsync(root, alice, "read");

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeFalse(
            "the key is authorized only for capabilityDelegation, not capabilityInvocation");
    }
}

/// <summary>
/// Configurable, call-recording <see cref="IVerificationRelationshipResolver"/> for isolating
/// VerificationService's authorization policy from real DID-document resolution.
/// </summary>
internal sealed class RecordingRelationshipResolver : IVerificationRelationshipResolver
{
    private readonly Func<string, string, VerificationRelationship, AuthorizationDecision> _decide;

    public List<(string Controller, string Vm, VerificationRelationship Relationship)> Calls { get; } = new();

    public RecordingRelationshipResolver(
        Func<string, string, VerificationRelationship, AuthorizationDecision> decide) => _decide = decide;

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        Calls.Add((controllerDid, verificationMethodDidUrl, relationship));
        var result = _decide(controllerDid, verificationMethodDidUrl, relationship) switch
        {
            AuthorizationDecision.Authorized => VerificationRelationshipAuthorizationResult.Authorized(),
            AuthorizationDecision.ControllerNotResolvable =>
                VerificationRelationshipAuthorizationResult.NotResolvable("notFound", "test: controller not resolvable"),
            _ => VerificationRelationshipAuthorizationResult.NotAuthorized()
        };
        return Task.FromResult(result);
    }
}

/// <summary>
/// Minimal NetDid <see cref="NetDid.Core.IDidResolver"/> backed by a fixed map of DID → document,
/// so the real <see cref="DefaultVerificationRelationshipResolver"/> can be exercised over hand-built
/// controller documents without any network access.
/// </summary>
internal sealed class StaticDidDocumentResolver : NetDid.Core.IDidResolver
{
    private readonly Dictionary<string, DidDocument> _docs;

    public StaticDidDocumentResolver(params (string Did, DidDocument Document)[] docs) =>
        _docs = docs.ToDictionary(d => d.Did, d => d.Document, StringComparer.Ordinal);

    public bool CanResolve(string did) => _docs.ContainsKey(did);

    public Task<DidResolutionResult> ResolveAsync(
        string did, DidResolutionOptions? options = null, CancellationToken ct = default) =>
        Task.FromResult(_docs.TryGetValue(did, out var doc)
            ? new DidResolutionResult { DidDocument = doc, ResolutionMetadata = new DidResolutionMetadata() }
            : DidResolutionResult.NotFound(did));
}
