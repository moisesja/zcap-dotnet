using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Issue #70: the <c>...DetailedAsync</c> verify methods return a structured <see cref="VerificationResult"/>
/// so callers can distinguish failure modes programmatically (revoked vs expired vs bad-signature vs …)
/// instead of a bare <c>false</c>. Each test drives one failure branch and asserts the specific
/// <see cref="VerificationOutcome"/>; the bool-parity tests confirm the legacy <c>Task&lt;bool&gt;</c>
/// methods still return <c>(await Detailed).IsValid</c> with identical fail-closed behavior.
/// </summary>
public class VerificationResultTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor;
    private readonly VerificationService _verificationService;

    public VerificationResultTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _caveatProcessor = new CaveatProcessor();
        _verificationService = new VerificationService(_didProvider, _caveatProcessor);
        _capabilityService = new CapabilityService(_signingService);
    }

    private Task<Capability> CreateAndRegisterRootAsync(
        ControllerSet controller, string invocationTarget, string[]? allowedActions = null,
        DateTime? expires = null, Caveat[]? caveats = null)
        => TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, controller, invocationTarget, allowedActions, expires, caveats);

    // Builds a valid first-level delegation (root registered for spec-exact root-by-id resolution).
    // The root id is derived from invocationTarget, so callers that build more than one root in a
    // single test MUST pass distinct targets to avoid a root-id collision in the resolver.
    private async Task<(Capability root, Capability delegated)> BuildValidDelegationAsync(
        string rootDid, string childDid, string[] actions, DateTime? expires = null, Caveat[]? caveats = null,
        string invocationTarget = "https://example.com/resource")
    {
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(childDid);
        var root = await CreateAndRegisterRootAsync(rootDid, invocationTarget, new[] { "read", "write" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, actions, expires ?? DateTime.UtcNow.AddDays(7), caveats);
        return (root, delegated);
    }

    private async Task<Invocation> SignInvocationAsync(
        Capability capability, string signerDid, string action, string target)
    {
        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(capability),
            CapabilityAction = action,
            InvocationTarget = target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, signerDid);
        return invocation;
    }

    // ---- success ----------------------------------------------------------

    [Fact]
    public async Task ChainDetailed_ValidDelegation_ReturnsValid()
    {
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkVRoot", "did:key:z6MkVChild", new[] { "read" });

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.Valid);
        result.IsValid.Should().BeTrue();
        result.Message.Should().BeNull();
    }

    [Fact]
    public async Task ProofDetailed_RootCapability_ReturnsValid()
    {
        var root = await CreateAndRegisterRootAsync("did:key:z6MkRootOnly", "https://example.com/resource", new[] { "read" });

        var result = await _verificationService.VerifyCapabilityProofDetailedAsync(root);

        result.Outcome.Should().Be(VerificationOutcome.Valid);
    }

    // ---- the eight named failure modes -----------------------------------

    [Fact]
    public async Task ChainDetailed_RevokedCapability_ReturnsRevoked()
    {
        var revocationService = new RevocationService(new InMemoryRevocationStore());
        var verifier = new VerificationService(
            _didProvider, _caveatProcessor, revocationService);
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkRevRoot", "did:key:z6MkRevChild", new[] { "read" });
        await revocationService.RevokeAsync(new RevocationRequest { CapabilityId = delegated.Id, RevokedBy = "did:key:z6MkRevRoot" });

        var result = await verifier.VerifyCapabilityChainDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.Revoked);
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ChainDetailed_ExpiredDelegation_ReturnsExpired()
    {
        var (_, delegated) = await BuildValidDelegationAsync(
            "did:key:z6MkExpRoot", "did:key:z6MkExpChild", new[] { "read" }, expires: DateTime.UtcNow.AddDays(-1));

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.Expired);
    }

    [Fact]
    public async Task ProofDetailed_TamperedSignature_ReturnsInvalidSignature()
    {
        // Swap in a valid-but-wrong signature: delegate two caps from the same root (same signer key,
        // so the multibase proofValue decodes to a correct-length Ed25519 signature) and graft B's
        // signature onto A. A's content no longer matches the signature → InvalidSignature (not a decode
        // fault, which would be CouldNotVerify).
        var (_, delegatedA) = await BuildValidDelegationAsync("did:key:z6MkSigRoot", "did:key:z6MkSigChildA", new[] { "read" });
        var rootB = await CreateAndRegisterRootAsync("did:key:z6MkSigRoot", "https://example.com/resource", new[] { "read", "write" });
        var delegatedB = await _capabilityService.DelegateCapabilityAsync(
            rootB, "did:key:z6MkSigChildB", new[] { "read" }, DateTime.UtcNow.AddDays(7));
        delegatedA.Proof!.Primary.ProofValue = delegatedB.Proof!.Primary.ProofValue;

        var result = await _verificationService.VerifyCapabilityProofDetailedAsync(delegatedA);

        result.Outcome.Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact]
    public async Task ChainDetailed_DelegationNotAuthorizedByRootController_ReturnsUnauthorizedController()
    {
        // Spec-exact first-level chain [rootId], but the child self-signs a delegation from a root it
        // does not control: the signature is valid, yet the signer is not authorized by the root's
        // controller for capabilityDelegation.
        var rootDid = "did:key:z6MkUnauthRoot";
        var childDid = "did:key:z6MkUnauthChild";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(childDid);
        var root = await CreateAndRegisterRootAsync(rootDid, "https://example.com/resource", new[] { "read", "write" });
        var suiteContext = await _signingService.ResolveSuiteContextUrlAsync(childDid);
        var selfSigned = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", suiteContext },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = root.Id,
            Controller = childDid,
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(5))
        };
        selfSigned.Proof = await _signingService.SignCapabilityAsync(
            selfSigned, childDid, "capabilityDelegation", new object[] { root.Id });

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(selfSigned);

        result.Outcome.Should().Be(VerificationOutcome.UnauthorizedController);
    }

    [Fact]
    public async Task ProofDetailed_OverbroadChild_ReturnsAttenuationViolation()
    {
        // root(read,write) → mid(read) → leaf claiming (read,write), validly signed by mid: the only
        // invalid factor is attenuation (Issue #69).
        var rootDid = "did:key:z6MkAttRoot";
        var midDid = "did:key:z6MkAttMid";
        var leafDid = "did:key:z6MkAttLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(midDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);
        var root = await CreateAndRegisterRootAsync(rootDid, "https://example.com/resource", new[] { "read", "write" });
        var mid = await _capabilityService.DelegateCapabilityAsync(root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        var overbroad = new Capability
        {
            Context = mid.Context,
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = leafDid,
            InvocationTarget = mid.InvocationTarget,
            AllowedAction = new[] { "read", "write" },
            Expires = mid.Expires,
            ParentCapability = mid.Id
        };
        overbroad.Proof = await _signingService.SignCapabilityAsync(
            overbroad, midDid, "capabilityDelegation", new object[] { root.Id, mid });

        var result = await _verificationService.VerifyCapabilityProofDetailedAsync(overbroad);

        result.Outcome.Should().Be(VerificationOutcome.AttenuationViolation);
    }

    [Fact]
    public async Task InvocationDetailed_FailingCaveat_ReturnsCaveatFailed()
    {
        var expiredCaveat = new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(-1) };
        var (_, delegated) = await BuildValidDelegationAsync(
            "did:key:z6MkCavRoot", "did:key:z6MkCavChild", new[] { "read" }, caveats: new Caveat[] { expiredCaveat });
        var invocation = await SignInvocationAsync(delegated, "did:key:z6MkCavChild", "read", "https://example.com/resource");

        var result = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.CaveatFailed);
    }

    [Fact]
    public async Task InvocationDetailed_SecondInvocation_ReturnsReplayed()
    {
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkRepRoot", "did:key:z6MkRepChild", new[] { "read" });
        var invocation = await SignInvocationAsync(delegated, "did:key:z6MkRepChild", "read", "https://example.com/resource");

        var first = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);
        var second = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);

        first.Outcome.Should().Be(VerificationOutcome.Valid);
        second.Outcome.Should().Be(VerificationOutcome.Replayed);
    }

    [Fact]
    public async Task ChainDetailed_TooLong_ReturnsChainTooLong()
    {
        // Build root → 11 delegations (chain length 12 > MaxChainLength 10).
        var rootDid = "did:key:z6MkLongRoot";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        var root = await CreateAndRegisterRootAsync(rootDid, "https://example.com/resource", new[] { "read" });

        var current = root;
        var currentSigner = rootDid;
        for (int i = 0; i < 11; i++)
        {
            var childDid = $"did:key:z6MkLong{i}";
            _didProvider.GenerateAndRegisterKeyPair(childDid);
            current = await _capabilityService.DelegateCapabilityAsync(
                current, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(30), signerDid: currentSigner);
            currentSigner = childDid;
        }

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(current);

        result.Outcome.Should().Be(VerificationOutcome.ChainTooLong);
    }

    [Fact]
    public async Task ChainDetailed_FutureDatedDelegationCreated_ReturnsInvalidProofTime()
    {
        // A delegation proof's `created` dated beyond the clock skew is rejected (Issue #99) — distinct
        // from StaleProof (invocation/revocation freshness) and Expired (past-`expires`). Re-signed with a
        // future created so the signature is valid and the only invalid factor is the proof time.
        var (_, delegated) = await BuildValidDelegationAsync(
            "did:key:z6MkProofTimeRoot", "did:key:z6MkProofTimeChild", new[] { "read" },
            invocationTarget: "https://example.com/proof-time");
        delegated.Proof = await _signingService.SignCapabilityAsync(
            delegated, "did:key:z6MkProofTimeRoot", "capabilityDelegation",
            delegated.Proof!.Primary.CapabilityChain, DateTime.UtcNow.AddMinutes(10));

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.InvalidProofTime);
    }

    // ---- invocation-specific structural modes ----------------------------

    [Fact]
    public async Task InvocationDetailed_ActionNotInAllowedAction_ReturnsActionNotAllowed()
    {
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkActRoot", "did:key:z6MkActChild", new[] { "read" });
        var invocation = await SignInvocationAsync(delegated, "did:key:z6MkActChild", "write", "https://example.com/resource");

        var result = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.ActionNotAllowed);
    }

    [Fact]
    public async Task InvocationDetailed_TargetOutsideCapability_ReturnsInvalidTarget()
    {
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkTgtRoot", "did:key:z6MkTgtChild", new[] { "read" });
        var invocation = await SignInvocationAsync(delegated, "did:key:z6MkTgtChild", "read", "https://different.example.org/elsewhere");

        var result = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.InvalidTarget);
    }

    [Fact]
    public async Task InvocationDetailed_MissingId_ReturnsMalformedCapability()
    {
        var (_, delegated) = await BuildValidDelegationAsync("did:key:z6MkMalRoot", "did:key:z6MkMalChild", new[] { "read" });
        var invocation = await SignInvocationAsync(delegated, "did:key:z6MkMalChild", "read", "https://example.com/resource");
        invocation.Id = ""; // structurally invalid after signing

        var result = await _verificationService.VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }

    // ---- "couldn't check" vs "invalid" (the M7 distinction) --------------

    [Fact]
    public async Task ChainDetailed_DelegatedWithUnobtainableRoot_ReturnsCouldNotVerify()
    {
        // Root is created but NOT registered, and no explicit root is supplied, so the spec-exact
        // root-by-id reference cannot be resolved: a configuration gap, not an invalid capability.
        var rootDid = "did:key:z6MkCnvRoot";
        var childDid = "did:key:z6MkCnvChild";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(childDid);
        var unregisteredRoot = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            unregisteredRoot, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var result = await _verificationService.VerifyCapabilityChainDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.CouldNotVerify);
    }

    // ---- bool parity ------------------------------------------------------

    [Fact]
    public async Task BoolMethods_MatchDetailedIsValid_ForValidAndInvalid()
    {
        var (_, valid) = await BuildValidDelegationAsync(
            "did:key:z6MkParRoot", "did:key:z6MkParChild", new[] { "read" },
            invocationTarget: "https://example.com/parity-valid");
        var (_, expired) = await BuildValidDelegationAsync(
            "did:key:z6MkParRoot2", "did:key:z6MkParChild2", new[] { "read" },
            expires: DateTime.UtcNow.AddDays(-1), invocationTarget: "https://example.com/parity-expired");

        var validBool = await _verificationService.VerifyCapabilityChainAsync(valid);
        var validDetailed = await _verificationService.VerifyCapabilityChainDetailedAsync(valid);
        var expiredBool = await _verificationService.VerifyCapabilityChainAsync(expired);
        var expiredDetailed = await _verificationService.VerifyCapabilityChainDetailedAsync(expired);

        validBool.Should().BeTrue();
        validBool.Should().Be(validDetailed.IsValid);
        expiredBool.Should().BeFalse();
        expiredBool.Should().Be(expiredDetailed.IsValid);
        expiredDetailed.Outcome.Should().Be(VerificationOutcome.Expired);
    }

    [Fact]
    public async Task DetailedMethods_NullCapability_ThrowsArgumentNullException()
    {
        // The throw contract for null arguments is preserved (LogDenial awaits and the guard propagates).
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _verificationService.VerifyCapabilityChainDetailedAsync(null!));
    }
}
