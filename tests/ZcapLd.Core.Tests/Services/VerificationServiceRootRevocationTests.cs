using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Revoking a root capability (Issue #155). A root-only chain carries no delegation proof, so the
/// verifier must authorize against the root it trusts — the explicit root or the configured
/// <see cref="IRootCapabilityResolver"/> — never against the caller-supplied copy. Otherwise anyone who
/// knows a root id could revoke it by presenting that id with their own controller.
/// </summary>
public class VerificationServiceRootRevocationTests
{
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly VerificationService _verifier;

    public VerificationServiceRootRevocationTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
        // _didProvider doubles as the IRootCapabilityResolver the verifier auto-detects.
        _verifier = new VerificationService(_didProvider);
    }

    [Fact]
    public async Task RevokeCapability_RootByItsController_WithTrustedRoot_Succeeds()
    {
        var owner = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, owner, "https://example.com/root-revoke-ok");
        var signed = await _signingService.SignRevocationAsync(root.Id, owner, root.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(root, signed)).Should().BeTrue();
        (await _verifier.IsCapabilityRevokedAsync(root.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCapability_ImpostorRootClaimingTrustedRootId_FailsAndDoesNotRevoke()
    {
        var owner = _didProvider.GenerateDidKey();
        var mallory = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, owner, "https://example.com/root-revoke-impostor");

        // Same id and target as the trusted root, but Mallory names herself as controller and signs
        // with her own (real, resolvable) key.
        var impostor = new Capability
        {
            Context = root.Context,
            Id = root.Id,
            Controller = mallory,
            InvocationTarget = root.InvocationTarget
        };
        var signed = await _signingService.SignRevocationAsync(impostor.Id, mallory, impostor.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(impostor, signed)).Should().BeFalse(
            "a root's controller comes from the trusted root, never from the request");
        (await _verifier.IsCapabilityRevokedAsync(root.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_RootUnknownToResolver_FailsClosed()
    {
        var owner = _didProvider.GenerateDidKey();
        // Created but never registered: the resolver cannot anchor it.
        var root = await _capabilityService.CreateRootCapabilityAsync(owner, "https://example.com/root-revoke-unknown");
        var signed = await _signingService.SignRevocationAsync(root.Id, owner, root.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(root, signed)).Should().BeFalse(
            "a root the verifier cannot resolve is not trusted, even with the genuine controller's signature");
        (await _verifier.IsCapabilityRevokedAsync(root.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_ExplicitRootOverload_AuthorizesAgainstExplicitRoot()
    {
        var owner = _didProvider.GenerateDidKey();
        var mallory = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(owner, "https://example.com/root-revoke-explicit");
        var impostor = new Capability
        {
            Context = root.Context,
            Id = root.Id,
            Controller = mallory,
            InvocationTarget = root.InvocationTarget
        };

        var malloryRequest = await _signingService.SignRevocationAsync(root.Id, mallory, root.InvocationTarget);
        (await _verifier.RevokeCapabilityAsync(impostor, malloryRequest, root)).Should().BeFalse();
        (await _verifier.IsCapabilityRevokedAsync(root.Id)).Should().BeFalse();

        var ownerRequest = await _signingService.SignRevocationAsync(root.Id, owner, root.InvocationTarget);
        (await _verifier.RevokeCapabilityAsync(root, ownerRequest, root)).Should().BeTrue();
        (await _verifier.IsCapabilityRevokedAsync(root.Id)).Should().BeTrue();
    }

    // ----- Root-ness is decided by the verifier's trust store, never by the request's shape -----
    //
    // A delegated-shaped body under the attacker's own, validly signed chain can carry any id. If
    // "is this a root?" were read from the request (no parentCapability), such a body borrowing a root's
    // id would skip the anchoring and the revocation would be recorded for the victim's root.

    [Fact]
    public async Task RevokeCapability_DelegatedShapedBodyBorrowingAnotherRootsId_FailsAndDoesNotRevoke()
    {
        var attacker = _didProvider.GenerateDidKey();
        var victim = _didProvider.GenerateDidKey();
        var attackerRoot = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, attacker, "https://attacker.example/resource");
        var victimRoot = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, victim, "https://victim.example/resource");

        var forged = ForgeDelegation(victimRoot.Id, attacker, attackerRoot.Id, attackerRoot.InvocationTarget);
        forged.Proof = await _signingService.SignCapabilityAsync(
            forged, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });
        var signed = await _signingService.SignRevocationAsync(forged.Id, attacker, forged.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(forged, signed)).Should().BeFalse(
            "an id the verifier knows as a root is anchored to that root however the request shapes it");
        (await _verifier.IsCapabilityRevokedAsync(victimRoot.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_DelegateForgingAnotherRootsIdUnderItsDelegation_FailsAndDoesNotRevoke()
    {
        var owner = _didProvider.GenerateDidKey();
        var delegate_ = _didProvider.GenerateDidKey();
        var victim = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, owner, "https://owner.example/resource");
        var victimRoot = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, victim, "https://victim.example/resource-2");
        var delegation = await _capabilityService.DelegateCapabilityAsync(
            root, delegate_, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        // A mere delegate mints a depth-2 "child" that borrows the victim root's id.
        var forged = ForgeDelegation(victimRoot.Id, delegate_, delegation.Id, delegation.InvocationTarget, new[] { "read" });
        forged.Proof = await _signingService.SignCapabilityAsync(
            forged, delegate_, "capabilityDelegation", new object[] { root.Id, delegation });
        var signed = await _signingService.SignRevocationAsync(forged.Id, delegate_, forged.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(forged, signed)).Should().BeFalse();
        (await _verifier.RevokeCapabilityAsync(forged, signed, root)).Should().BeFalse(
            "the explicit-root overload still consults the resolver for the id being revoked");
        (await _verifier.IsCapabilityRevokedAsync(victimRoot.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_DelegatedShapedBodyWithUnknownRootNamedId_FailsClosed()
    {
        var attacker = _didProvider.GenerateDidKey();
        var attackerRoot = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, attacker, "https://attacker.example/resource-3");
        const string unknownRootId = "urn:zcap:root:https%3A%2F%2Fother.example%2Fresource";

        var forged = ForgeDelegation(unknownRootId, attacker, attackerRoot.Id, attackerRoot.InvocationTarget);
        forged.Proof = await _signingService.SignCapabilityAsync(
            forged, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });
        var signed = await _signingService.SignRevocationAsync(forged.Id, attacker, forged.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(forged, signed)).Should().BeFalse(
            "a urn:zcap:root:-named id the verifier cannot resolve has nothing trusted to authorize against");
        (await _verifier.IsCapabilityRevokedAsync(unknownRootId)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_GenuineDelegation_StillRevocableByDelegateAndOwner()
    {
        var owner = _didProvider.GenerateDidKey();
        var delegate_ = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, owner, "https://owner.example/resource-4");
        var first = await _capabilityService.DelegateCapabilityAsync(root, delegate_, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        var second = await _capabilityService.DelegateCapabilityAsync(root, delegate_, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var byDelegate = await _signingService.SignRevocationAsync(first.Id, delegate_, first.InvocationTarget);
        (await _verifier.RevokeCapabilityAsync(first, byDelegate)).Should().BeTrue();

        var byOwner = await _signingService.SignRevocationAsync(second.Id, owner, second.InvocationTarget);
        (await _verifier.RevokeCapabilityAsync(second, byOwner)).Should().BeTrue();
    }

    private static Capability ForgeDelegation(
        string id, string controller, string parentId, string invocationTarget, string[]? allowedAction = null)
        => new()
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = id,
            Controller = controller,
            InvocationTarget = invocationTarget,
            AllowedAction = allowedAction,
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1)),
            ParentCapability = parentId
        };
}
