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
        // The urn:zcap:root: guard alone would also refuse this id; the custom-root case further down
        // pins the resolver lookup itself.
        (await _verifier.RevokeCapabilityAsync(forged, signed, root)).Should().BeFalse(
            "a known root's id is refused through the explicit-root overload too");
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

    // ----- Explicit-root overload: the explicit root scopes the call (PR #156 review) -----

    [Fact]
    public async Task RevokeCapability_ExplicitRootOverload_RefusesADifferentKnownRoot()
    {
        // Root B, signed by B's genuine controller, revoked through unrelated explicit root A: the
        // explicit root admits only itself, as it does for a delegated chain and for invocations.
        var ownerA = _didProvider.GenerateDidKey();
        var ownerB = _didProvider.GenerateDidKey();
        var rootA = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, ownerA, "https://a.example/explicit-scope");
        var rootB = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, ownerB, "https://b.example/explicit-scope");
        var signedByB = await _signingService.SignRevocationAsync(rootB.Id, ownerB, rootB.InvocationTarget);

        (await _verifier.RevokeCapabilityAsync(rootB, signedByB, rootA)).Should().BeFalse(
            "a root may be revoked through the explicit-root overload only when it IS the explicit root");
        (await _verifier.IsCapabilityRevokedAsync(rootB.Id)).Should().BeFalse();

        var retry = await _signingService.SignRevocationAsync(rootB.Id, ownerB, rootB.InvocationTarget);
        (await _verifier.RevokeCapabilityAsync(rootB, retry, rootB)).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCapability_ExplicitRootOverload_RefusesUnknownRootShapedIdOtherThanExplicitRoot()
    {
        var owner = _didProvider.GenerateDidKey();
        var rootA = await _capabilityService.CreateRootCapabilityAsync(owner, "https://a.example/explicit-unknown");
        var customRoot = new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "https://custom.example/root-x",
            Controller = owner,
            InvocationTarget = "https://custom.example/resource"
        };
        var verifier = CreateVerifier(new SwitchableRootResolver());
        var signed = await _signingService.SignRevocationAsync(customRoot.Id, owner, customRoot.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(customRoot, signed, rootA)).Should().BeFalse();
        (await verifier.IsCapabilityRevokedAsync(customRoot.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_ExplicitRootOverload_RefusesDelegationUnderADifferentRoot()
    {
        var ownerA = _didProvider.GenerateDidKey();
        var ownerB = _didProvider.GenerateDidKey();
        var rootA = await _capabilityService.CreateRootCapabilityAsync(ownerA, "https://a.example/explicit-delegated");
        var rootB = await _capabilityService.CreateRootCapabilityAsync(ownerB, "https://b.example/explicit-delegated");
        var underB = await _capabilityService.DelegateCapabilityAsync(
            rootB, _didProvider.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(1));
        var signed = await _signingService.SignRevocationAsync(underB.Id, ownerB, underB.InvocationTarget);

        (await CreateVerifier(new SwitchableRootResolver()).RevokeCapabilityAsync(underB, signed, rootA)).Should().BeFalse(
            "the chain must end at the explicit root");
    }

    // ----- Resolver dependency on the explicit-root overload (PR #156 review) -----
    //
    // The revocation path asks a configured resolver whether the id being revoked names a root, even
    // when an explicit root is supplied; skipping that would reopen the borrowed-root-id forgery. A
    // resolver fault fails closed and is retryable. Without a configured resolver nothing is consulted.

    [Fact]
    public async Task RevokeCapability_ExplicitRootOverload_DelegationBorrowingAKnownCustomRootId_FailsAndDoesNotRevoke()
    {
        // A custom root id has no reserved prefix, so only the resolver lookup refuses this forgery. The
        // forged delegation is validly signed under explicit root A and differs from the control only in
        // borrowing victim root B's id (PR #156 review).
        var attacker = _didProvider.GenerateDidKey();
        var rootA = await _capabilityService.CreateRootCapabilityAsync(attacker, "https://attacker.example/explicit-custom");
        var victimRoot = _didProvider.RegisterRoot(new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "https://victim.example/custom-root",
            Controller = _didProvider.GenerateDidKey(),
            InvocationTarget = "https://victim.example/resource"
        });

        async Task<bool> RevokeThroughRootAAsync(string id)
        {
            var delegation = ForgeDelegation(id, attacker, rootA.Id, rootA.InvocationTarget);
            delegation.Proof = await _signingService.SignCapabilityAsync(
                delegation, attacker, "capabilityDelegation", new object[] { rootA.Id });
            var signed = await _signingService.SignRevocationAsync(delegation.Id, attacker, delegation.InvocationTarget);
            return await _verifier.RevokeCapabilityAsync(delegation, signed, rootA);
        }

        var controlId = "urn:uuid:" + Guid.NewGuid();
        (await RevokeThroughRootAAsync(controlId)).Should().BeTrue(
            "the same delegation with an id of its own is genuine and revocable through root A");
        (await _verifier.IsCapabilityRevokedAsync(controlId)).Should().BeTrue();

        (await RevokeThroughRootAAsync(victimRoot.Id)).Should().BeFalse(
            "the resolver knows this id as root B, and the explicit root admits only itself");
        (await _verifier.IsCapabilityRevokedAsync(victimRoot.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_ExplicitRootWithFailingResolver_FailsClosedThenSucceedsOnRetry()
    {
        var owner = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(owner, "https://example.com/resolver-fault");
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, _didProvider.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(1));
        var resolver = new SwitchableRootResolver { Throw = true };
        var verifier = CreateVerifier(resolver);
        var signed = await _signingService.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(delegated, signed, root)).Should().BeFalse(
            "the configured resolver could not say whether the id names a trusted root");
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeFalse();
        resolver.Calls.Should().Contain(delegated.Id, "the leaf id is looked up even with an explicit root");

        resolver.Throw = false;
        (await verifier.RevokeCapabilityAsync(delegated, signed, root)).Should().BeTrue(
            "nothing was recorded and the nonce was not consumed, so the same request succeeds on retry");
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCapability_ExplicitRootWithoutConfiguredResolver_DelegatedRevocationSucceeds()
    {
        var owner = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(owner, "https://example.com/no-resolver");
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, _didProvider.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(1));
        // The DID resolver is wrapped so it is not also an IRootCapabilityResolver: no resolver at all.
        var verifier = new VerificationService(new KeyOnlyDidResolver(_didProvider),
            new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
            relationshipResolver: _didProvider);
        var signed = await _signingService.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(delegated, signed, root)).Should().BeTrue();
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    // ----- Equivalent spellings of a root id (second adversarial pass) -----

    [Fact]
    public async Task RevokeCapability_RecasedRootPrefixUnderCaseInsensitiveStore_FailsAndDoesNotRevokeTheRoot()
    {
        // URN:ZCAP:ROOT:… is the reserved form in another casing (RFC 8141). The resolver does not know
        // that exact string, but a store keyed case-insensitively would file it under root B.
        var ownerA = _didProvider.GenerateDidKey();
        var ownerB = _didProvider.GenerateDidKey();
        var holder = _didProvider.GenerateDidKey();
        var rootA = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, ownerA, "https://a.example/recased");
        var rootB = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, ownerB, "https://b.example/recased");
        var delegation = await _capabilityService.DelegateCapabilityAsync(
            rootA, holder, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        var store = new CaseInsensitiveRevocationStore();
        var verifier = new VerificationService(_didProvider, new RevocationService(store), new InMemoryNonceStore(),
            relationshipResolver: _didProvider, rootResolver: _didProvider);

        var recasedId = "URN:ZCAP:ROOT:" + rootB.Id["urn:zcap:root:".Length..];
        var forged = ForgeDelegation(recasedId, holder, delegation.Id, delegation.InvocationTarget, new[] { "read" });
        // SigningService refuses a non-normalized id, so sign as an attacker's own signer would.
        forged.Proof = await RawProofSigner.SignCapabilityAsync(
            _didProvider, forged, holder, new object[] { rootA.Id, delegation });

        var request = await _signingService.SignRevocationAsync(forged.Id, holder, forged.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(forged, request)).Should().BeFalse();
        var explicitRequest = await _signingService.SignRevocationAsync(forged.Id, holder, forged.InvocationTarget);
        (await verifier.RevokeCapabilityAsync(forged, explicitRequest, rootA)).Should().BeFalse();

        (await verifier.IsCapabilityRevokedAsync(rootB.Id)).Should().BeFalse();
        store.Count.Should().Be(0);
    }

    [Fact]
    public async Task RevokeCapability_ResolverReturningOneRootForAnyId_DelegatedRevocationSucceeds()
    {
        // A resolver that ignores the requested id answers "not a root" for a delegated id; the chain's
        // own root lookup still binds by id.
        var owner = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(owner, "https://example.com/single-root");
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, _didProvider.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(1));
        var verifier = CreateVerifier(new SingleRootResolver(root));
        var signed = await _signingService.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(delegated, signed)).Should().BeTrue();
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    private sealed class SingleRootResolver(Capability root) : IRootCapabilityResolver
    {
        public Task<Capability?> ResolveRootAsync(string rootCapabilityId) => Task.FromResult<Capability?>(root);
    }

    /// <summary>Models a backend with a case-insensitive key (e.g. a default SQL Server collation).</summary>
    private sealed class CaseInsensitiveRevocationStore : IRevocationStore
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, RevocationRecord> _records =
            new(StringComparer.OrdinalIgnoreCase);

        public int Count => _records.Count;

        public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
        {
            _records[record.CapabilityId] = record;
            return Task.CompletedTask;
        }

        public Task<RevocationRecord?> GetByCapabilityIdAsync(string capabilityId, CancellationToken cancellationToken = default)
            => Task.FromResult(_records.TryGetValue(capabilityId, out var r) ? r : null);

        public Task DeleteAsync(string capabilityId, CancellationToken cancellationToken = default)
        {
            _records.TryRemove(capabilityId, out _);
            return Task.CompletedTask;
        }
    }

    private VerificationService CreateVerifier(IRootCapabilityResolver rootResolver)
        => new(_didProvider, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
            relationshipResolver: _didProvider, rootResolver: rootResolver);

    /// <summary>Knows no roots; can be switched to throw, and records every id it was asked about.</summary>
    private sealed class SwitchableRootResolver : IRootCapabilityResolver
    {
        public bool Throw { get; set; }
        public List<string> Calls { get; } = new();

        public Task<Capability?> ResolveRootAsync(string rootCapabilityId)
        {
            Calls.Add(rootCapabilityId);
            return Throw
                ? throw new InvalidOperationException("root resolver unavailable")
                : Task.FromResult<Capability?>(null);
        }
    }

    /// <summary>Delegates key resolution only, so the verifier finds no root resolver on it.</summary>
    private sealed class KeyOnlyDidResolver(IDidResolver inner) : IDidResolver
    {
        public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
            => inner.ResolvePublicKeyAsync(didOrVerificationMethod);

        public Task<string> GetVerificationMethodAsync(string did) => inner.GetVerificationMethodAsync(did);
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
