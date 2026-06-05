using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Opt-in verifier-side 3-month delegated-expiration ceiling (Issue #73): the W3C ZCAP-LD SHOULD that
/// "a verifier SHOULD ensure that an invoked delegated zcap does not have an expiration date-time more
/// than three months in the future." It is measured at verification time and gated behind
/// <see cref="VerificationPolicy.EnforceMaxDelegationExpiration"/> (off by default, since it is a SHOULD
/// and can reject legitimately long-lived delegations). These tests pin: the invocation path enforces it
/// (the spec's "invoked" zcap); the revocation path deliberately does NOT (a long-lived delegation must
/// stay revocable); and <see cref="VerificationPolicy.MaxDelegationExpirationMonths"/> is honored.
/// </summary>
public class VerificationServicePolicyTests
{
    private const string Target = "https://example.com/resource";
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor = new();

    public VerificationServicePolicyTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService CreateVerifier(VerificationPolicy? policy = null)
        => new(
            _didProvider, _caveatProcessor,
            VerificationService.CreateDefaultSuiteProvider(),
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(),
            SigningService.CreateDefaultCanonicalizerProvider(),
            policy: policy);

    // Root + delegated capability whose expiration is `expires` out. The root is registered so the
    // verifier resolves the spec-exact (root-by-id) chain. The target is parameterized so each test gets
    // a distinct root id (root id derives from the target) and roots never collide across tests.
    private async Task<(Capability root, Capability delegated, string childDid)> CreateChainAsync(
        DateTime expires, string target = Target)
    {
        var rootDid = _didProvider.GenerateDidKey();
        var childDid = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, expires);
        return (root, delegated, childDid);
    }

    private async Task<Invocation> SignInvocationAsync(Capability delegated, string childDid, string target)
    {
        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, childDid);
        return invocation;
    }

    [Fact]
    public async Task VerifyInvocation_ExpirationBeyondCeiling_PolicyOff_Verifies()
    {
        var (_, delegated, childDid) = await CreateChainAsync(DateTime.UtcNow.AddMonths(6));
        var invocation = await SignInvocationAsync(delegated, childDid, Target);

        var result = await CreateVerifier().VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.Valid,
            "the 3-month ceiling is a SHOULD and is off by default");
    }

    [Fact]
    public async Task VerifyInvocation_ExpirationBeyondCeiling_PolicyOn_Rejected()
    {
        var target = "https://example.com/resource-inv";
        var (_, delegated, childDid) = await CreateChainAsync(DateTime.UtcNow.AddMonths(6), target);
        var invocation = await SignInvocationAsync(delegated, childDid, target);

        var verifier = CreateVerifier(new VerificationPolicy { EnforceMaxDelegationExpiration = true });
        var result = await verifier.VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.ExpirationTooFarInFuture,
            "the spec's SHOULD targets an *invoked* delegated zcap; with the policy on it is rejected");
    }

    [Fact]
    public async Task RevokeCapability_ExpirationBeyondCeiling_PolicyOn_StillSucceeds()
    {
        // The ceiling must NOT block revocation: refusing to authorize removal of a long-lived
        // delegation would be exactly backwards (revocation is the storage-burden mitigation the
        // ceiling exists to bound). The revocation path passes applyExpirationCeiling: false.
        var target = "https://example.com/resource-revoke";
        var (root, delegated, childDid) = await CreateChainAsync(DateTime.UtcNow.AddMonths(6), target);
        var verifier = CreateVerifier(new VerificationPolicy { EnforceMaxDelegationExpiration = true });

        // Self-revoke: the leaf's own controller signs; authorization walks the chain.
        var signed = await _signingService.SignRevocationAsync(delegated.Id, childDid, delegated.InvocationTarget);
        var revoked = await verifier.RevokeCapabilityAsync(delegated, signed, root);

        revoked.Should().BeTrue(
            "a long-lived delegation must remain revocable even when the expiration-ceiling policy is on");
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task VerifyChain_CustomCeiling_PolicyOn_RespectsConfiguredMonths()
    {
        // MaxDelegationExpirationMonths is configurable: a 1-month ceiling rejects a 2-month delegation
        // but admits a ~2-week one.
        var target = "https://example.com/resource-custom";
        var (root, twoMonths, childDid) = await CreateChainAsync(DateTime.UtcNow.AddMonths(2), target);
        var verifier = CreateVerifier(new VerificationPolicy
        {
            EnforceMaxDelegationExpiration = true,
            MaxDelegationExpirationMonths = 1
        });

        (await verifier.VerifyCapabilityChainDetailedAsync(twoMonths, root)).Outcome
            .Should().Be(VerificationOutcome.ExpirationTooFarInFuture,
                "2 months exceeds the configured 1-month ceiling");

        var shortLived = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(14));
        (await verifier.VerifyCapabilityChainDetailedAsync(shortLived, root)).IsValid
            .Should().BeTrue("two weeks is within the configured 1-month ceiling");
    }

    [Fact]
    public async Task VerifyChain_LongLivedIntermediate_PolicyOn_Rejected()
    {
        // Per-link, not leaf-only: a long-lived INTERMEDIATE link is rejected even when the invoked
        // leaf is well within the ceiling. The verifier stores every link's revocation until it
        // expires, so the storage-burden bound must hold for the whole chain (and under attenuation the
        // ancestors are the longest-lived links).
        var target = "https://example.com/resource-multilink";
        var rootDid = _didProvider.GenerateDidKey();
        var midDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddMonths(6));   // long-lived intermediate
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            mid, leafDid, new[] { "read" }, DateTime.UtcNow.AddMonths(1));   // short-lived invoked leaf

        var verifier = CreateVerifier(new VerificationPolicy { EnforceMaxDelegationExpiration = true });
        var result = await verifier.VerifyCapabilityChainDetailedAsync(leaf, root);

        result.Outcome.Should().Be(VerificationOutcome.ExpirationTooFarInFuture,
            "a long-lived intermediate link exceeds the ceiling even though the invoked leaf does not");
    }

    [Fact]
    public async Task VerifyChain_DelegatedWithoutExpires_PolicyOn_Rejected_OffVerifies()
    {
        // A delegated zcap with NO `expires` is unbounded — strictly worse for the storage burden the
        // ceiling caps. The policy treats "missing" as "infinitely far out" and rejects it, so omitting
        // `expires` cannot trivially defeat the feature. Default-off keeps verifying it (no regression).
        var target = "https://example.com/resource-noexpires";
        var rootDid = _didProvider.GenerateDidKey();
        var childDid = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        // Delegating from the (expiry-less) root without an `expires` argument inherits no expiration.
        var delegated = await _capabilityService.DelegateCapabilityAsync(root, childDid, new[] { "read" });
        delegated.ExpiresAt.Should().BeNull("test setup: the delegated zcap must carry no expiration");

        var strict = CreateVerifier(new VerificationPolicy { EnforceMaxDelegationExpiration = true });
        (await strict.VerifyCapabilityChainDetailedAsync(delegated, root)).Outcome
            .Should().Be(VerificationOutcome.ExpirationTooFarInFuture,
                "an unbounded (no-expires) delegation is rejected under the ceiling policy");

        (await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root)).IsValid
            .Should().BeTrue("the default verifier does not enforce the ceiling");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Policy_MaxDelegationExpirationMonthsBelowOne_Throws(int months)
    {
        // A misconfigured value ≤ 0 would silently reject every future-dated delegation. Fail fast at
        // construction with a clear error instead (PR #102 review).
        var act = () => new VerificationPolicy { MaxDelegationExpirationMonths = months };

        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("MaxDelegationExpirationMonths");
    }

    [Fact]
    public void Policy_MaxDelegationExpirationMonthsOfOne_IsAccepted()
    {
        var policy = new VerificationPolicy { MaxDelegationExpirationMonths = 1 };
        policy.MaxDelegationExpirationMonths.Should().Be(1);
    }
}
