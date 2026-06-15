using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Proof <c>created</c> freshness on the invocation and signed-revocation verify paths (Issue #71).
/// A captured invocation must not re-verify once its nonce entry has evicted (or when replay protection
/// is the no-op opt-out), so the verifier rejects a proof whose <c>created</c> is missing, future-dated
/// beyond the clock-skew tolerance, or older than the replay window. Each case signs a fully valid proof
/// over the chosen <c>created</c> (via the determinism overload of <c>SignInvocationAsync</c>/
/// <c>SignRevocationAsync</c>), so every rejection is attributable to freshness alone, not the signature.
/// </summary>
public class VerificationServiceFreshnessTests
{
    private const string Target = "https://example.com/resource";
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor = new();

    public VerificationServiceFreshnessTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService CreateVerificationService(INonceStore nonceStore, TimeSpan? freshnessClockSkew = null)
        => new(
            _didProvider, _caveatProcessor,
            new RevocationService(new InMemoryRevocationStore()),
            nonceStore, nonceWindow: null, freshnessClockSkew: freshnessClockSkew);

    // Builds a root + delegated capability and signs a delegated DI invocation whose proof carries the
    // supplied created instant (null => stamp current UTC time). The target is parameterized so a single
    // test can register more than one root without an id collision (root id derives from the target).
    // Returns the invocation and the delegated capability it is verified against.
    private async Task<(Invocation invocation, Capability capability)> CreateSignedInvocationAsync(
        DateTime? createdOverride, string target = Target)
    {
        var rootDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();

        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid, createdOverride);
        return (invocation, delegated);
    }

    // ─────────────────────────── Invocation path ───────────────────────────

    [Fact]
    public async Task VerifyInvocation_FreshCreated_Verifies()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var (invocation, capability) = await CreateSignedInvocationAsync(createdOverride: null);

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.Valid, "a freshly-created invocation must verify");
    }

    [Fact]
    public async Task VerifyInvocation_StaleCreated_IsRejected()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        // 10 minutes old — older than the default 5-minute replay window, but otherwise fully valid.
        var (invocation, capability) = await CreateSignedInvocationAsync(DateTime.UtcNow.AddMinutes(-10));

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.StaleProof,
            "a proof older than the replay window must be rejected even though its signature is valid");
    }

    [Fact]
    public async Task VerifyInvocation_FutureBeyondSkew_IsRejected()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        // 10 minutes in the future — well beyond the 1-minute clock-skew tolerance.
        var (invocation, capability) = await CreateSignedInvocationAsync(DateTime.UtcNow.AddMinutes(10));

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.StaleProof,
            "a proof dated beyond the clock-skew tolerance must be rejected");
    }

    [Fact]
    public async Task VerifyInvocation_FutureWithinSkew_Verifies()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        // 30 seconds in the future — within the 1-minute clock-skew tolerance.
        var (invocation, capability) = await CreateSignedInvocationAsync(DateTime.UtcNow.AddSeconds(30));

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.Valid,
            "a slightly-future proof within the clock-skew tolerance must still verify");
    }

    [Fact]
    public async Task VerifyInvocation_FutureProof_HonorsConfiguredClockSkew()
    {
        // 90 seconds in the future: beyond the default 1-minute skew, but within a configured 2-minute one.
        // Distinct targets keep the two roots from colliding (a root id derives from its invocationTarget).
        var created = DateTime.UtcNow.AddSeconds(90);

        var defaultVerifier = CreateVerificationService(new InMemoryNonceStore());
        var (inv1, cap1) = await CreateSignedInvocationAsync(created, "https://example.com/resource-a");
        (await defaultVerifier.VerifyInvocationDetailedAsync(inv1, cap1)).Outcome
            .Should().Be(VerificationOutcome.StaleProof, "the default 1-minute skew rejects a +90s proof");

        var widerVerifier = CreateVerificationService(new InMemoryNonceStore(), TimeSpan.FromMinutes(2));
        var (inv2, cap2) = await CreateSignedInvocationAsync(created, "https://example.com/resource-b");
        (await widerVerifier.VerifyInvocationDetailedAsync(inv2, cap2)).Outcome
            .Should().Be(VerificationOutcome.Valid, "a configured 2-minute clock-skew tolerance accepts a +90s proof");
    }

    [Fact]
    public async Task VerifyInvocation_NullCreated_IsRejected()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var (invocation, capability) = await CreateSignedInvocationAsync(createdOverride: null);
        // Drop the created timestamp. The freshness gate runs before signature verification, so the
        // missing timestamp is the operative (and fail-closed) rejection reason.
        invocation.Proof!.Created = null;

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.StaleProof,
            "an invocation proof without a created timestamp must fail closed");
    }

    [Fact]
    public async Task VerifyInvocation_StaleCreated_RejectedEvenWithNullNonceStore()
    {
        // Replay protection disabled (the no-op opt-out, audit ref M5): freshness must STILL bound replay.
        var verifier = CreateVerificationService(NullNonceStore.Instance);
        var (invocation, capability) = await CreateSignedInvocationAsync(DateTime.UtcNow.AddMinutes(-10));

        var result = await verifier.VerifyInvocationDetailedAsync(invocation, capability);

        result.Outcome.Should().Be(VerificationOutcome.StaleProof,
            "freshness must reject a stale invocation even when the nonce store is the no-op opt-out");
    }

    // ─────────────────────────── Revocation path ───────────────────────────

    [Fact]
    public async Task RevokeCapability_FreshCreated_Succeeds()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var rootDid = _didProvider.GenerateDidKey();
        var childDid = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(rootDid, Target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        // Self-revoke: the leaf's own controller signs; authorization walks the chain.
        var signed = await _signingService.SignRevocationAsync(delegated.Id, childDid, delegated.InvocationTarget);

        var revoked = await verifier.RevokeCapabilityAsync(delegated, signed, root);

        revoked.Should().BeTrue("a freshly-signed revocation must be accepted");
    }

    [Fact]
    public async Task RevokeCapability_StaleCreated_IsRejected()
    {
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var rootDid = _didProvider.GenerateDidKey();
        var childDid = _didProvider.GenerateDidKey();
        var root = await _capabilityService.CreateRootCapabilityAsync(rootDid, Target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        // Valid signature, but the request is 10 minutes old — older than the replay window.
        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, childDid, delegated.InvocationTarget,
            reason: null, metadata: null, createdOverride: DateTime.UtcNow.AddMinutes(-10));

        var revoked = await verifier.RevokeCapabilityAsync(delegated, signed, root);

        revoked.Should().BeFalse("a stale signed revocation must be rejected by the freshness gate");
    }
}
