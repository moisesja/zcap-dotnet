using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Delegation-proof <c>created</c> soundness on the verify paths (Issue #99). A delegation proof never
/// had its <c>created</c> inspected, so it could claim any value — future-dated, or unparseable — and
/// still verify. Unlike the invocation/revocation freshness check (Issue #71), a delegation proof is
/// <b>durable</b>: there is deliberately NO staleness lower-bound, so a capability delegated months ago
/// must still verify until it <c>expires</c>. The future-dated and unparseable checks are always on; the
/// missing-<c>created</c> check is opt-in (<see cref="VerificationPolicy.RequireDelegationProofCreated"/>)
/// to preserve durable/cross-stack delegations that legitimately omit it. The check is skipped on the
/// revocation-authorization path so a malformed-<c>created</c> delegation stays revocable.
/// </summary>
public class VerificationServiceDelegationFreshnessTests
{
    private const string Target = "https://example.com/resource";
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor = new();

    public VerificationServiceDelegationFreshnessTests()
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

    // Root + first-level delegated capability with an explicit `expires`. The root is registered so the
    // verifier resolves the spec-exact (root-by-id) chain. The target is parameterized so each test gets
    // a distinct root id (root id derives from the target) and roots never collide across tests.
    private async Task<(Capability root, Capability delegated, string childDid)> CreateChainAsync(
        DateTime delegatedExpires, string target = Target)
    {
        var rootDid = _didProvider.GenerateDidKey();
        var childDid = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, delegatedExpires);
        return (root, delegated, childDid);
    }

    // Re-signs the delegation proof with a chosen `created` instant, producing a FULLY VALID signature
    // over that instant (created is part of the signed canonical bytes, so a future/old value cannot be
    // faked by post-signing mutation). The delegation proof is signed by the parent (here, the root)
    // controller, so the re-signature is authorized exactly as the original was.
    private async Task ResignDelegationCreatedAsync(Capability root, Capability delegated, DateTime created)
    {
        var signer = root.Controller!.Primary;
        delegated.Proof = await _signingService.SignCapabilityAsync(
            delegated, signer, Proof.CapabilityDelegationPurpose,
            delegated.Proof!.Primary.CapabilityChain, created);
    }

    // ─────────────────── future-dated `created` (always on) ───────────────────

    [Fact]
    public async Task VerifyChain_DelegationCreatedInFutureBeyondSkew_Rejected()
    {
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7));
        await ResignDelegationCreatedAsync(root, delegated, DateTime.UtcNow.AddMinutes(10));

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.InvalidProofTime,
            "a validly-signed delegation proof dated 10 minutes in the future exceeds the clock skew");
    }

    [Fact]
    public async Task VerifyCapabilityProof_DelegationCreatedInFutureBeyondSkew_Rejected()
    {
        // The standalone single-proof path must reject it identically to the chain path.
        var target = "https://example.com/resource-standalone";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        await ResignDelegationCreatedAsync(root, delegated, DateTime.UtcNow.AddMinutes(10));

        var result = await CreateVerifier().VerifyCapabilityProofDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.InvalidProofTime,
            "the standalone VerifyCapabilityProof path enforces the #99 created check too");
    }

    [Fact]
    public async Task VerifyChain_DelegationCreatedWithinSkew_Verifies()
    {
        // 30 seconds ahead is within the default 1-minute clock-skew tolerance.
        var target = "https://example.com/resource-skew";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        await ResignDelegationCreatedAsync(root, delegated, DateTime.UtcNow.AddSeconds(30));

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.Valid,
            "a created within the clock-skew tolerance is fresh; the future check is skew-tolerant");
    }

    // ─────────────────── NO staleness lower-bound (regression guard) ───────────────────

    [Fact]
    public async Task VerifyChain_OldButUnexpiredDelegation_StillVerifies()
    {
        // The whole reason #99 cannot reuse #71's bound: a delegation signed 90 days ago (far past any
        // nonce/replay window) but not yet expired MUST still verify. If a future refactor imported a
        // staleness lower-bound onto the delegation path, this test would fail.
        var target = "https://example.com/resource-old";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(30), target);
        await ResignDelegationCreatedAsync(root, delegated, DateTime.UtcNow.AddDays(-90));

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.Valid,
            "a durable delegation signed long ago must verify until it expires — there is no lower-bound");
    }

    // ─────────────────── unparseable `created` (always on) ───────────────────

    [Fact]
    public async Task VerifyChain_DelegationCreatedUnparseable_AlwaysRejected()
    {
        // A present-but-garbage timestamp is provably malformed, so it is rejected even under the default
        // policy. The gate reads the RAW string and parses defensively, so the reason is InvalidProofTime
        // (not InvalidDelegation, which is what the per-proof catch would have produced from the throw).
        var target = "https://example.com/resource-garbage";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        delegated.Proof!.Primary.Created = "not-a-timestamp";

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.InvalidProofTime,
            "a present-but-unparseable created is always rejected, with a precise reason");
    }

    // ─────────────────── missing `created` (opt-in) ───────────────────

    [Fact]
    public async Task VerifyChain_DelegationCreatedMissing_PolicyOn_Rejected()
    {
        var target = "https://example.com/resource-missing-on";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        delegated.Proof!.Primary.Created = null;

        var verifier = CreateVerifier(new VerificationPolicy { RequireDelegationProofCreated = true });
        var result = await verifier.VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.InvalidProofTime,
            "with the opt-in policy on, a delegation proof that omits created is rejected");
    }

    [Fact]
    public async Task VerifyChain_DelegationCreatedMissing_DefaultPolicy_NotRejectedByCreatedGate()
    {
        // Backwards-compat: by default a delegation that omits created is NOT rejected by the #99 gate
        // (durable/cross-stack delegations may legitimately lack it). We null the field post-signing, so
        // the signature no longer matches; the salient point is that verification proceeds PAST the
        // created gate — the outcome is InvalidSignature, never InvalidProofTime. The sibling policy-on
        // test (same mutation → InvalidProofTime) proves the gate is the only behavioural difference.
        var target = "https://example.com/resource-missing-off";
        var (root, delegated, _) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        delegated.Proof!.Primary.Created = null;

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(delegated, root);

        result.Outcome.Should().Be(VerificationOutcome.InvalidSignature,
            "default policy does not reject a missing created as InvalidProofTime; the gate is bypassed");
    }

    // ─────────────────── single-link vs full-chain scope boundary ───────────────────

    [Fact]
    public async Task VerifyCapabilityProof_DeepChain_GatesLeafOnly_ChainPathGatesEveryLink()
    {
        // Scope boundary (Issue #99 review): the standalone single-link VerifyCapabilityProof path checks
        // only the LEAF proof's created — by design it never independently verifies an intermediate
        // ancestor's own proof (its signature OR its created), the same way it already skips ancestor
        // signatures. Full-ancestry temporal soundness is the chain path's job. This pins that boundary so
        // it stays intentional rather than an accidental gap.
        var target = "https://example.com/resource-deep";
        var rootDid = _didProvider.GenerateDidKey();
        var midDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();

        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        // Future-date the INTERMEDIATE link's created (validly re-signed by the root controller) BEFORE
        // delegating the leaf, so the leaf embeds and signs over the future-dated mid.
        mid.Proof = await _signingService.SignCapabilityAsync(
            mid, rootDid, Proof.CapabilityDelegationPurpose,
            mid.Proof!.Primary.CapabilityChain, DateTime.UtcNow.AddMinutes(10));
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            mid, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var verifier = CreateVerifier();

        // Single-link path: the leaf's own created is fresh, so it verifies — the intermediate's
        // future-dated created is out of this path's scope (so is the intermediate's signature).
        (await verifier.VerifyCapabilityProofDetailedAsync(leaf, root)).Outcome
            .Should().Be(VerificationOutcome.Valid,
                "the single-link path checks only the leaf proof's created, not an intermediate's");

        // Full-chain path: gates EVERY non-root link, so the intermediate's future-dated created is caught.
        (await verifier.VerifyCapabilityChainDetailedAsync(leaf, root)).Outcome
            .Should().Be(VerificationOutcome.InvalidProofTime,
                "the chain path gates every delegated link's created — use it for full-ancestry soundness");
    }

    // ─────────────────── revocation carve-out ───────────────────

    [Fact]
    public async Task RevokeCapability_FutureDatedDelegationCreated_StillRevocable()
    {
        // A delegation with a malformed (future-dated) created must stay REVOCABLE: refusing to authorize
        // its removal would be backwards (you especially want to cancel suspect capabilities). The
        // revocation-authorization path passes applyCreatedCheck: false. The same delegation is rejected
        // on the normal verify path (InvalidProofTime), which is exactly why the carve-out matters.
        var target = "https://example.com/resource-revoke-created";
        var (root, delegated, childDid) = await CreateChainAsync(DateTime.UtcNow.AddDays(7), target);
        await ResignDelegationCreatedAsync(root, delegated, DateTime.UtcNow.AddMinutes(10));
        var verifier = CreateVerifier();

        // Sanity: the normal verify path DOES reject the future-dated delegation created.
        (await verifier.VerifyCapabilityChainDetailedAsync(delegated, root)).Outcome
            .Should().Be(VerificationOutcome.InvalidProofTime,
                "the verify path enforces the #99 created check");

        // Self-revoke: the leaf's own controller signs; authorization walks the chain.
        var signed = await _signingService.SignRevocationAsync(delegated.Id, childDid, delegated.InvocationTarget);
        var revoked = await verifier.RevokeCapabilityAsync(delegated, signed, root);

        revoked.Should().BeTrue(
            "a delegation with a malformed created must remain revocable (created check is off on revoke)");
        (await verifier.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }
}
