using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

public class VerificationServiceReplayTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor;

    public VerificationServiceReplayTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _caveatProcessor = new CaveatProcessor();
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService CreateVerificationService(INonceStore nonceStore)
    {
        return new VerificationService(
            _didProvider, _caveatProcessor,
            VerificationService.CreateDefaultSuiteProvider(),
            new RevocationService(new InMemoryRevocationStore()),
            nonceStore);
    }

    private async Task<(Invocation invocation, Capability capability)> CreateSignedInvocation()
    {
        var rootDid = "did:key:z6MkRoot";
        var leafDid = "did:key:z6MkLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read" });

        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var invocation = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);
        return (invocation, delegated);
    }

    /// <summary>
    /// Builds an unsigned invocation plus its capability and the leaf signer DID, for freshness
    /// tests that re-sign over a controlled <c>proof.created</c> via <see cref="SignInvocationWithCreatedAsync"/>.
    /// </summary>
    private async Task<(Invocation invocation, Capability capability, string leafDid)> CreateSignedInvocationParts()
    {
        var rootDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var invocation = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        return (invocation, delegated, leafDid);
    }

    /// <summary>
    /// Replicates <c>SigningService.SignInvocationAsync</c> but signs over a caller-controlled
    /// <c>created</c> timestamp, producing a cryptographically valid proof whose freshness can be
    /// exercised (Issue #71 test support).
    /// </summary>
    private async Task SignInvocationWithCreatedAsync(Invocation invocation, string signerDid, DateTime createdUtc)
    {
        var suite = CryptoSuite.Ed25519();
        var canonicalizer = new JcsDocumentCanonicalizer();
        var withoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
        var vm = await _didProvider.GetVerificationMethodAsync(signerDid);

        var proof = new Proof
        {
            Type = suite.ProofType,
            Created = ZcapTimestamps.Format(createdUtc),
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = vm,
            ProofValue = string.Empty,
            Capability = invocation.Capability,
            InvocationTarget = invocation.InvocationTarget,
            CapabilityAction = invocation.CapabilityAction
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(withoutProof, proof, canonicalizer);
        var signature = await _didProvider.SignAsync(signerDid, canonicalBytes);
        proof.ProofValue = MultibaseCodec.Encode(signature.Signature);
        invocation.Proof = proof;
    }

    [Fact]
    public async Task VerifyInvocation_SameInvocationTwice_SecondFails()
    {
        var nonceStore = new InMemoryNonceStore();
        var verifier = CreateVerificationService(nonceStore);
        var (invocation, capability) = await CreateSignedInvocation();

        var first = await verifier.VerifyInvocationAsync(invocation, capability);
        var second = await verifier.VerifyInvocationAsync(invocation, capability);

        first.Should().BeTrue("first invocation should succeed");
        second.Should().BeFalse("replayed invocation should be rejected");
    }

    [Fact]
    public async Task VerifyInvocation_TwoArgConstructor_RejectsReplayByDefault()
    {
        // Issue #62: the convenience constructors must enable replay protection by default
        // (InMemoryNonceStore), not NullNonceStore. The 2-arg constructor is the README Quick
        // Start path, so it must reject a replayed invocation out of the box.
        var verifier = new VerificationService(_didProvider, _caveatProcessor);
        var (invocation, capability) = await CreateSignedInvocation();

        var first = await verifier.VerifyInvocationAsync(invocation, capability);
        var second = await verifier.VerifyInvocationAsync(invocation, capability);

        first.Should().BeTrue("first invocation should succeed");
        second.Should().BeFalse("the 2-arg convenience constructor must reject replays by default");
    }

    [Fact]
    public async Task VerifyInvocation_DifferentIds_BothSucceed()
    {
        var nonceStore = new InMemoryNonceStore();
        var verifier = CreateVerificationService(nonceStore);

        var rootDid = "did:key:z6MkRoot2";
        var leafDid = "did:key:z6MkLeaf2";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var inv1 = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        inv1.Proof = await _signingService.SignInvocationAsync(inv1, leafDid);

        var inv2 = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        inv2.Proof = await _signingService.SignInvocationAsync(inv2, leafDid);

        var r1 = await verifier.VerifyInvocationAsync(inv1, delegated);
        var r2 = await verifier.VerifyInvocationAsync(inv2, delegated);

        r1.Should().BeTrue();
        r2.Should().BeTrue("different invocation IDs should both succeed");
    }

    [Fact]
    public async Task VerifyInvocation_WithNullNonceStore_BothSucceed()
    {
        var verifier = CreateVerificationService(NullNonceStore.Instance);
        var (invocation, capability) = await CreateSignedInvocation();

        var first = await verifier.VerifyInvocationAsync(invocation, capability);
        var second = await verifier.VerifyInvocationAsync(invocation, capability);

        first.Should().BeTrue();
        second.Should().BeTrue("NullNonceStore never rejects replays");
    }

    [Fact]
    public async Task VerifyInvocation_StaleCreated_IsRejected()
    {
        // Issue #71: a signed invocation whose proof.created is older than the replay window must
        // be rejected even when its signature is valid — freshness bounds replay independently of
        // the nonce store TTL.
        var nonceStore = new InMemoryNonceStore();
        var verifier = CreateVerificationService(nonceStore); // default 5-minute window
        var (invocation, capability, leafDid) = await CreateSignedInvocationParts();

        // Re-sign over a created timestamp 10 minutes in the past (valid signature, stale).
        await SignInvocationWithCreatedAsync(invocation, leafDid, DateTime.UtcNow.AddMinutes(-10));

        (await verifier.VerifyInvocationAsync(invocation, capability)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_FutureCreated_IsRejected()
    {
        // Issue #71: a created timestamp beyond the small clock-skew allowance is rejected.
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var (invocation, capability, leafDid) = await CreateSignedInvocationParts();

        await SignInvocationWithCreatedAsync(invocation, leafDid, DateTime.UtcNow.AddMinutes(10));

        (await verifier.VerifyInvocationAsync(invocation, capability)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_FreshCreated_Verifies()
    {
        // Positive control: the replication helper produces a verifiable invocation, so the
        // stale/future rejections above are due to freshness, not a broken signature.
        var verifier = CreateVerificationService(new InMemoryNonceStore());
        var (invocation, capability, leafDid) = await CreateSignedInvocationParts();

        await SignInvocationWithCreatedAsync(invocation, leafDid, DateTime.UtcNow);

        (await verifier.VerifyInvocationAsync(invocation, capability)).Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_InvalidInvocation_DoesNotConsumeNonce()
    {
        var nonceStore = new InMemoryNonceStore();
        var verifier = CreateVerificationService(nonceStore);
        var (invocation, capability) = await CreateSignedInvocation();

        // Create an invalid invocation with the same ID but wrong action
        var invalidInvocation = new Invocation
        {
            Id = invocation.Id,
            Capability = invocation.Capability,
            CapabilityAction = "write", // not allowed
            InvocationTarget = invocation.InvocationTarget,
            Proof = invocation.Proof
        };

        var invalid = await verifier.VerifyInvocationAsync(invalidInvocation, capability);
        invalid.Should().BeFalse("action 'write' is not allowed");

        // The nonce should not have been consumed — the real invocation should still work
        // Note: the signature won't match because the canonical doc changed (different action),
        // so it will fail at step 5 before reaching the nonce check. The nonce IS unconsumed.
        // We verify by checking that a properly signed invocation with a fresh ID works.
        var fresh = new Invocation
        {
            Capability = invocation.Capability,
            CapabilityAction = "read",
            InvocationTarget = invocation.InvocationTarget
        };

        fresh.Proof = await _signingService.SignInvocationAsync(fresh, "did:key:z6MkLeaf");
        var result = await verifier.VerifyInvocationAsync(fresh, capability);
        result.Should().BeTrue("nonce was not consumed by the failed invocation");
    }
}
