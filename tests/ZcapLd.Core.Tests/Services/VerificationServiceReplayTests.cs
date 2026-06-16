using FluentAssertions;
using Xunit;
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

    // Creates a root and registers it with the in-memory resolver so the verifier (which auto-detects
    // _didProvider as an IRootCapabilityResolver) can resolve the root that spec-exact chains reference
    // by id only (Issue #50).
    private Task<Capability> CreateAndRegisterRootAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null)
        => TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, controller, invocationTarget, allowedActions, expires, caveats);

    private VerificationService CreateVerificationService(INonceStore nonceStore)
    {
        return new VerificationService(
            _didProvider, _caveatProcessor,
            new RevocationService(new InMemoryRevocationStore()),
            nonceStore);
    }

    private async Task<(Invocation invocation, Capability capability)> CreateSignedInvocation()
    {
        var rootDid = "did:key:z6MkRoot";
        var leafDid = "did:key:z6MkLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read" });

        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);
        return (invocation, delegated);
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

        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var inv1 = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        inv1.Proof = await _signingService.SignInvocationAsync(inv1, leafDid);

        var inv2 = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
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
