using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Verification tests for delegated zcaps whose <c>proof</c> is an array of DI proofs
/// (Issue #48). The verifier must succeed if AT LEAST ONE proof is a valid, authorized
/// <c>capabilityDelegation</c> proof, ignoring non-delegation proofs and tolerating other
/// delegation proofs that fail to verify.
/// </summary>
public class MultiProofVerificationTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly VerificationService _verificationService;

    private const string Target = "https://api.example.com/resource";

    public MultiProofVerificationTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _verificationService = new VerificationService(_didProvider, new CaveatProcessor());
        _capabilityService = new CapabilityService(_signingService);
    }

    // Creates a root and registers it with the in-memory resolver so the verifier (which auto-detects
    // _didProvider as an IRootCapabilityResolver) can resolve the root that spec-exact chains reference
    // by id only (Issue #50).
    private async Task<Capability> CreateAndRegisterRootAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null)
        => _didProvider.RegisterRoot(
            await _capabilityService.CreateRootCapabilityAsync(controller, invocationTarget, allowedActions, expires, caveats));

    private static Proof NonDelegationProof(string verificationMethod) => new()
    {
        Type = "Ed25519Signature2020",
        Created = "2026-01-01T00:00:00.000000Z",
        ProofPurpose = "assertionMethod",
        VerificationMethod = verificationMethod,
        ProofValue = MultibaseCodec.Encode(new byte[64])
    };

    private async Task<(Capability root, Capability delegated, Proof realProof, string alice)> BuildDelegationAsync()
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var root = await CreateAndRegisterRootAsync(alice, Target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, bob, new[] { "read" }, expires: DateTime.UtcNow.AddDays(1));
        return (root, delegated, delegated.Proof!.Primary, alice);
    }

    [Fact]
    public async Task ProofArray_WithValidDelegationProofAmongOthers_Verifies()
    {
        var (_, delegated, realProof, alice) = await BuildDelegationAsync();

        // Valid delegation proof preceded AND followed by unrelated proofs.
        delegated.Proof = ProofSet.FromValues(new[]
        {
            NonDelegationProof(alice + "#assert"),
            realProof,
            NonDelegationProof(alice + "#assert2")
        });

        (await _verificationService.VerifyCapabilityProofAsync(delegated)).Should().BeTrue();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeTrue();
    }

    [Fact]
    public async Task ProofArray_WithNoDelegationProof_Fails()
    {
        var (_, delegated, _, alice) = await BuildDelegationAsync();

        delegated.Proof = ProofSet.FromValues(new[]
        {
            NonDelegationProof(alice + "#assert"),
            NonDelegationProof(alice + "#authn")
        });

        (await _verificationService.VerifyCapabilityProofAsync(delegated)).Should().BeFalse();
    }

    [Fact]
    public async Task ProofArray_InvalidDelegationProofBeforeValidOne_StillVerifies()
    {
        // The load-bearing test for #48: a delegation proof that fails signature verification
        // must not abort evaluation — the verifier keeps trying and succeeds on the valid one.
        var (_, delegated, realProof, _) = await BuildDelegationAsync();

        var badDelegationProof = new Proof
        {
            Type = realProof.Type,
            Created = realProof.Created,
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = realProof.VerificationMethod,
            CapabilityChain = realProof.CapabilityChain,
            ProofValue = MultibaseCodec.Encode(new byte[64]) // valid multibase, wrong signature
        };

        delegated.Proof = ProofSet.FromValues(new[] { badDelegationProof, realProof });

        (await _verificationService.VerifyCapabilityProofAsync(delegated)).Should().BeTrue();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeTrue();
    }

    [Fact]
    public async Task ProofArray_OnlyDelegationProofSignedByNonController_Fails()
    {
        var (root, delegated, _, _) = await BuildDelegationAsync();
        var mallory = _didProvider.GenerateDidKey(); // resolvable key, but not a controller of root

        // A cryptographically valid delegation proof with a spec-exact first-level chain — but signed
        // by a non-controller, so authorization (not chain shape) is the reason it must fail.
        var malloryProof = await _signingService.SignCapabilityAsync(
            delegated, mallory, "capabilityDelegation", new object[] { root.Id });

        delegated.Proof = ProofSet.FromValues(new[] { malloryProof });

        (await _verificationService.VerifyCapabilityProofAsync(delegated)).Should().BeFalse();
    }

    [Fact]
    public async Task ProofArray_OnlyDelegationProofHasNoChain_Fails()
    {
        // Isolate the "missing chain" failure: this delegation proof carries a VALID signature
        // (freshly signed by the authorized delegator over an empty-chain payload) but no usable
        // capabilityChain — so the only reason verification can fail is the absent chain, not a
        // signature mismatch.
        var (_, delegated, _, alice) = await BuildDelegationAsync();

        var chainlessProof = await _signingService.SignCapabilityAsync(
            delegated, alice, "capabilityDelegation", capabilityChain: Array.Empty<object>());
        chainlessProof.CapabilityChain.Should().BeEmpty("the proof is signed without a chain");

        delegated.Proof = ProofSet.FromValues(new[] { chainlessProof });

        (await _verificationService.VerifyCapabilityProofAsync(delegated)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeFalse();
    }
}
