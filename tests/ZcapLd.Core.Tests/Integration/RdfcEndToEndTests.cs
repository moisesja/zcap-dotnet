using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// End-to-end tests for RDFC-1.0 canonicalization through the full
/// signing and verification pipeline: create → delegate → invoke → verify.
/// These tests wire an ICryptoSuite with CanonicalizationMethod = "RDFC-1.0"
/// through SigningService and VerificationService.
/// </summary>
public class RdfcEndToEndTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly VerificationService _verificationService;

    public RdfcEndToEndTests()
    {
        _didProvider = new InMemoryDidProvider();

        var canonicalizerProvider = new DocumentCanonicalizerProvider();
        canonicalizerProvider.Register(new JcsDocumentCanonicalizer());
        canonicalizerProvider.Register(new RdfcDocumentCanonicalizer());

        // Register RDFC Ed25519 suite (last registered wins for same ProofType)
        var suiteProvider = new CryptoSuiteProvider();
        suiteProvider.Register(new RdfcEd25519CryptoSuite());

        _signingService = new SigningService(
            _didProvider, _didProvider, suiteProvider, canonicalizerProvider);

        var caveatProcessor = new CaveatProcessor();
        _verificationService = new VerificationService(
            _didProvider, caveatProcessor, suiteProvider,
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), canonicalizerProvider);

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

    [Fact]
    public async Task CreateRootAndInvoke_WithRdfc_ShouldSucceed()
    {
        var controllerDid = "did:key:z6MkRdfcController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var root = await CreateAndRegisterRootAsync(
            controllerDid,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        var isValid = await _verificationService.VerifyInvocationAsync(invocation, root);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task SingleLevelDelegation_WithRdfc_ShouldSucceed()
    {
        var ownerDid = "did:key:z6MkRdfcOwner";
        var delegateDid = "did:key:z6MkRdfcDelegate";
        _didProvider.GenerateAndRegisterKeyPair(ownerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegateDid);

        var root = await CreateAndRegisterRootAsync(
            ownerDid,
            "https://storage.example.com/rdfc-documents",
            new[] { "read", "write" });

        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, delegateDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(7));

        // Verify chain
        var chainValid = await _verificationService.VerifyCapabilityChainAsync(delegated);
        chainValid.Should().BeTrue();

        // Invoke and verify
        var invocation = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://storage.example.com/rdfc-documents"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegateDid);

        var invocationValid = await _verificationService.VerifyInvocationAsync(invocation, delegated);
        invocationValid.Should().BeTrue();
    }

    [Fact]
    public async Task MultiLevelDelegation_WithRdfc_ChainAndInvocationValid()
    {
        var controller1 = "did:key:z6MkRdfcC1";
        var controller2 = "did:key:z6MkRdfcC2";
        var controller3 = "did:key:z6MkRdfcC3";
        _didProvider.GenerateAndRegisterKeyPair(controller1);
        _didProvider.GenerateAndRegisterKeyPair(controller2);
        _didProvider.GenerateAndRegisterKeyPair(controller3);

        var root = await CreateAndRegisterRootAsync(
            controller1,
            "https://api.example.com/resources",
            new[] { "read", "write", "delete" });

        var level1 = await _capabilityService.DelegateCapabilityAsync(
            root, controller2,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(60));

        var level2 = await _capabilityService.DelegateCapabilityAsync(
            level1, controller3,
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        var chainValid = await _verificationService.VerifyCapabilityChainAsync(level2);
        chainValid.Should().BeTrue();

        var invocation = new Invocation
        {
            Capability = level2.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/resources/item1"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controller3);

        var invocationValid = await _verificationService.VerifyInvocationAsync(invocation, level2);
        invocationValid.Should().BeTrue();
    }

    [Fact]
    public async Task TamperedCapability_WithRdfc_ShouldReject()
    {
        var ownerDid = "did:key:z6MkRdfcOwner";
        var childDid = "did:key:z6MkRdfcChild";
        _didProvider.GenerateAndRegisterKeyPair(ownerDid);

        var root = await CreateAndRegisterRootAsync(
            ownerDid,
            "https://api.example.com/documents",
            new[] { "read" });

        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Tamper with the capability after signing
        delegated.AllowedAction = new[] { "read", "write", "delete" };

        var isValid = await _verificationService.VerifyCapabilityProofAsync(delegated);
        isValid.Should().BeFalse();
    }
}
