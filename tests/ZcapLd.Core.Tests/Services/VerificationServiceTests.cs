using FluentAssertions;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class VerificationServiceTests
{
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor;
    private readonly VerificationService _verificationService;

    public VerificationServiceTests()
    {
        _signingService = new SigningService();
        _caveatProcessor = new CaveatProcessor();
        _verificationService = new VerificationService(_signingService, _caveatProcessor);
        _capabilityService = new CapabilityService(_signingService);
    }

    #region Capability Proof Verification Tests

    [Fact]
    public async Task VerifyCapabilityProof_RootCapability_ShouldReturnTrue()
    {
        // Arrange
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkRoot",
            "https://example.com/resource",
            new[] { "read" });

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(rootCapability);

        // Assert
        result.Should().BeTrue(); // Root capabilities have no proof, which is valid
    }

    [Fact]
    public async Task VerifyCapabilityProof_ValidDelegation_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityProof_RootWithProof_ShouldReturnFalse()
    {
        // Arrange - Create a malformed root capability with a proof
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkRoot",
            "https://example.com/resource",
            new[] { "read" });

        rootCapability.Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofValue = "z123...",
            ProofPurpose = "capabilityDelegation"
        };

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(rootCapability);

        // Assert
        result.Should().BeFalse(); // Root capabilities MUST NOT have proofs
    }

    [Fact]
    public async Task VerifyCapabilityProof_DelegationWithoutProof_ShouldReturnFalse()
    {
        // Arrange - Create a malformed delegated capability without a proof
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:test",
            ParentCapability = "urn:zcap:root:something",
            Controller = "did:key:z6MkChild",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Proof = null // Missing required proof
        };

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(capability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_InvalidProofPurpose_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Corrupt the proof purpose
        delegatedCapability.Proof!.ProofPurpose = "capabilityInvocation"; // Wrong purpose

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Capability Chain Verification Tests

    [Fact]
    public async Task VerifyCapabilityChain_ValidSingleLevelChain_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_ValidMultiLevelChain_ShouldReturnTrue()
    {
        // Arrange
        var controller1 = "did:key:z6MkController1";
        var controller2 = "did:key:z6MkController2";
        var controller3 = "did:key:z6MkController3";

        _signingService.GenerateAndRegisterKeyPair(controller1);
        _signingService.GenerateAndRegisterKeyPair(controller2);
        _signingService.GenerateAndRegisterKeyPair(controller3);

        // Create root
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controller1,
            "https://example.com/resource",
            new[] { "read", "write", "delete" });

        // First delegation
        var level1 = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controller2,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(30));

        // Second delegation
        var level2 = await _capabilityService.DelegateCapabilityAsync(
            level1,
            controller3,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(level2);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_ExceedsMaxLength_ShouldThrow()
    {
        // Arrange - Create a chain longer than 10 delegations
        var controllers = new List<string>();
        for (int i = 0; i <= 11; i++)
        {
            var did = $"did:key:z6MkController{i}";
            controllers.Add(did);
            _signingService.GenerateAndRegisterKeyPair(did);
        }

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllers[0],
            "https://example.com/resource",
            new[] { "read" });

        Capability current = rootCapability;
        for (int i = 1; i <= 11; i++)
        {
            current = await _capabilityService.DelegateCapabilityAsync(
                current,
                controllers[i],
                new[] { "read" },
                DateTime.UtcNow.AddDays(30));
        }

        // Act & Assert
        var act = async () => await _verificationService.VerifyCapabilityChainAsync(current);
        await act.Should().ThrowAsync<CapabilityValidationException>()
            .WithMessage("*exceeds maximum*");
    }

    [Fact]
    public async Task VerifyCapabilityChain_WithExpiredCapability_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        // Create delegation with expiration in the past
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(-1)); // Expired

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Attenuation Validation Tests

    [Fact]
    public async Task VerifyCapabilityChain_ValidAttenuation_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write", "delete" });

        // Delegate with subset of actions (proper attenuation)
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" }, // Subset of parent's actions
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_InvalidTargetAttenuation_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _signingService.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Corrupt the invocation target to an invalid value
        delegatedCapability.InvocationTarget = "https://different.com/resource";

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Invocation Verification Tests

    [Fact]
    public async Task VerifyInvocation_ValidInvocation_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        // Sign the invocation
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithInvalidAction_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" }); // Only "read" allowed

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "write", // Not allowed
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithInvalidTarget_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://different.com/resource" // Wrong target
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithValidTargetPrefix_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        // Invoke with a valid prefix extension
        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource/subpath" // Valid prefix
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithoutProof_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource",
            Proof = null // No proof
        };

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithWrongProofPurpose_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        invocation.Proof.ProofPurpose = "capabilityDelegation"; // Wrong purpose

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithCaveats_ShouldEvaluateThem()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _signingService.GenerateAndRegisterKeyPair(controllerDid);

        var expiredCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(-1) // Expired
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" },
            caveats: new Caveat[] { expiredCaveat });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse(); // Caveat should cause failure
    }

    #endregion

    #region DID Resolution Tests

    [Fact]
    public async Task ResolvePublicKey_WithDidKey_ShouldExtractPublicKey()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (privateKey, publicKey) = _signingService.GenerateAndRegisterKeyPair(did);
        var verificationMethod = await _signingService.GetVerificationMethodAsync(did);

        // Act
        var resolvedKey = await _verificationService.ResolvePublicKeyAsync(verificationMethod);

        // Assert
        resolvedKey.Should().NotBeNull();
        resolvedKey.Should().HaveCount(32); // Ed25519 public keys are 32 bytes
    }

    [Fact]
    public async Task ResolvePublicKey_WithInvalidDid_ShouldThrow()
    {
        // Arrange
        var invalidDid = "did:invalid:xyz";

        // Act & Assert
        var act = async () => await _verificationService.ResolvePublicKeyAsync(invalidDid);
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    [Fact]
    public async Task ResolvePublicKey_WithEmptyDid_ShouldThrow()
    {
        // Arrange
        var emptyDid = "";

        // Act & Assert
        var act = async () => await _verificationService.ResolvePublicKeyAsync(emptyDid);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region Edge Cases and Error Handling

    [Fact]
    public async Task VerifyCapabilityProof_WithNullCapability_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _verificationService.VerifyCapabilityProofAsync(null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyInvocation_WithNullInvocation_ShouldThrow()
    {
        // Arrange
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkTest",
            "https://example.com/resource",
            new[] { "read" });

        // Act & Assert
        var act = async () => await _verificationService.VerifyInvocationAsync(null!, capability);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyInvocation_WithNullCapability_ShouldThrow()
    {
        // Arrange
        var invocation = new Invocation
        {
            Capability = "urn:zcap:root:test",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        // Act & Assert
        var act = async () => await _verificationService.VerifyInvocationAsync(invocation, null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyCapabilityChain_WithNullCapability_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _verificationService.VerifyCapabilityChainAsync(null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    #endregion
}
