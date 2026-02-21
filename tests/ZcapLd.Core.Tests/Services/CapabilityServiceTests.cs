using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class CapabilityServiceTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;

    public CapabilityServiceTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    [Fact]
    public async Task CreateRootCapability_ShouldCreateValidRootCapability()
    {
        // Arrange
        var controller = "did:key:z6MkExample";
        var invocationTarget = "https://example.com/foo";
        var allowedActions = new[] { "read", "write" };

        // Act
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            controller,
            invocationTarget,
            allowedActions);

        // Assert
        capability.Should().NotBeNull();
        capability.Id.Should().StartWith("urn:zcap:root:");
        capability.Controller.Should().Be(controller);
        capability.InvocationTarget.Should().Be(invocationTarget);
        capability.AllowedAction.Should().BeEmpty();
        capability.Context.Should().Be("https://w3id.org/zcap/v1");

        // Root capabilities MUST NOT have:
        capability.Proof.Should().BeNull();
        capability.Expires.Should().BeNull();
        capability.ParentCapability.Should().BeNull();
    }

    [Fact]
    public async Task CreateRootCapability_WithInvalidURI_ShouldThrowException()
    {
        // Arrange
        var controller = "did:key:z6MkExample";
        var invalidTarget = "not-a-uri";
        var allowedActions = new[] { "read" };

        // Act & Assert
        var act = async () => await _capabilityService.CreateRootCapabilityAsync(
            controller,
            invalidTarget,
            allowedActions);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateRootCapability_WithEmptyController_ShouldThrowException()
    {
        // Arrange
        var controller = "";
        var invocationTarget = "https://example.com/foo";
        var allowedActions = new[] { "read" };

        // Act & Assert
        var act = async () => await _capabilityService.CreateRootCapabilityAsync(
            controller,
            invocationTarget,
            allowedActions);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task DelegateCapability_FromRootCapability_ShouldCreateValidDelegation()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        var newController = "did:key:z6MkChild";
        var invocationTarget = "https://example.com/foo";
        var allowedActions = new[] { "read", "write" };

        // Register key for parent controller
        var (privateKey, publicKey) = _didProvider.GenerateAndRegisterKeyPair(parentController);

        // Create root capability
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            invocationTarget,
            allowedActions);

        var expires = DateTime.UtcNow.AddDays(30);

        // Act
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            newController,
            new[] { "read" }, // Subset of parent actions
            expires);

        // Assert
        delegatedCapability.Should().NotBeNull();
        delegatedCapability.Id.Should().StartWith("urn:uuid:");
        delegatedCapability.Controller.Should().Be(newController);
        delegatedCapability.InvocationTarget.Should().Be(invocationTarget);
        delegatedCapability.AllowedAction.Should().Equal(new[] { "read" });
        delegatedCapability.Expires.Should().Be(expires);
        delegatedCapability.ParentCapability.Should().Be(rootCapability.Id);

        // Context MUST be array for delegated capabilities
        delegatedCapability.Context.Should().BeOfType<object[]>();

        // MUST have proof
        delegatedCapability.Proof.Should().NotBeNull();
        delegatedCapability.Proof!.ProofPurpose.Should().Be("capabilityDelegation");
        delegatedCapability.Proof.Type.Should().Be("Ed25519Signature2020");
        delegatedCapability.Proof.ProofValue.Should().NotBeNullOrEmpty();
        delegatedCapability.Proof.ProofValue.Should().StartWith("z");

        // Capability chain should contain root ID
        delegatedCapability.Proof.CapabilityChain.Should().NotBeEmpty();
        delegatedCapability.Proof.CapabilityChain[0].Should().Be(rootCapability.Id);
    }

    [Fact]
    public async Task DelegateCapability_WithExpandedActions_ShouldThrowException()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        var newController = "did:key:z6MkChild";
        var invocationTarget = "https://example.com/foo";

        _didProvider.GenerateAndRegisterKeyPair(parentController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            invocationTarget,
            new[] { "read", "write" });

        var parentDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            parentController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20));

        // Act & Assert - Try to delegate with "write", which expands delegated parent authority
        var act = async () => await _capabilityService.DelegateCapabilityAsync(
            parentDelegation,
            newController,
            new[] { "read", "write" }, // Trying to add "write"
            DateTime.UtcNow.AddDays(10));

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*cannot expand authority*");
    }

    [Fact]
    public async Task DelegateCapability_WithLaterExpiration_ShouldThrowException()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        var newController = "did:key:z6MkChild";
        var invocationTarget = "https://example.com/foo";

        _didProvider.GenerateAndRegisterKeyPair(parentController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            invocationTarget,
            new[] { "read" });

        // Create first delegation with 10-day expiration
        var parentExpires = DateTime.UtcNow.AddDays(10);
        var firstDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            parentController, // Same controller for simplicity
            new[] { "read" },
            parentExpires);

        // Act & Assert - Try to delegate with later expiration
        var act = async () => await _capabilityService.DelegateCapabilityAsync(
            firstDelegation,
            newController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20)); // Later than parent's 10 days

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*cannot be later than parent*");
    }

    [Fact]
    public async Task DelegateCapability_ShouldInheritParentCaveats()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        var newController = "did:key:z6MkChild";
        var invocationTarget = "https://example.com/foo";

        _didProvider.GenerateAndRegisterKeyPair(parentController);

        var parentCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(5)
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            invocationTarget,
            new[] { "read", "write" });

        var childCaveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 0
        };

        var parentDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            parentController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20),
            new Caveat[] { parentCaveat });

        // Act
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            parentDelegation,
            newController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10),
            new Caveat[] { childCaveat });

        // Assert
        delegatedCapability.Caveat.Should().HaveCount(2);
        delegatedCapability.Caveat.Should().Contain(c => c.Type == "Expiration"); // Inherited
        delegatedCapability.Caveat.Should().Contain(c => c.Type == "UsageCount"); // New
    }

    [Fact]
    public async Task DelegateCapability_MultiLevel_ShouldBuildCorrectChain()
    {
        // Arrange
        var controller1 = "did:key:z6MkController1";
        var controller2 = "did:key:z6MkController2";
        var controller3 = "did:key:z6MkController3";
        var invocationTarget = "https://example.com/foo";

        _didProvider.GenerateAndRegisterKeyPair(controller1);
        _didProvider.GenerateAndRegisterKeyPair(controller2);

        // Create root capability
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controller1,
            invocationTarget,
            new[] { "read", "write" });

        // First delegation
        var firstDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controller2,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(30));

        // Act - Second delegation
        var secondDelegation = await _capabilityService.DelegateCapabilityAsync(
            firstDelegation,
            controller3,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20));

        // Assert
        secondDelegation.Should().NotBeNull();
        secondDelegation.Proof.Should().NotBeNull();

        // Chain should be: [rootId, firstDelegationId]
        // Per spec: root ID, intermediate IDs, parent object
        secondDelegation.Proof!.CapabilityChain.Should().NotBeEmpty();
        secondDelegation.Proof.CapabilityChain.Length.Should().BeGreaterThanOrEqualTo(2);

        // First element should be root ID
        secondDelegation.Proof.CapabilityChain[0].Should().Be(rootCapability.Id);

        // Should contain first delegation's ID
        secondDelegation.Proof.CapabilityChain.Should().Contain(firstDelegation.Id);
    }

    [Fact]
    public async Task ValidateCapability_WithValidRootCapability_ShouldReturnTrue()
    {
        // Arrange
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkExample",
            "https://example.com/foo",
            new[] { "read" });

        // Act
        var isValid = await _capabilityService.ValidateCapabilityAsync(capability);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCapability_WithValidDelegatedCapability_ShouldReturnTrue()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            "https://example.com/foo",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act
        var isValid = await _capabilityService.ValidateCapabilityAsync(delegatedCapability);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCapability_RootWithProof_ShouldReturnFalse()
    {
        // Arrange
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkExample",
            "https://example.com/foo",
            new[] { "read" });

        // Corrupt the capability by adding a proof (root capabilities MUST NOT have proofs)
        capability.Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofValue = "z123..."
        };

        // Act
        var isValid = await _capabilityService.ValidateCapabilityAsync(capability);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateCapability_DelegatedWithoutExpires_ShouldReturnFalse()
    {
        // Arrange - Create a delegated capability manually without expires
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:test",
            Controller = "did:key:z6MkExample",
            InvocationTarget = "https://example.com/foo",
            AllowedAction = new[] { "read" },
            ParentCapability = "urn:zcap:root:something",
            Proof = new Proof { Type = "Ed25519Signature2020", ProofValue = "z123" },
            Expires = null // Delegated capabilities MUST have expires
        };

        // Act
        var isValid = await _capabilityService.ValidateCapabilityAsync(capability);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateCapability_WithInvalidURI_ShouldReturnFalse()
    {
        // Arrange
        var capability = new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkExample",
            InvocationTarget = "not-a-valid-uri",
            AllowedAction = new[] { "read" }
        };

        // Act
        var isValid = await _capabilityService.ValidateCapabilityAsync(capability);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task DelegateCapability_UsesParentExpirationWhenNotSpecified()
    {
        // Arrange
        var parentController = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentController);

        var parentExpires = DateTime.UtcNow.AddDays(10);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentController,
            "https://example.com/foo",
            new[] { "read" });

        var firstDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            parentController,
            new[] { "read" },
            parentExpires);

        // Act - Delegate without specifying expiration
        var secondDelegation = await _capabilityService.DelegateCapabilityAsync(
            firstDelegation,
            "did:key:z6MkChild",
            new[] { "read" },
            expires: null); // Not specified

        // Assert
        secondDelegation.Expires.Should().Be(parentExpires);
    }

    [Fact]
    public async Task DidProvider_GenerateAndRegisterKeyPair_ShouldCreateValidKeys()
    {
        // Arrange
        var did = "did:key:z6MkTest";

        // Act
        var (privateKey, publicKey) = _didProvider.GenerateAndRegisterKeyPair(did);

        // Assert
        privateKey.Should().HaveCount(32);
        publicKey.Should().HaveCount(32);

        // Should be able to resolve the public key later
        var resolvedPublicKey = await _didProvider.ResolvePublicKeyAsync(did);
        resolvedPublicKey.Should().Equal(publicKey);
    }

    [Fact]
    public async Task DidProvider_GetVerificationMethod_ForDidKey_ShouldReturnValidFormat()
    {
        // Arrange
        var did = "did:key:z6MkExample1234";

        // Act
        var verificationMethod = await _didProvider.GetVerificationMethodAsync(did);

        // Assert
        verificationMethod.Should().StartWith(did);
        verificationMethod.Should().Contain("#");
    }
}
