using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Delegation;
using ZcapLd.Core.DependencyInjection;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Delegation;

public class DelegationServiceIntegrationTests
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IDelegationService _delegationService;
    private readonly IKeyProvider _keyProvider;
    private readonly IProofService _proofService;

    public DelegationServiceIntegrationTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZcapLd();

        _serviceProvider = services.BuildServiceProvider();
        _delegationService = _serviceProvider.GetRequiredService<IDelegationService>();
        _keyProvider = _serviceProvider.GetRequiredService<IKeyProvider>();
        _proofService = _serviceProvider.GetRequiredService<IProofService>();
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldCreateValidDelegation_FromRootCapability()
    {
        // Arrange - Create root capability
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        // Generate key for delegator (issuer)
        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        // Act - Delegate to Alice
        var delegated = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            delegatorKey,
            attenuatedTarget: "https://api.example.com/users",
            allowedAction: "read",
            expires: DateTime.UtcNow.AddDays(30));

        // Assert
        delegated.Should().NotBeNull();
        delegated.ParentCapability.Should().Be(rootCapability.Id);
        delegated.Controller.Should().Be("did:example:alice");
        delegated.InvocationTarget.Should().Be("https://api.example.com/users");
        delegated.AllowedAction.Should().Be("read");
        delegated.Proof.Should().NotBeNull();
        delegated.Proof!.ProofPurpose.Should().Be("capabilityDelegation");
        delegated.Proof.VerificationMethod.Should().Be("did:example:issuer#key-1");
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldCreateChainOfDelegations()
    {
        // Arrange - Create root capability
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        // Generate keys
        var issuerKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        var aliceKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:alice#key-1",
            "did:example:alice#key-1");

        // Act - Delegate root → Alice
        var aliceCapability = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            issuerKey,
            attenuatedTarget: "https://api.example.com/users",
            allowedAction: new[] { "read", "write" },
            expires: DateTime.UtcNow.AddDays(30));

        // Act - Delegate Alice → Bob
        var bobCapability = await _delegationService.DelegateCapabilityAsync(
            aliceCapability,
            "did:example:bob",
            aliceKey,
            attenuatedTarget: "https://api.example.com/users/123",
            allowedAction: "read",
            expires: DateTime.UtcNow.AddDays(15));

        // Assert
        bobCapability.Should().NotBeNull();
        bobCapability.ParentCapability.Should().Be(aliceCapability.Id);
        bobCapability.Controller.Should().Be("did:example:bob");
        bobCapability.InvocationTarget.Should().Be("https://api.example.com/users/123");
        bobCapability.AllowedAction.Should().Be("read");
        bobCapability.Proof.Should().NotBeNull();
        bobCapability.Proof!.CapabilityChain.Should().NotBeNull();
        bobCapability.Proof!.CapabilityChain!.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldEnforceUrlAttenuation()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com/users",
            "did:example:issuer");

        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        // Act & Assert - Try to delegate to a different path
        var act = async () => await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            delegatorKey,
            attenuatedTarget: "https://api.example.com/posts");

        await act.Should().ThrowAsync<Exceptions.CapabilityValidationException>()
            .WithMessage("*attenuation*");
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldEnforceActionAttenuation()
    {
        // Arrange
        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:alice#key-1",
            "did:example:alice#key-1");

        var parentCapability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: "read");

        // Act & Assert - Try to delegate with broader actions
        var act = async () => await _delegationService.DelegateCapabilityAsync(
            parentCapability,
            "did:example:bob",
            delegatorKey,
            allowedAction: new[] { "read", "write" });

        await act.Should().ThrowAsync<Exceptions.CapabilityValidationException>()
            .WithMessage("*attenuation*");
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldEnforceExpirationAttenuation()
    {
        // Arrange
        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:alice#key-1",
            "did:example:alice#key-1");

        var parentCapability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15));

        // Act & Assert - Try to delegate with later expiration
        var act = async () => await _delegationService.DelegateCapabilityAsync(
            parentCapability,
            "did:example:bob",
            delegatorKey,
            expires: DateTime.UtcNow.AddDays(30));

        await act.Should().ThrowAsync<Exceptions.CapabilityValidationException>()
            .WithMessage("*attenuation*");
    }

    [Fact]
    public async Task ValidateCapabilityAsync_ShouldSucceed_ForValidCapability()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        var issuerKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        var delegated = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            issuerKey,
            attenuatedTarget: "https://api.example.com/users",
            expires: DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _delegationService.ValidateCapabilityAsync(delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task BuildCapabilityChainAsync_ShouldReturnRootId_ForRootCapability()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        // Act
        var chain = await _delegationService.BuildCapabilityChainAsync(rootCapability);

        // Assert
        chain.Should().NotBeNull();
        chain.Should().HaveCount(1);
        chain[0].Should().Be(rootCapability.Id);
    }

    [Fact]
    public async Task BuildCapabilityChainAsync_ShouldReturnChain_ForDelegatedCapability()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        var issuerKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        var delegated = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            issuerKey,
            expires: DateTime.UtcNow.AddDays(30));

        // Act
        var chain = await _delegationService.BuildCapabilityChainAsync(delegated);

        // Assert
        chain.Should().NotBeNull();
        chain.Should().NotBeEmpty();
        chain[0].Should().Be(rootCapability.Id);
    }

    [Fact]
    public async Task IsRevokedAsync_ShouldReturnFalse_WhenRevocationIsDisabled()
    {
        // Act
        var isRevoked = await _delegationService.IsRevokedAsync("cap-123");

        // Assert
        isRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldUseDefaultExpiration_WhenNotSpecified()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        // Act
        var delegated = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            delegatorKey);

        // Assert
        delegated.Expires.Should().BeAfter(DateTime.UtcNow);
        delegated.Expires.Should().BeBefore(DateTime.UtcNow.AddDays(31)); // Default is 30 days
    }

    [Fact]
    public async Task DelegateCapabilityAsync_ShouldAllowCaveats()
    {
        // Arrange
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        var delegatorKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        var caveats = new Caveat[]
        {
            new ExpirationCaveat(DateTime.UtcNow.AddDays(15)),
            new UsageCountCaveat(10)
        };

        // Act
        var delegated = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            delegatorKey,
            expires: DateTime.UtcNow.AddDays(30),
            caveats: caveats);

        // Assert
        delegated.Caveats.Should().NotBeNull();
        delegated.Caveats.Should().HaveCount(2);
        delegated.Caveats.Should().Contain(c => c is ExpirationCaveat);
        delegated.Caveats.Should().Contain(c => c is UsageCountCaveat);
    }

    [Fact]
    public async Task EndToEndDelegationWorkflow_ShouldWork()
    {
        // This test simulates a complete delegation workflow:
        // 1. Create root capability
        // 2. Delegate root → Alice (admin access)
        // 3. Delegate Alice → Bob (read-only access to users)
        // 4. Validate Bob's capability

        // Step 1: Create root capability
        var rootCapability = RootCapability.Create(
            "https://api.example.com",
            "did:example:issuer");

        // Step 2: Generate keys for all parties
        var issuerKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:issuer#key-1",
            "did:example:issuer#key-1");

        var aliceKey = await _keyProvider.GenerateKeyPairAsync(
            "did:example:alice#key-1",
            "did:example:alice#key-1");

        // Step 3: Delegate root → Alice (admin access to /users)
        var aliceCapability = await _delegationService.DelegateCapabilityAsync(
            rootCapability,
            "did:example:alice",
            issuerKey,
            attenuatedTarget: "https://api.example.com/users",
            allowedAction: new[] { "read", "write", "delete" },
            expires: DateTime.UtcNow.AddDays(90));

        // Step 4: Delegate Alice → Bob (read-only access to specific user)
        var bobCapability = await _delegationService.DelegateCapabilityAsync(
            aliceCapability,
            "did:example:bob",
            aliceKey,
            attenuatedTarget: "https://api.example.com/users/123",
            allowedAction: "read",
            expires: DateTime.UtcNow.AddDays(30));

        // Step 5: Validate Bob's capability
        var validationResult = await _delegationService.ValidateCapabilityAsync(bobCapability);

        // Assert - All delegations should be valid
        aliceCapability.Should().NotBeNull();
        aliceCapability.Proof.Should().NotBeNull();

        bobCapability.Should().NotBeNull();
        bobCapability.Proof.Should().NotBeNull();
        bobCapability.Controller.Should().Be("did:example:bob");
        bobCapability.InvocationTarget.Should().Be("https://api.example.com/users/123");
        bobCapability.AllowedAction.Should().Be("read");

        validationResult.IsValid.Should().BeTrue();
    }
}
