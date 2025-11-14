using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using ZcapLd.Core.Delegation;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Delegation;

public class AttenuationValidatorTests
{
    private readonly AttenuationValidator _validator;
    private readonly DelegationOptions _options;

    public AttenuationValidatorTests()
    {
        _options = DelegationOptions.Default;
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<AttenuationValidator>();
        _validator = new AttenuationValidator(Options.Create(_options), logger);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenOptionsIsNull()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<AttenuationValidator>();

        // Act
        var act = () => new AttenuationValidator(null!, logger);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act
        var act = () => new AttenuationValidator(Options.Create(_options), null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    #region URL Attenuation Tests

    [Fact]
    public void ValidateUrlAttenuation_ShouldSucceed_WhenTargetsAreEqual()
    {
        // Arrange
        var parentTarget = "https://api.example.com/users";
        var delegatedTarget = "https://api.example.com/users";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldSucceed_WhenDelegatedIsPathSuffix()
    {
        // Arrange
        var parentTarget = "https://api.example.com";
        var delegatedTarget = "https://api.example.com/users";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldSucceed_WhenDelegatedIsNestedPathSuffix()
    {
        // Arrange
        var parentTarget = "https://api.example.com/users";
        var delegatedTarget = "https://api.example.com/users/123";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldSucceed_WhenParentHasTrailingSlash()
    {
        // Arrange
        var parentTarget = "https://api.example.com/users/";
        var delegatedTarget = "https://api.example.com/users/123";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldFail_WhenDelegatedIsNotSuffix()
    {
        // Arrange
        var parentTarget = "https://api.example.com/users";
        var delegatedTarget = "https://api.example.com/posts";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("URL_ATTENUATION_VIOLATION");
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldFail_WhenDelegatedIsPrefixMatch()
    {
        // Arrange - Parent is /api, child is /api-v2 (prefix match but not path suffix)
        var parentTarget = "https://api.example.com/api";
        var delegatedTarget = "https://api.example.com/api-v2";

        // Act
        var result = _validator.ValidateUrlAttenuation(parentTarget, delegatedTarget);

        // Assert
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldThrowArgumentNullException_WhenParentTargetIsNull()
    {
        // Act
        var act = () => _validator.ValidateUrlAttenuation(null!, "https://api.example.com");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("parentTarget");
    }

    [Fact]
    public void ValidateUrlAttenuation_ShouldThrowArgumentNullException_WhenDelegatedTargetIsNull()
    {
        // Act
        var act = () => _validator.ValidateUrlAttenuation("https://api.example.com", null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("delegatedTarget");
    }

    #endregion

    #region Expiration Attenuation Tests

    [Fact]
    public void ValidateExpirationAttenuation_ShouldSucceed_WhenParentIsRoot()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateExpirationAttenuation_ShouldSucceed_WhenDelegatedExpiresBeforeParent()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30));

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15));

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateExpirationAttenuation_ShouldSucceed_WhenDelegatedExpiresAtSameTimeAsParent()
    {
        // Arrange
        var expires = DateTime.UtcNow.AddDays(30);

        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            expires);

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            expires);

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateExpirationAttenuation_ShouldFail_WhenDelegatedExpiresAfterParent()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15));

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("EXPIRATION_ATTENUATION_VIOLATION");
    }

    [Fact]
    public void ValidateExpirationAttenuation_ShouldFail_WhenDelegatedHasExpired()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(-1)); // Expired yesterday

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("CAPABILITY_EXPIRED");
    }

    [Fact]
    public void ValidateExpirationAttenuation_ShouldFail_WhenParentHasExpired()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(-1)); // Expired yesterday

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15));

        // Act
        var result = _validator.ValidateExpirationAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("PARENT_CAPABILITY_EXPIRED");
    }

    #endregion

    #region Action Attenuation Tests

    [Fact]
    public void ValidateActionAttenuation_ShouldSucceed_WhenParentHasNoActions()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: "read");

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateActionAttenuation_ShouldSucceed_WhenDelegatedHasNoActions()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: new[] { "read", "write" });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15));

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateActionAttenuation_ShouldSucceed_WhenDelegatedActionsAreSubset()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: new[] { "read", "write", "delete" });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            allowedAction: new[] { "read", "write" });

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateActionAttenuation_ShouldSucceed_WhenActionsAreEqual()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: new[] { "read", "write" });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            allowedAction: new[] { "read", "write" });

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateActionAttenuation_ShouldFail_WhenDelegatedHasUnauthorizedActions()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: new[] { "read" });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            allowedAction: new[] { "read", "write", "delete" });

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("ACTION_ATTENUATION_VIOLATION");
        result.ErrorMessage.Should().Contain("write");
        result.ErrorMessage.Should().Contain("delete");
    }

    [Fact]
    public void ValidateActionAttenuation_ShouldBeCaseInsensitive()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            allowedAction: new[] { "READ", "WRITE" });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            allowedAction: new[] { "read", "write" });

        // Act
        var result = _validator.ValidateActionAttenuation(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    #endregion

    #region Full Attenuation Validation Tests

    [Fact]
    public async Task ValidateAttenuationAsync_ShouldSucceed_WithValidDelegation()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com/users",
            DateTime.UtcNow.AddDays(30),
            allowedAction: "read");

        // Act
        var result = await _validator.ValidateAttenuationAsync(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAttenuationAsync_ShouldFail_WithUrlAttenuation Violation()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com/users", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com/posts", // Different path
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _validator.ValidateAttenuationAsync(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("URL_ATTENUATION_VIOLATION");
    }

    [Fact]
    public async Task ValidateAttenuationAsync_ShouldThrowArgumentNullException_WhenParentIsNull()
    {
        // Arrange
        var delegated = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30));

        // Act
        var act = async () => await _validator.ValidateAttenuationAsync(null!, delegated);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("parent");
    }

    [Fact]
    public async Task ValidateAttenuationAsync_ShouldThrowArgumentNullException_WhenDelegatedIsNull()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");

        // Act
        var act = async () => await _validator.ValidateAttenuationAsync(parent, null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("delegated");
    }

    #endregion

    #region Caveat Inheritance Tests

    [Fact]
    public async Task ValidateCaveatInheritanceAsync_ShouldSucceed_WhenParentHasNoCaveats()
    {
        // Arrange
        var parent = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            caveats: new[] { new ExpirationCaveat(DateTime.UtcNow.AddDays(15)) });

        // Act
        var result = await _validator.ValidateCaveatInheritanceAsync(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCaveatInheritanceAsync_ShouldSucceed_WhenDelegatedHasAllParentCaveats()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            caveats: new Caveat[] { new ExpirationCaveat(DateTime.UtcNow.AddDays(15)) });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            caveats: new Caveat[] { new ExpirationCaveat(DateTime.UtcNow.AddDays(10)) });

        // Act
        var result = await _validator.ValidateCaveatInheritanceAsync(parent, delegated);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCaveatInheritanceAsync_ShouldFail_WhenDelegatedMissingParentCaveats()
    {
        // Arrange
        var parent = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(30),
            caveats: new Caveat[]
            {
                new ExpirationCaveat(DateTime.UtcNow.AddDays(15)),
                new UsageCountCaveat(10)
            });

        var delegated = DelegatedCapability.Create(
            parent.Id,
            "did:example:bob",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(15),
            caveats: new Caveat[] { new ExpirationCaveat(DateTime.UtcNow.AddDays(10)) });

        // Act
        var result = await _validator.ValidateCaveatInheritanceAsync(parent, delegated);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("CAVEAT_INHERITANCE_VIOLATION");
    }

    #endregion
}
