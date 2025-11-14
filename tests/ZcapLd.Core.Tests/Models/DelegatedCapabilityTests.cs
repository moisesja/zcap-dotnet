using FluentAssertions;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>
/// Unit tests for <see cref="DelegatedCapability"/> class.
/// </summary>
public class DelegatedCapabilityTests
{
    private const string ValidParentId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi";
    private const string ValidInvocationTarget = "https://example.com/api/resource";
    private const string ValidController = "did:example:controller123";

    private static DateTime GetValidExpiration() => DateTime.UtcNow.AddDays(30);

    [Fact]
    public void Create_WithValidParameters_ReturnsDelegatedCapability()
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            expires);

        // Assert
        capability.Should().NotBeNull();
        capability.ParentCapability.Should().Be(ValidParentId);
        capability.InvocationTarget.Should().Be(ValidInvocationTarget);
        capability.Controller.Should().Be(ValidController);
        capability.Expires.Should().Be(expires);
        capability.Id.Should().StartWith("urn:uuid:");
        capability.Context.Should().BeOfType<string[]>();
    }

    [Fact]
    public void Create_GeneratesUuidId()
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            expires);

        // Assert
        capability.Id.Should().MatchRegex(@"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    }

    [Fact]
    public void Create_WithAllowedAction_SetsAllowedAction()
    {
        // Arrange
        var expires = GetValidExpiration();
        var allowedAction = "read";

        // Act
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            expires,
            allowedAction);

        // Assert
        capability.AllowedAction.Should().Be(allowedAction);
    }

    [Fact]
    public void Create_SetsContextAsArray()
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            expires);

        // Assert
        var contextArray = capability.Context as string[];
        contextArray.Should().NotBeNull();
        contextArray.Should().HaveCountGreaterOrEqualTo(1);
        contextArray![0].Should().Be("https://w3id.org/zcap/v1");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_WithNullOrEmptyParentCapabilityId_ThrowsArgumentNullException(string? parentId)
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var act = () => DelegatedCapability.Create(
            parentId!,
            ValidInvocationTarget,
            ValidController,
            expires);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("parentCapabilityId");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_WithNullOrEmptyInvocationTarget_ThrowsArgumentNullException(string? invocationTarget)
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var act = () => DelegatedCapability.Create(
            ValidParentId,
            invocationTarget!,
            ValidController,
            expires);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("invocationTarget");
    }

    [Fact]
    public void Create_WithNullController_ThrowsArgumentNullException()
    {
        // Arrange
        var expires = GetValidExpiration();

        // Act
        var act = () => DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            null!,
            expires);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("controller");
    }

    [Fact]
    public void Validate_WithValidDelegatedCapability_DoesNotThrow()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_WithExpiredCapability_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            DateTime.UtcNow.AddDays(-1)); // Expired

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*expired*")
            .Which.ErrorCode.Should().Be("CAPABILITY_EXPIRED");
    }

    [Fact]
    public void Validate_WithDefaultExpiration_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.Expires = default;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must have an expiration*")
            .Which.ErrorCode.Should().Be("MISSING_EXPIRATION");
    }

    [Fact]
    public void Validate_WithEmptyParentCapability_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.ParentCapability = string.Empty;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must have a parentCapability*")
            .Which.ErrorCode.Should().Be("MISSING_PARENT_CAPABILITY");
    }

    [Fact]
    public void Validate_WithInvalidParentCapabilityUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.ParentCapability = "not-a-valid-uri";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*ParentCapability must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_PARENT_CAPABILITY_URI");
    }

    [Fact]
    public void Validate_WithEmptyAllowedActionString_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.AllowedAction = string.Empty;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*AllowedAction string cannot be empty*")
            .Which.ErrorCode.Should().Be("EMPTY_ALLOWED_ACTION");
    }

    [Fact]
    public void Validate_WithEmptyAllowedActionArray_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.AllowedAction = Array.Empty<string>();

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*AllowedAction array cannot be empty*")
            .Which.ErrorCode.Should().Be("EMPTY_ALLOWED_ACTION_ARRAY");
    }

    [Fact]
    public void Validate_WithInvalidAllowedActionType_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.AllowedAction = 123; // Invalid type

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must be either a string or an array*")
            .Which.ErrorCode.Should().Be("INVALID_ALLOWED_ACTION_TYPE");
    }

    [Fact]
    public void Validate_WithStringContext_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.Context = "https://w3id.org/zcap/v1";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*@context must be an array*")
            .Which.ErrorCode.Should().Be("INVALID_DELEGATED_CONTEXT_TYPE");
    }

    [Fact]
    public void Validate_WithEmptyContextArray_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.Context = Array.Empty<string>();

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*@context array cannot be empty*")
            .Which.ErrorCode.Should().Be("EMPTY_CONTEXT_ARRAY");
    }

    [Fact]
    public void Validate_WithWrongFirstContextValue_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());
        capability.Context = new[] { "https://w3id.org/zcap/v2" };

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must start with 'https://w3id.org/zcap/v1'*")
            .Which.ErrorCode.Should().Be("INVALID_DELEGATED_CONTEXT_VALUE");
    }

    [Fact]
    public void ValidateAttenuation_WithExactMatch_DoesNotThrow()
    {
        // Arrange
        var parentTarget = "https://example.com/api";
        var capability = DelegatedCapability.Create(
            ValidParentId,
            parentTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAttenuation_WithValidPathSuffix_DoesNotThrow()
    {
        // Arrange
        var parentTarget = "https://example.com/api";
        var childTarget = "https://example.com/api/resource";
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAttenuation_WithValidQuerySuffix_DoesNotThrow()
    {
        // Arrange
        var parentTarget = "https://example.com/api";
        var childTarget = "https://example.com/api?param=value";
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAttenuation_WithQueryAddition_DoesNotThrow()
    {
        // Arrange
        var parentTarget = "https://example.com/api?existing=param";
        var childTarget = "https://example.com/api?existing=param&new=value";
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAttenuation_WithInvalidPrefix_ThrowsCapabilityValidationException()
    {
        // Arrange
        var parentTarget = "https://example.com/api";
        var childTarget = "https://different.com/api";
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must match parent or use parent as prefix*")
            .Which.ErrorCode.Should().Be("INVALID_INVOCATION_TARGET_ATTENUATION");
    }

    [Fact]
    public void ValidateAttenuation_WithInvalidSuffixWhenNoQuery_ThrowsCapabilityValidationException()
    {
        // Arrange
        var parentTarget = "https://example.com/api";
        var childTarget = "https://example.com/apiextra"; // Missing '/' or '?'
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*suffix must start with '/' or '?'*")
            .Which.ErrorCode.Should().Be("INVALID_ATTENUATION_SUFFIX");
    }

    [Fact]
    public void ValidateAttenuation_WithInvalidSuffixWhenQuery_ThrowsCapabilityValidationException()
    {
        // Arrange
        var parentTarget = "https://example.com/api?param=value";
        var childTarget = "https://example.com/api?param=value?invalid"; // Should start with '&'
        var capability = DelegatedCapability.Create(
            ValidParentId,
            childTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var act = () => capability.ValidateAttenuation(parentTarget);

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*suffix must start with '&'*")
            .Which.ErrorCode.Should().Be("INVALID_ATTENUATION_SUFFIX");
    }

    [Fact]
    public void GetAllowedActions_WithStringAction_ReturnsArray()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration(),
            "read");

        // Act
        var actions = capability.GetAllowedActions();

        // Assert
        actions.Should().HaveCount(1);
        actions[0].Should().Be("read");
    }

    [Fact]
    public void GetAllowedActions_WithArrayAction_ReturnsArray()
    {
        // Arrange
        var actionArray = new[] { "read", "write" };
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration(),
            actionArray);

        // Act
        var actions = capability.GetAllowedActions();

        // Assert
        actions.Should().BeEquivalentTo(actionArray);
    }

    [Fact]
    public void GetAllowedActions_WithNoAction_ReturnsEmptyArray()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var actions = capability.GetAllowedActions();

        // Assert
        actions.Should().BeEmpty();
    }

    [Fact]
    public void AllowsAction_WithMatchingAction_ReturnsTrue()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration(),
            new[] { "read", "write" });

        // Act
        var result = capability.AllowsAction("read");

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void AllowsAction_WithNonMatchingAction_ReturnsFalse()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration(),
            new[] { "read", "write" });

        // Act
        var result = capability.AllowsAction("delete");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void AllowsAction_WithNoActionsSpecified_ReturnsTrue()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var result = capability.AllowsAction("anyAction");

        // Assert
        result.Should().BeTrue(); // No restrictions means all actions allowed
    }

    [Fact]
    public void IsExpired_WithExpiredCapability_ReturnsTrue()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            DateTime.UtcNow.AddSeconds(-1));

        // Act
        var result = capability.IsExpired();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsExpired_WithValidCapability_ReturnsFalse()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var result = capability.IsExpired();

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void HasValidExpiration_WithNullParentExpiration_ReturnsTrue()
    {
        // Arrange (child of root capability)
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            GetValidExpiration());

        // Act
        var result = capability.HasValidExpiration(null);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void HasValidExpiration_WithValidChildExpiration_ReturnsTrue()
    {
        // Arrange
        var parentExpires = DateTime.UtcNow.AddDays(60);
        var childExpires = DateTime.UtcNow.AddDays(30);
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            childExpires);

        // Act
        var result = capability.HasValidExpiration(parentExpires);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void HasValidExpiration_WithChildExpirationExceedingParent_ReturnsFalse()
    {
        // Arrange
        var parentExpires = DateTime.UtcNow.AddDays(30);
        var childExpires = DateTime.UtcNow.AddDays(60);
        var capability = DelegatedCapability.Create(
            ValidParentId,
            ValidInvocationTarget,
            ValidController,
            childExpires);

        // Act
        var result = capability.HasValidExpiration(parentExpires);

        // Assert
        result.Should().BeFalse();
    }
}
