using FluentAssertions;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>
/// Unit tests for <see cref="RootCapability"/> class.
/// </summary>
public class RootCapabilityTests
{
    private const string ValidInvocationTarget = "https://example.com/api/resource";
    private const string ValidController = "did:example:controller123";

    [Fact]
    public void Create_WithValidParameters_ReturnsRootCapability()
    {
        // Act
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Assert
        capability.Should().NotBeNull();
        capability.InvocationTarget.Should().Be(ValidInvocationTarget);
        capability.Controller.Should().Be(ValidController);
        capability.Context.Should().Be("https://w3id.org/zcap/v1");
        capability.Id.Should().StartWith("urn:zcap:root:");
    }

    [Fact]
    public void Create_GeneratesCorrectId()
    {
        // Act
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Assert
        var expectedId = $"urn:zcap:root:{Uri.EscapeDataString(ValidInvocationTarget)}";
        capability.Id.Should().Be(expectedId);
    }

    [Fact]
    public void Create_WithUrlEncodingRequired_EncodesCorrectly()
    {
        // Arrange
        var targetWithSpecialChars = "https://example.com/api/resource?query=value&other=123";

        // Act
        var capability = RootCapability.Create(targetWithSpecialChars, ValidController);

        // Assert
        capability.Id.Should().Contain("urn:zcap:root:");
        capability.Id.Should().NotContain("?");
        capability.Id.Should().NotContain("&");
        capability.Id.Should().NotContain("=");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_WithNullOrEmptyInvocationTarget_ThrowsArgumentNullException(string? invocationTarget)
    {
        // Act
        var act = () => RootCapability.Create(invocationTarget!, ValidController);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("invocationTarget");
    }

    [Fact]
    public void Create_WithNullController_ThrowsArgumentNullException()
    {
        // Act
        var act = () => RootCapability.Create(ValidInvocationTarget, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("controller");
    }

    [Fact]
    public void Create_WithControllerArray_SetsControllerCorrectly()
    {
        // Arrange
        var controllers = new[] { "did:example:controller1", "did:example:controller2" };

        // Act
        var capability = RootCapability.Create(ValidInvocationTarget, controllers);

        // Assert
        capability.Controller.Should().BeEquivalentTo(controllers);
    }

    [Fact]
    public void Validate_WithValidRootCapability_DoesNotThrow()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_WithEmptyId_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Id = string.Empty;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*ID is required*")
            .Which.ErrorCode.Should().Be("MISSING_ID");
    }

    [Fact]
    public void Validate_WithInvalidIdUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Id = "not-a-valid-uri";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_ID_URI");
    }

    [Fact]
    public void Validate_WithWrongIdFormat_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Id = "urn:uuid:12345678-1234-1234-1234-123456789abc"; // Wrong format

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must start with 'urn:zcap:root:'*")
            .Which.ErrorCode.Should().Be("INVALID_ROOT_ID_FORMAT");
    }

    [Fact]
    public void Validate_WithMismatchedId_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Id = "urn:zcap:root:https%3A%2F%2Fdifferent.com";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*does not match expected format*")
            .Which.ErrorCode.Should().Be("MISMATCHED_ROOT_ID");
    }

    [Fact]
    public void Validate_WithEmptyInvocationTarget_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.InvocationTarget = string.Empty;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*InvocationTarget is required*")
            .Which.ErrorCode.Should().Be("MISSING_INVOCATION_TARGET");
    }

    [Fact]
    public void Validate_WithInvalidInvocationTargetUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.InvocationTarget = "not-a-valid-uri";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*InvocationTarget must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_INVOCATION_TARGET");
    }

    [Fact]
    public void Validate_WithEmptyController_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Controller = string.Empty;

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Controller is required*")
            .Which.ErrorCode.Should().Be("MISSING_CONTROLLER");
    }

    [Fact]
    public void Validate_WithInvalidControllerUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Controller = "not-a-valid-did";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Controller must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_CONTROLLER_URI");
    }

    [Fact]
    public void Validate_WithContextArray_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Context = new[] { "https://w3id.org/zcap/v1" };

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*@context must be a string*")
            .Which.ErrorCode.Should().Be("INVALID_ROOT_CONTEXT_TYPE");
    }

    [Fact]
    public void Validate_WithWrongContextValue_ThrowsCapabilityValidationException()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Context = "https://w3id.org/zcap/v2";

        // Act
        var act = () => capability.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must be exactly 'https://w3id.org/zcap/v1'*")
            .Which.ErrorCode.Should().Be("INVALID_ROOT_CONTEXT_VALUE");
    }

    [Fact]
    public void AuthorizesTarget_WithMatchingTarget_ReturnsTrue()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.AuthorizesTarget(ValidInvocationTarget);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void AuthorizesTarget_WithDifferentTarget_ReturnsFalse()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.AuthorizesTarget("https://different.com/api");

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AuthorizesTarget_WithNullOrEmptyTarget_ReturnsFalse(string? target)
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.AuthorizesTarget(target!);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsController_WithMatchingController_ReturnsTrue()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.IsController(ValidController);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsController_WithNonMatchingController_ReturnsFalse()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.IsController("did:example:different");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsController_WithControllerArray_ChecksAllControllers()
    {
        // Arrange
        var controllers = new[] { "did:example:controller1", "did:example:controller2" };
        var capability = RootCapability.Create(ValidInvocationTarget, controllers);

        // Act & Assert
        capability.IsController("did:example:controller1").Should().BeTrue();
        capability.IsController("did:example:controller2").Should().BeTrue();
        capability.IsController("did:example:controller3").Should().BeFalse();
    }

    [Fact]
    public void GetControllers_WithSingleController_ReturnsArray()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var controllers = capability.GetControllers();

        // Assert
        controllers.Should().HaveCount(1);
        controllers[0].Should().Be(ValidController);
    }

    [Fact]
    public void GetControllers_WithControllerArray_ReturnsArray()
    {
        // Arrange
        var controllerArray = new[] { "did:example:controller1", "did:example:controller2" };
        var capability = RootCapability.Create(ValidInvocationTarget, controllerArray);

        // Act
        var controllers = capability.GetControllers();

        // Assert
        controllers.Should().BeEquivalentTo(controllerArray);
    }

    [Fact]
    public void IsValidFor_WithValidControllerAndTarget_ReturnsTrue()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.IsValidFor(ValidController, ValidInvocationTarget);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsValidFor_WithInvalidController_ReturnsFalse()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.IsValidFor("did:example:different", ValidInvocationTarget);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsValidFor_WithInvalidTarget_ReturnsFalse()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);

        // Act
        var result = capability.IsValidFor(ValidController, "https://different.com/api");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsValidFor_WithInvalidCapability_ReturnsFalse()
    {
        // Arrange
        var capability = RootCapability.Create(ValidInvocationTarget, ValidController);
        capability.Id = "invalid-id";

        // Act
        var result = capability.IsValidFor(ValidController, ValidInvocationTarget);

        // Assert
        result.Should().BeFalse();
    }
}
