using System;
using System.Collections.Generic;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Delegation;

namespace ZcapLd.Core.Tests.Delegation;

public class ValidationResultTests
{
    [Fact]
    public void Success_ShouldCreateSuccessfulResult()
    {
        // Act
        var result = ValidationResult.Success();

        // Assert
        result.IsValid.Should().BeTrue();
        result.ErrorCode.Should().BeNull();
        result.ErrorMessage.Should().BeNull();
        result.Context.Should().NotBeNull();
        result.Context.Should().BeEmpty();
    }

    [Fact]
    public void Success_WithContext_ShouldIncludeContext()
    {
        // Arrange
        var context = new Dictionary<string, object>
        {
            ["Key1"] = "Value1",
            ["Key2"] = 42
        };

        // Act
        var result = ValidationResult.Success(context);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Context.Should().HaveCount(2);
        result.Context["Key1"].Should().Be("Value1");
        result.Context["Key2"].Should().Be(42);
    }

    [Fact]
    public void Failure_ShouldCreateFailedResult()
    {
        // Act
        var result = ValidationResult.Failure("ERROR_CODE", "Error message");

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("ERROR_CODE");
        result.ErrorMessage.Should().Be("Error message");
        result.Context.Should().NotBeNull();
        result.Context.Should().BeEmpty();
    }

    [Fact]
    public void Failure_WithContext_ShouldIncludeContext()
    {
        // Arrange
        var context = new Dictionary<string, object>
        {
            ["CapabilityId"] = "cap-123",
            ["Timestamp"] = DateTime.UtcNow
        };

        // Act
        var result = ValidationResult.Failure("ERROR_CODE", "Error message", context);

        // Assert
        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("ERROR_CODE");
        result.ErrorMessage.Should().Be("Error message");
        result.Context.Should().HaveCount(2);
        result.Context["CapabilityId"].Should().Be("cap-123");
    }

    [Fact]
    public void Failure_ShouldThrowArgumentNullException_WhenErrorCodeIsNull()
    {
        // Act
        var act = () => ValidationResult.Failure(null!, "Error message");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("errorCode");
    }

    [Fact]
    public void Failure_ShouldThrowArgumentNullException_WhenErrorCodeIsEmpty()
    {
        // Act
        var act = () => ValidationResult.Failure("", "Error message");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("errorCode");
    }

    [Fact]
    public void Failure_ShouldThrowArgumentNullException_WhenErrorCodeIsWhitespace()
    {
        // Act
        var act = () => ValidationResult.Failure("   ", "Error message");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("errorCode");
    }

    [Fact]
    public void Failure_ShouldThrowArgumentNullException_WhenErrorMessageIsNull()
    {
        // Act
        var act = () => ValidationResult.Failure("ERROR_CODE", null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("errorMessage");
    }

    [Fact]
    public void Failure_ShouldThrowArgumentNullException_WhenErrorMessageIsEmpty()
    {
        // Act
        var act = () => ValidationResult.Failure("ERROR_CODE", "");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("errorMessage");
    }

    [Fact]
    public void ToString_ShouldReturnSuccess_ForSuccessfulResult()
    {
        // Arrange
        var result = ValidationResult.Success();

        // Act
        var str = result.ToString();

        // Assert
        str.Should().Be("ValidationResult: Success");
    }

    [Fact]
    public void ToString_ShouldReturnFailure_ForFailedResult()
    {
        // Arrange
        var result = ValidationResult.Failure("ERROR_CODE", "Error message");

        // Act
        var str = result.ToString();

        // Assert
        str.Should().Contain("ValidationResult: Failure");
        str.Should().Contain("ERROR_CODE");
        str.Should().Contain("Error message");
    }

    [Fact]
    public void ToString_ShouldIncludeContext_ForFailedResultWithContext()
    {
        // Arrange
        var context = new Dictionary<string, object>
        {
            ["Key1"] = "Value1"
        };
        var result = ValidationResult.Failure("ERROR_CODE", "Error message", context);

        // Act
        var str = result.ToString();

        // Assert
        str.Should().Contain("Context:");
        str.Should().Contain("Key1=Value1");
    }
}
