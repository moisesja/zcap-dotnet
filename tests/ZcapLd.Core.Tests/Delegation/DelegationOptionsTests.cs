using System;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Delegation;

namespace ZcapLd.Core.Tests.Delegation;

public class DelegationOptionsTests
{
    [Fact]
    public void Default_ShouldHaveExpectedValues()
    {
        // Act
        var options = DelegationOptions.Default;

        // Assert
        options.MaxChainDepth.Should().Be(10);
        options.MaxClockSkew.Should().Be(TimeSpan.FromMinutes(5));
        options.EnforceUrlAttenuation.Should().BeTrue();
        options.EnforceCaveatInheritance.Should().BeTrue();
        options.CheckRevocation.Should().BeFalse();
        options.DefaultExpirationDuration.Should().Be(TimeSpan.FromDays(30));
        options.AllowNoExpiration.Should().BeFalse();
        options.ValidateProofSignatures.Should().BeTrue();
    }

    [Fact]
    public void Strict_ShouldHaveStrictValues()
    {
        // Act
        var options = DelegationOptions.Strict;

        // Assert
        options.MaxChainDepth.Should().Be(5);
        options.MaxClockSkew.Should().Be(TimeSpan.FromMinutes(1));
        options.EnforceUrlAttenuation.Should().BeTrue();
        options.EnforceCaveatInheritance.Should().BeTrue();
        options.CheckRevocation.Should().BeTrue();
        options.DefaultExpirationDuration.Should().Be(TimeSpan.FromDays(7));
        options.AllowNoExpiration.Should().BeFalse();
        options.ValidateProofSignatures.Should().BeTrue();
    }

    [Fact]
    public void Lenient_ShouldHaveLenientValues()
    {
        // Act
        var options = DelegationOptions.Lenient;

        // Assert
        options.MaxChainDepth.Should().Be(20);
        options.MaxClockSkew.Should().Be(TimeSpan.FromMinutes(15));
        options.EnforceUrlAttenuation.Should().BeFalse();
        options.EnforceCaveatInheritance.Should().BeFalse();
        options.CheckRevocation.Should().BeFalse();
        options.DefaultExpirationDuration.Should().Be(TimeSpan.FromDays(365));
        options.AllowNoExpiration.Should().BeTrue();
        options.ValidateProofSignatures.Should().BeFalse();
    }

    [Fact]
    public void Validate_ShouldSucceed_WithDefaultOptions()
    {
        // Arrange
        var options = DelegationOptions.Default;

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_ShouldThrow_WhenMaxChainDepthIsZero()
    {
        // Arrange
        var options = new DelegationOptions { MaxChainDepth = 0 };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxChainDepth*at least 1*");
    }

    [Fact]
    public void Validate_ShouldThrow_WhenMaxChainDepthIsNegative()
    {
        // Arrange
        var options = new DelegationOptions { MaxChainDepth = -1 };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxChainDepth*at least 1*");
    }

    [Fact]
    public void Validate_ShouldThrow_WhenMaxChainDepthExceeds100()
    {
        // Arrange
        var options = new DelegationOptions { MaxChainDepth = 101 };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxChainDepth*cannot exceed 100*");
    }

    [Fact]
    public void Validate_ShouldThrow_WhenMaxClockSkewIsNegative()
    {
        // Arrange
        var options = new DelegationOptions { MaxClockSkew = TimeSpan.FromMinutes(-1) };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxClockSkew*cannot be negative*");
    }

    [Fact]
    public void Validate_ShouldThrow_WhenMaxClockSkewExceeds24Hours()
    {
        // Arrange
        var options = new DelegationOptions { MaxClockSkew = TimeSpan.FromHours(25) };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxClockSkew*cannot exceed 24 hours*");
    }

    [Fact]
    public void Validate_ShouldThrow_WhenDefaultExpirationDurationIsTooSmall()
    {
        // Arrange
        var options = new DelegationOptions { DefaultExpirationDuration = TimeSpan.FromSeconds(30) };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*DefaultExpirationDuration*at least 1 minute*");
    }

    [Fact]
    public void Validate_ShouldSucceed_WithMaxChainDepth100()
    {
        // Arrange
        var options = new DelegationOptions { MaxChainDepth = 100 };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_ShouldSucceed_WithMaxClockSkew24Hours()
    {
        // Arrange
        var options = new DelegationOptions { MaxClockSkew = TimeSpan.FromHours(24) };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_ShouldSucceed_WithDefaultExpirationDuration1Minute()
    {
        // Arrange
        var options = new DelegationOptions { DefaultExpirationDuration = TimeSpan.FromMinutes(1) };

        // Act
        var act = () => options.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void PropertySetters_ShouldWork()
    {
        // Arrange
        var options = new DelegationOptions();

        // Act
        options.MaxChainDepth = 15;
        options.MaxClockSkew = TimeSpan.FromMinutes(10);
        options.EnforceUrlAttenuation = false;
        options.EnforceCaveatInheritance = false;
        options.CheckRevocation = true;
        options.DefaultExpirationDuration = TimeSpan.FromDays(90);
        options.AllowNoExpiration = true;
        options.ValidateProofSignatures = false;

        // Assert
        options.MaxChainDepth.Should().Be(15);
        options.MaxClockSkew.Should().Be(TimeSpan.FromMinutes(10));
        options.EnforceUrlAttenuation.Should().BeFalse();
        options.EnforceCaveatInheritance.Should().BeFalse();
        options.CheckRevocation.Should().BeTrue();
        options.DefaultExpirationDuration.Should().Be(TimeSpan.FromDays(90));
        options.AllowNoExpiration.Should().BeTrue();
        options.ValidateProofSignatures.Should().BeFalse();
    }
}
