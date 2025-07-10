using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests;

public class BasicTests
{
    [Fact]
    public void BasicTest_ShouldPass()
    {
        // Arrange
        var capability = new Capability();

        // Act & Assert
        capability.Should().NotBeNull();
        capability.Id.Should().BeEmpty();
    }
    
    [Fact]
    public void InvocationContext_ShouldInitialize()
    {
        // Arrange & Act
        var context = new InvocationContext();

        // Assert
        context.Should().NotBeNull();
        context.InvocationTime.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(1));
    }
}