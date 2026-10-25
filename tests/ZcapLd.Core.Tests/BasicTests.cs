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

}
