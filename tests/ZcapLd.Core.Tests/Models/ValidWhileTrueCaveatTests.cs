using FluentAssertions;
using System.Text.Json;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

public class ValidWhileTrueCaveatTests
{
    [Fact]
    public void Type_ShouldReturnValidWhileTrue()
    {
        var caveat = new ValidWhileTrueCaveat();

        caveat.Type.Should().Be("ValidWhileTrue");
    }

    [Fact]
    public void Uri_DefaultValue_ShouldBeEmpty()
    {
        var caveat = new ValidWhileTrueCaveat();

        caveat.Uri.Should().BeEmpty();
    }

    [Fact]
    public void Uri_WhenSet_ShouldReturnValue()
    {
        var caveat = new ValidWhileTrueCaveat
        {
            Uri = "https://example.com/zcaps/revocations/urn:uuid:123"
        };

        caveat.Uri.Should().Be("https://example.com/zcaps/revocations/urn:uuid:123");
    }

    [Fact]
    public void IsSatisfied_ShouldAlwaysReturnFalse()
    {
        // Fail-closed: without the async handler path, deny access
        var caveat = new ValidWhileTrueCaveat
        {
            Uri = "https://example.com/status"
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        caveat.IsSatisfied(context).Should().BeFalse();
    }

    [Fact]
    public void Serialize_ShouldIncludeTypeAndUri()
    {
        var caveat = new ValidWhileTrueCaveat
        {
            Uri = "https://social.example/alyssa/ben-can-still-drive"
        };

        var json = JsonSerializer.Serialize(caveat);
        var doc = JsonDocument.Parse(json);

        doc.RootElement.GetProperty("type").GetString().Should().Be("ValidWhileTrue");
        doc.RootElement.GetProperty("uri").GetString()
            .Should().Be("https://social.example/alyssa/ben-can-still-drive");
    }
}
