using FluentAssertions;
using System.Text.Json;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

public class CapabilityTests
{
    [Fact]
    public void Capability_DefaultConstructor_ShouldInitializeProperties()
    {
        // Arrange & Act
        var capability = new Capability();

        // Assert
        capability.Id.Should().BeEmpty();
        capability.Context.Should().Be("https://w3id.org/zcap/v1");
        capability.Controller.Should().BeEmpty();
        capability.InvocationTarget.Should().BeEmpty();
        capability.AllowedAction.Should().BeEmpty();
        capability.Expires.Should().BeNull();
        capability.ParentCapability.Should().BeNull();
        capability.Caveat.Should().BeEmpty();
        capability.Proof.Should().BeNull();
    }

    [Fact]
    public void Capability_WithProperties_ShouldSerializeToJson()
    {
        // Arrange
        var capability = new Capability
        {
            Id = "urn:uuid:12345",
            Controller = "did:example:alice",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read", "write" },
            Expires = new DateTime(2025, 12, 31, 23, 59, 59, DateTimeKind.Utc)
        };

        // Act
        var json = JsonSerializer.Serialize(capability, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        });

        // Assert
        json.Should().Contain("\"id\": \"urn:uuid:12345\"");
        json.Should().Contain("\"controller\": \"did:example:alice\"");
        json.Should().Contain("\"invocationTarget\": \"https://example.com/resource\"");
        json.Should().Contain("\"allowedAction\": [\"read\", \"write\"]");
    }

    [Fact]
    public void Capability_FromJson_ShouldDeserializeCorrectly()
    {
        // Arrange
        var json = """
        {
            "id": "urn:uuid:12345",
            "controller": "did:example:alice",
            "invocationTarget": "https://example.com/resource",
            "allowedAction": ["read", "write"]
        }
        """;

        // Act
        var capability = JsonSerializer.Deserialize<Capability>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        // Assert
        capability.Should().NotBeNull();
        capability!.Id.Should().Be("urn:uuid:12345");
        capability.Controller.Should().Be("did:example:alice");
        capability.InvocationTarget.Should().Be("https://example.com/resource");
        capability.AllowedAction.Should().BeEquivalentTo(new[] { "read", "write" });
    }
}