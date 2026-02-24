using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class RevocationServiceTests
{
    [Fact]
    public async Task RevokeAsync_ShouldPersistRevocationRecord()
    {
        // Arrange
        var store = new InMemoryRevocationStore();
        var service = new RevocationService(store);
        var request = new RevocationRequest
        {
            CapabilityId = "urn:uuid:abc-123",
            RootCapabilityId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource",
            RevokedBy = "did:key:z6MkRevoker",
            ExpiresAt = DateTime.UtcNow.AddDays(3),
            Reason = "Compromised key",
            Metadata = new Dictionary<string, string>
            {
                ["source"] = "security-monitor"
            }
        };

        // Act
        var record = await service.RevokeAsync(request);
        var persisted = await store.GetByCapabilityIdAsync(request.CapabilityId);

        // Assert
        record.CapabilityId.Should().Be(request.CapabilityId);
        record.RevokedBy.Should().Be(request.RevokedBy);
        record.Reason.Should().Be(request.Reason);
        record.Metadata.Should().NotBeNull();
        record.Metadata!["source"].Should().Be("security-monitor");
        persisted.Should().NotBeNull();
        persisted!.RevokedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task IsRevokedAsync_ExpiredRecord_ShouldReturnFalseAndEvict()
    {
        // Arrange
        var store = new InMemoryRevocationStore();
        var service = new RevocationService(store);
        var capabilityId = "urn:uuid:expired-zcap";

        await service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId,
            RevokedBy = "did:key:z6MkRevoker",
            ExpiresAt = DateTime.UtcNow.AddSeconds(-1)
        });

        // Act
        var isRevoked = await service.IsRevokedAsync(capabilityId);
        var persisted = await store.GetByCapabilityIdAsync(capabilityId);

        // Assert
        isRevoked.Should().BeFalse();
        persisted.Should().BeNull();
    }

    [Fact]
    public async Task IsRevokedAsync_UnknownCapability_ShouldReturnFalse()
    {
        // Arrange
        var service = new RevocationService(new InMemoryRevocationStore());

        // Act
        var result = await service.IsRevokedAsync("urn:uuid:missing");

        // Assert
        result.Should().BeFalse();
    }
}
