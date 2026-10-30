using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class RevocationServiceTests
{
    private static readonly RevocationScope Alice = RevocationScope.Delegated("did:key:z6MkAlice");
    private static readonly RevocationScope Mallory = RevocationScope.Delegated("did:key:z6MkMallory");

    [Fact]
    public async Task RevokeAsync_ShouldPersistRevocationRecordUnderItsKey()
    {
        // Arrange
        var store = new InMemoryRevocationStore();
        var service = new RevocationService(store);
        var request = new RevocationRequest
        {
            CapabilityId = "urn:uuid:abc-123",
            Scope = Alice,
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
        var persisted = await store.GetAsync([record.Key]);

        // Assert
        record.CapabilityId.Should().Be(request.CapabilityId);
        record.Scope.Should().Be(Alice);
        record.Key.Should().Be(Alice.KeyFor(request.CapabilityId));
        record.RootCapabilityId.Should().Be(request.RootCapabilityId);
        record.RevokedBy.Should().Be(request.RevokedBy);
        record.Reason.Should().Be(request.Reason);
        record.Metadata.Should().NotBeNull();
        record.Metadata!["source"].Should().Be("security-monitor");
        persisted.Should().ContainSingle().Which.RevokedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task RevokeAsync_RequiresAScope()
    {
        var service = new RevocationService(new InMemoryRevocationStore());

        var act = () => service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = "urn:uuid:no-scope", Scope = null!, RevokedBy = "did:key:z6MkRevoker"
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task IsRevokedAsync_ExpiredRecord_ShouldReturnFalseAndEvictOnlyThatKey()
    {
        // Arrange
        var store = new InMemoryRevocationStore();
        var service = new RevocationService(store);
        var capabilityId = "urn:uuid:expired-zcap";
        await service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId, Scope = Alice, RevokedBy = "did:key:z6MkAlice"
        });
        await service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId, Scope = Mallory, RevokedBy = "did:key:z6MkMallory",
            ExpiresAt = DateTime.UtcNow.AddSeconds(-1)
        });

        // Act
        var isRevoked = await service.IsRevokedAsync(capabilityId, Mallory);

        // Assert: expiry cleanup deletes by exact key, so Mallory's short-lived record cannot take
        // Alice's record for the same id with it (#158).
        isRevoked.Should().BeFalse();
        (await store.GetAsync([Mallory.KeyFor(capabilityId)])).Should().BeEmpty();
        (await store.GetAsync([Alice.KeyFor(capabilityId)])).Should().ContainSingle();
        (await service.IsRevokedAsync(capabilityId, Alice)).Should().BeTrue();
    }

    [Fact]
    public async Task IsRevokedAsync_UnknownCapability_ShouldReturnFalse()
    {
        var service = new RevocationService(new InMemoryRevocationStore());

        (await service.IsRevokedAsync("urn:uuid:missing", Alice)).Should().BeFalse();
        (await service.IsRevokedAsync("urn:uuid:missing", RevocationScope.Root)).Should().BeFalse();
        (await service.IsRevokedAsync("urn:uuid:missing", RevocationScope.Unscoped)).Should().BeFalse();
    }

    [Fact]
    public async Task Scopes_IsolateRecordsForTheSameId()
    {
        var service = new RevocationService(new InMemoryRevocationStore());
        const string id = "urn:uuid:shared-id";
        await service.RevokeAsync(new RevocationRequest { CapabilityId = id, Scope = Mallory, RevokedBy = "did:key:z6MkMallory" });

        (await service.IsRevokedAsync(id, Mallory)).Should().BeTrue();
        (await service.IsRevokedAsync(id, Alice)).Should().BeFalse(
            "a record in Mallory's scope says nothing about a capability Alice delegated");
        (await service.IsRevokedAsync(id, RevocationScope.Root)).Should().BeFalse();
        (await service.IsRevokedAsync(id, RevocationScope.Unscoped)).Should().BeFalse();
    }

    [Fact]
    public async Task UnscopedRecord_AppliesInEveryScope()
    {
        var service = new RevocationService(new InMemoryRevocationStore());
        const string id = "urn:uuid:legacy-id";
        await service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = id, Scope = RevocationScope.Unscoped, RevokedBy = "did:key:z6MkOperator"
        });

        (await service.IsRevokedAsync(id, Alice)).Should().BeTrue();
        (await service.IsRevokedAsync(id, RevocationScope.Root)).Should().BeTrue();
        (await service.IsRevokedAsync(id, RevocationScope.Unscoped)).Should().BeTrue();
    }

    [Fact]
    public async Task FindRevocationAsync_ReturnsTheFirstRevokedLookupInOrder()
    {
        var service = new RevocationService(new InMemoryRevocationStore());
        await service.RevokeAsync(new RevocationRequest { CapabilityId = "urn:uuid:second", Scope = Alice, RevokedBy = "did:key:z6MkAlice" });
        await service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = "urn:uuid:third", Scope = RevocationScope.Unscoped, RevokedBy = "did:key:z6MkOperator"
        });

        var found = await service.FindRevocationAsync(
        [
            new RevocationLookup("urn:uuid:first", RevocationScope.Root),
            new RevocationLookup("urn:uuid:second", Alice),
            new RevocationLookup("urn:uuid:third", Mallory),
        ]);

        found.Should().NotBeNull();
        found!.CapabilityId.Should().Be("urn:uuid:second");

        var viaUnscoped = await service.FindRevocationAsync(
        [
            new RevocationLookup("urn:uuid:second", Mallory),
            new RevocationLookup("urn:uuid:third", Mallory),
        ]);
        viaUnscoped!.CapabilityId.Should().Be("urn:uuid:third", "the unscoped record is honoured under any scope");

        (await service.FindRevocationAsync([new RevocationLookup("urn:uuid:first", Alice)])).Should().BeNull();
        (await service.FindRevocationAsync([])).Should().BeNull();
    }

    [Fact]
    public async Task FindRevocationAsync_StoreReturningAnUnrequestedRecord_FailsClosed()
    {
        // A store that ignores the key and answers by capability id would turn Mallory's record into a
        // global one. The service refuses a record it did not ask for instead of treating it as a match.
        var store = new ByCapabilityIdStore();
        var service = new RevocationService(store);
        await store.UpsertAsync(new RevocationRecord
        {
            CapabilityId = "urn:uuid:x", Scope = Mallory, RevokedBy = "did:key:z6MkMallory", RevokedAt = DateTime.UtcNow
        });

        var act = () => service.IsRevokedAsync("urn:uuid:x", Alice);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RevokeAsync_StoreDroppingTheScope_FailsClosed()
    {
        // The record is read back under its key after the write; a backend without a scope column
        // cannot return it there, so the write is reported as failed rather than silently widened.
        var service = new RevocationService(new ScopeDroppingStore());

        var act = () => service.RevokeAsync(new RevocationRequest
        {
            CapabilityId = "urn:uuid:x", Scope = Alice, RevokedBy = "did:key:z6MkAlice"
        });

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    /// <summary>Keys by bare capability id, as a 5.x backend did.</summary>
    private sealed class ByCapabilityIdStore : IRevocationStore
    {
        private readonly Dictionary<string, RevocationRecord> _records = new(StringComparer.Ordinal);

        public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
        {
            _records[record.CapabilityId] = record;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<RevocationRecord>>(_records.Values.ToList());

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    /// <summary>Persists every record as unscoped, as a backend without a scope column would.</summary>
    private sealed class ScopeDroppingStore : IRevocationStore
    {
        private readonly InMemoryRevocationStore _inner = new();

        public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
            => _inner.UpsertAsync(record with { Scope = RevocationScope.Unscoped }, cancellationToken);

        public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
            => _inner.GetAsync(keys, cancellationToken);

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => _inner.DeleteAsync(key, cancellationToken);
    }
}
