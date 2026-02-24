using System.Collections.Concurrent;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default in-memory revocation store for development/testing.
/// </summary>
public sealed class InMemoryRevocationStore : IRevocationStore
{
    private readonly ConcurrentDictionary<string, RevocationRecord> _records = new(StringComparer.Ordinal);

    public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        cancellationToken.ThrowIfCancellationRequested();
        _records[record.CapabilityId] = record;
        return Task.CompletedTask;
    }

    public Task<RevocationRecord?> GetByCapabilityIdAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return Task.FromResult<RevocationRecord?>(null);
        }

        _records.TryGetValue(capabilityId, out var record);
        return Task.FromResult(record);
    }

    public Task DeleteAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return Task.CompletedTask;
        }

        _records.TryRemove(capabilityId, out _);
        return Task.CompletedTask;
    }
}
