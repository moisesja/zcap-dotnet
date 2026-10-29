using System.Collections.Concurrent;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default in-memory revocation store for development/testing, keyed by <see cref="RevocationRecord.Key"/>.
/// </summary>
public sealed class InMemoryRevocationStore : IRevocationStore
{
    private readonly ConcurrentDictionary<string, RevocationRecord> _records = new(StringComparer.Ordinal);

    public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        cancellationToken.ThrowIfCancellationRequested();
        _records[record.Key] = record;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        cancellationToken.ThrowIfCancellationRequested();

        var found = new List<RevocationRecord>();
        foreach (var key in keys.Distinct(StringComparer.Ordinal))
        {
            if (!string.IsNullOrEmpty(key) && _records.TryGetValue(key, out var record))
            {
                found.Add(record);
            }
        }

        return Task.FromResult<IReadOnlyList<RevocationRecord>>(found);
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(key))
        {
            return Task.CompletedTask;
        }

        _records.TryRemove(key, out _);
        return Task.CompletedTask;
    }
}
