using System.Collections.Concurrent;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default in-memory nonce store for development and testing.
/// Automatically evicts expired entries on read and periodically during writes.
/// Thread-safe via <see cref="ConcurrentDictionary{TKey, TValue}"/>.
/// </summary>
public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<string, DateTime?> _nonces = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private int _writesSinceLastPurge;
    private const int PurgeInterval = 100;

    public InMemoryNonceStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<bool> TryMarkAsUsedAsync(string nonce, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        cancellationToken.ThrowIfCancellationRequested();

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        // Check if an existing entry has expired; if so, evict it before the TryAdd
        if (_nonces.TryGetValue(nonce, out var existingExpiry))
        {
            if (existingExpiry.HasValue && existingExpiry.Value <= now)
            {
                // Expired — remove and allow re-use
                _nonces.TryRemove(nonce, out _);
            }
            else
            {
                // Still valid — this is a replay
                return Task.FromResult(true);
            }
        }

        // Atomic insert: returns false if key already exists (another thread beat us)
        var added = _nonces.TryAdd(nonce, expiresAt);

        if (added && Interlocked.Increment(ref _writesSinceLastPurge) >= PurgeInterval)
        {
            Interlocked.Exchange(ref _writesSinceLastPurge, 0);
            PurgeExpired(now);
        }

        // added=true means fresh nonce → return false (not a replay)
        // added=false means concurrent insert won → return true (replay)
        return Task.FromResult(!added);
    }

    private void PurgeExpired(DateTime now)
    {
        foreach (var kvp in _nonces)
        {
            if (kvp.Value.HasValue && kvp.Value.Value <= now)
            {
                _nonces.TryRemove(kvp.Key, out _);
            }
        }
    }
}
