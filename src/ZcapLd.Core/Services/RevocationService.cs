using System.Collections.ObjectModel;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default revocation workflow implementation using a pluggable store.
/// </summary>
public sealed class RevocationService : IRevocationService
{
    private readonly IRevocationStore _store;
    private readonly TimeProvider _timeProvider;

    public RevocationService(IRevocationStore store, TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<RevocationRecord> RevokeAsync(RevocationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.CapabilityId))
        {
            throw new ArgumentException("Capability ID cannot be null or empty.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.RevokedBy))
        {
            throw new ArgumentException("Revoker identifier cannot be null or empty.", nameof(request));
        }

        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyDictionary<string, string>? metadata = null;
        if (request.Metadata != null && request.Metadata.Count > 0)
        {
            metadata = new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(request.Metadata, StringComparer.Ordinal));
        }

        var record = new RevocationRecord
        {
            CapabilityId = request.CapabilityId,
            RootCapabilityId = request.RootCapabilityId,
            RevokedBy = request.RevokedBy,
            RevokedAt = _timeProvider.GetUtcNow().UtcDateTime,
            ExpiresAt = request.ExpiresAt,
            Reason = request.Reason,
            Metadata = metadata
        };

        await _store.UpsertAsync(record, cancellationToken);
        return record;
    }

    public async Task<RevocationRecord?> GetRevocationAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();

        var record = await _store.GetByCapabilityIdAsync(capabilityId, cancellationToken);
        if (record == null)
        {
            return null;
        }

        if (IsExpired(record))
        {
            await _store.DeleteAsync(capabilityId, cancellationToken);
            return null;
        }

        return record;
    }

    public async Task<bool> IsRevokedAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        var record = await GetRevocationAsync(capabilityId, cancellationToken);
        return record != null;
    }

    private bool IsExpired(RevocationRecord record)
    {
        if (!record.ExpiresAt.HasValue)
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        return record.ExpiresAt.Value <= now;
    }
}
