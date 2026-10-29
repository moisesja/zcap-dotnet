using System.Collections.ObjectModel;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default revocation workflow implementation using a pluggable store.
/// </summary>
/// <remarks>
/// Guards the store contract (#158): a record the store returns must be one this service asked for,
/// keyed consistently with its own id and scope, and a record just written must read back unchanged.
/// A violation throws, so the verifier fails closed (<c>CouldNotVerify</c>, or a false revocation
/// result with the replay nonce unconsumed) rather than treating a scoped revocation as global or as
/// missing.
/// </remarks>
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

        if (request.Scope is null)
        {
            throw new ArgumentException("Revocation scope cannot be null.", nameof(request));
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
            Scope = request.Scope,
            RootCapabilityId = request.RootCapabilityId,
            RevokedBy = request.RevokedBy,
            RevokedAt = _timeProvider.GetUtcNow().UtcDateTime,
            ExpiresAt = request.ExpiresAt,
            Reason = request.Reason,
            Metadata = metadata
        };

        await _store.UpsertAsync(record, cancellationToken);

        // Read the record back under its key. A store that drops the scope, rewrites it, or keys by the
        // bare id would otherwise turn this scoped revocation into a global one or into nothing, and the
        // signed path would consume its replay nonce believing the write succeeded.
        var requested = new HashSet<string>(StringComparer.Ordinal) { record.Key };
        var stored = (await _store.GetAsync(requested, cancellationToken))
            .FirstOrDefault(entry => entry is not null && ValidateReturned(entry, requested) && string.Equals(entry.Key, record.Key, StringComparison.Ordinal));
        if (stored is null ||
            !string.Equals(stored.CapabilityId, record.CapabilityId, StringComparison.Ordinal) ||
            !record.Scope.Equals(stored.Scope))
        {
            throw new InvalidOperationException(
                $"The revocation store did not persist the record for '{record.CapabilityId}' ({record.Scope}) under its key.");
        }

        return record;
    }

    public Task<RevocationRecord?> GetRevocationAsync(string capabilityId, RevocationScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return Task.FromResult<RevocationRecord?>(null);
        }

        return FindRevocationAsync([new RevocationLookup(capabilityId, scope)], cancellationToken);
    }

    public async Task<bool> IsRevokedAsync(string capabilityId, RevocationScope scope, CancellationToken cancellationToken = default)
    {
        var record = await GetRevocationAsync(capabilityId, scope, cancellationToken);
        return record != null;
    }

    public async Task<RevocationRecord?> FindRevocationAsync(IReadOnlyList<RevocationLookup> lookups, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lookups);
        if (lookups.Count == 0)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Each lookup asks for its own scope and, unless it is already unscoped, for the unscoped record
        // of the same id. Keys keep lookup order so the first revoked lookup is the one reported.
        var ordered = new List<string>();
        var requested = new HashSet<string>(StringComparer.Ordinal);
        foreach (var lookup in lookups)
        {
            if (string.IsNullOrWhiteSpace(lookup.CapabilityId) || lookup.Scope is null)
            {
                throw new ArgumentException("Every lookup needs a capability id and a scope.", nameof(lookups));
            }

            if (requested.Add(lookup.Scope.KeyFor(lookup.CapabilityId)))
            {
                ordered.Add(lookup.Scope.KeyFor(lookup.CapabilityId));
            }

            if (lookup.Scope.Kind != RevocationScopeKind.Unscoped &&
                requested.Add(RevocationScope.Unscoped.KeyFor(lookup.CapabilityId)))
            {
                ordered.Add(RevocationScope.Unscoped.KeyFor(lookup.CapabilityId));
            }
        }

        var byKey = new Dictionary<string, RevocationRecord>(StringComparer.Ordinal);
        foreach (var record in await _store.GetAsync(ordered, cancellationToken))
        {
            if (!ValidateReturned(record, requested))
            {
                throw new InvalidOperationException(
                    "The revocation store returned a record that was not requested or is keyed inconsistently with its id and scope.");
            }

            byKey[record.Key] = record;
        }

        foreach (var key in ordered)
        {
            if (!byKey.TryGetValue(key, out var record))
            {
                continue;
            }

            if (IsExpired(record))
            {
                // Expiry cleanup deletes by the exact key: deleting by id would let a short-lived record
                // in one scope remove a legitimate record for the same id in another.
                await _store.DeleteAsync(key, cancellationToken);
                continue;
            }

            return record;
        }

        return null;
    }

    /// <summary>True when the store returned a well-formed record under one of the requested keys.</summary>
    private static bool ValidateReturned(RevocationRecord? record, HashSet<string> requested)
        => record is not null
           && !string.IsNullOrWhiteSpace(record.CapabilityId)
           && record.Scope is not null
           && requested.Contains(record.Key);

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
