using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Pluggable persistence abstraction for capability revocation records.
/// </summary>
public interface IRevocationStore
{
    /// <summary>
    /// Inserts or updates a revocation record.
    /// </summary>
    Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a revocation record by capability ID.
    /// </summary>
    Task<RevocationRecord?> GetByCapabilityIdAsync(string capabilityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a revocation record by capability ID.
    /// </summary>
    Task DeleteAsync(string capabilityId, CancellationToken cancellationToken = default);
}
