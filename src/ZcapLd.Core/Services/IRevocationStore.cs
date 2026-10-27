using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Pluggable persistence abstraction for capability revocation records.
/// </summary>
/// <remarks>
/// Capability ids are keys compared <b>ordinally</b>: exact, case-sensitive, with no Unicode or
/// percent-encoding normalization, as everywhere else in the verifier. A backend whose keys compare
/// case-insensitively or normalize (for example SQL Server's or MySQL's default collations) maps
/// distinct ids onto one record, so a revocation recorded for one id would apply to another. Use a
/// binary or case-sensitive collation, as the in-memory store and the SQLite demo do.
/// </remarks>
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
