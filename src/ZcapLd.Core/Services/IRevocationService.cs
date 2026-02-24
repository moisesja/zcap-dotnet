using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// High-level revocation workflow service backed by a pluggable store.
/// </summary>
public interface IRevocationService
{
    /// <summary>
    /// Persists a revocation request.
    /// </summary>
    Task<RevocationRecord> RevokeAsync(RevocationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the active revocation record for a capability ID.
    /// </summary>
    Task<RevocationRecord?> GetRevocationAsync(string capabilityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns true when a capability has an active revocation record.
    /// </summary>
    Task<bool> IsRevokedAsync(string capabilityId, CancellationToken cancellationToken = default);
}
