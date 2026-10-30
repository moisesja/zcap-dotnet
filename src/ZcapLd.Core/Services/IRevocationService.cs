using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// High-level revocation workflow service backed by a pluggable store.
/// </summary>
public interface IRevocationService
{
    /// <summary>
    /// Persists a revocation request. This is the persistence primitive: it performs no authentication
    /// or authorization. Route untrusted requests through
    /// <see cref="IVerificationService.RevokeCapabilityAsync(Capability, Invocation)"/> instead.
    /// </summary>
    Task<RevocationRecord> RevokeAsync(RevocationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the active revocation record for a capability id in <paramref name="scope"/>: the record in
    /// that scope, or else the <see cref="RevocationScope.Unscoped"/> record for the id.
    /// </summary>
    Task<RevocationRecord?> GetRevocationAsync(string capabilityId, RevocationScope scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns true when <see cref="GetRevocationAsync"/> finds an active record.
    /// </summary>
    Task<bool> IsRevokedAsync(string capabilityId, RevocationScope scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds the first active record for <paramref name="lookups"/> in order, consulting each lookup's
    /// own scope and the unscoped record for its id, with a single store read.
    /// </summary>
    Task<RevocationRecord?> FindRevocationAsync(IReadOnlyList<RevocationLookup> lookups, CancellationToken cancellationToken = default);
}
