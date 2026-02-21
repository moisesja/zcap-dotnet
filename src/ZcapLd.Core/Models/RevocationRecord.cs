namespace ZcapLd.Core.Models;

/// <summary>
/// Persisted revocation record for a capability ID.
/// </summary>
public sealed record RevocationRecord
{
    /// <summary>
    /// Capability ID that has been revoked.
    /// </summary>
    public string CapabilityId { get; init; } = string.Empty;

    /// <summary>
    /// Optional root capability ID associated with the revoked capability.
    /// </summary>
    public string? RootCapabilityId { get; init; }

    /// <summary>
    /// DID or identifier of the actor that requested revocation.
    /// </summary>
    public string RevokedBy { get; init; } = string.Empty;

    /// <summary>
    /// UTC timestamp for when revocation was recorded.
    /// </summary>
    public DateTime RevokedAt { get; init; }

    /// <summary>
    /// UTC expiration timestamp for revocation retention.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>
    /// Optional free-form reason associated with the revocation.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Optional metadata for storage-provider-specific context.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
