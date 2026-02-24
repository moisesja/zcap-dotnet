namespace ZcapLd.Core.Models;

/// <summary>
/// Request payload used to persist a revocation.
/// </summary>
public sealed class RevocationRequest
{
    /// <summary>
    /// Capability ID to revoke.
    /// </summary>
    public string CapabilityId { get; set; } = string.Empty;

    /// <summary>
    /// Optional root capability ID associated with the capability being revoked.
    /// </summary>
    public string? RootCapabilityId { get; set; }

    /// <summary>
    /// DID or identifier of the actor requesting revocation.
    /// </summary>
    public string RevokedBy { get; set; } = string.Empty;

    /// <summary>
    /// Capability expiration used for revocation retention semantics.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Optional free-form reason associated with the revocation request.
    /// </summary>
    public string? Reason { get; set; }

    /// <summary>
    /// Optional storage-provider-specific metadata.
    /// </summary>
    public IDictionary<string, string>? Metadata { get; set; }
}
