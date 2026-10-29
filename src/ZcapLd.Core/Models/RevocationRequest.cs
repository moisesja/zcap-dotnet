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
    /// The scope to record the revocation in (#158). The signed revocation path supplies the scope the
    /// capability was authorized under; an operator writing a record directly must choose one
    /// deliberately. <see cref="RevocationScope.Unscoped"/> applies to the id on every chain, which is
    /// the 5.x behaviour and is appropriate only for an id the operator knows to be unique.
    /// </summary>
    public required RevocationScope Scope { get; set; }

    /// <summary>
    /// The root of the chain the revocation was authorized on, when known. Informational only.
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
