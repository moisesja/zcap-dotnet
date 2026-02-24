using System.Text.Json.Serialization;

namespace ZcapLd.AspNetCore.Contracts;

/// <summary>
/// HTTP response payload for capability revocation status.
/// </summary>
public sealed class RevocationStatusHttpResponse
{
    /// <summary>
    /// Capability ID queried or updated.
    /// </summary>
    [JsonPropertyName("capabilityId")]
    public string CapabilityId { get; set; } = string.Empty;

    /// <summary>
    /// Whether the capability currently has an active revocation record.
    /// </summary>
    [JsonPropertyName("isRevoked")]
    public bool IsRevoked { get; set; }

    /// <summary>
    /// Optional root capability ID associated with the revocation.
    /// </summary>
    [JsonPropertyName("rootCapabilityId")]
    public string? RootCapabilityId { get; set; }

    /// <summary>
    /// DID or identifier of the revoker.
    /// </summary>
    [JsonPropertyName("revokedBy")]
    public string? RevokedBy { get; set; }

    /// <summary>
    /// UTC time the revocation was recorded.
    /// </summary>
    [JsonPropertyName("revokedAt")]
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Optional expiration timestamp for revocation retention.
    /// </summary>
    [JsonPropertyName("expiresAt")]
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Optional reason associated with the revocation request.
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>
    /// Optional backend-specific metadata.
    /// </summary>
    [JsonPropertyName("metadata")]
    public IReadOnlyDictionary<string, string>? Metadata { get; set; }
}
