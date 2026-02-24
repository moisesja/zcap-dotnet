using System.Text.Json.Serialization;

namespace ZcapLd.AspNetCore.Contracts;

/// <summary>
/// HTTP request payload for a revocation write operation.
/// </summary>
public sealed class RevokeCapabilityHttpRequest
{
    /// <summary>
    /// DID or identifier of the revoker.
    /// </summary>
    [JsonPropertyName("revokerDid")]
    public string RevokerDid { get; set; } = string.Empty;

    /// <summary>
    /// Optional root capability ID associated with the revoked capability.
    /// </summary>
    [JsonPropertyName("rootCapabilityId")]
    public string? RootCapabilityId { get; set; }

    /// <summary>
    /// Optional expiration timestamp for retention semantics.
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
    public Dictionary<string, string>? Metadata { get; set; }
}
