using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a capability invocation request
/// SECURITY FIX S-04: Added id field for replay protection
/// </summary>
public class Invocation
{
    /// <summary>
    /// Unique identifier for this invocation (for replay protection)
    /// SECURITY: This should be a nonce, UUID, or timestamp-based identifier
    /// that is validated to prevent replay attacks
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = $"urn:uuid:{Guid.NewGuid()}";

    /// <summary>
    /// Reference to the capability being invoked
    /// </summary>
    [JsonPropertyName("capability")]
    public string Capability { get; set; } = string.Empty;

    /// <summary>
    /// The action being requested
    /// </summary>
    [JsonPropertyName("capabilityAction")]
    public string CapabilityAction { get; set; } = string.Empty;

    /// <summary>
    /// Target resource for the invocation
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    public string InvocationTarget { get; set; } = string.Empty;

    /// <summary>
    /// Proof of invocation
    /// </summary>
    [JsonPropertyName("proof")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Proof? Proof { get; set; }
}

