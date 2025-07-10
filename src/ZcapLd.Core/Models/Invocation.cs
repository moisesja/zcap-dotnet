using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a capability invocation request
/// </summary>
public class Invocation
{
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
    public Proof? Proof { get; set; }
}

