using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a ZCAP-LD capability document according to W3C specification
/// </summary>
public class Capability
{
    /// <summary>
    /// The unique identifier for this capability (URI)
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// JSON-LD context for the capability
    /// </summary>
    [JsonPropertyName("@context")]
    public object Context { get; set; } = "https://w3id.org/zcap/v1";

    /// <summary>
    /// The DID of the entity issuing this capability
    /// </summary>
    [JsonPropertyName("controller")]
    public string Controller { get; set; } = string.Empty;

    /// <summary>
    /// The target resource URI this capability grants access to
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    public string InvocationTarget { get; set; } = string.Empty;

    /// <summary>
    /// Actions allowed by this capability (e.g., "read", "write")
    /// </summary>
    [JsonPropertyName("allowedAction")]
    public string[] AllowedAction { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Optional expiration timestamp for this capability
    /// </summary>
    [JsonPropertyName("expires")]
    public DateTime? Expires { get; set; }

    /// <summary>
    /// Reference to parent capability for delegated capabilities
    /// </summary>
    [JsonPropertyName("parentCapability")]
    public string? ParentCapability { get; set; }

    /// <summary>
    /// List of caveats (restrictions) for this capability
    /// </summary>
    [JsonPropertyName("caveat")]
    public Caveat[] Caveat { get; set; } = Array.Empty<Caveat>();

    /// <summary>
    /// Cryptographic proof for this capability
    /// </summary>
    [JsonPropertyName("proof")]
    public Proof? Proof { get; set; }
}