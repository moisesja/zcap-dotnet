using System.Text.Json;
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
    /// The controller(s) of this capability — the DID(s) authorized over it.
    /// Per ZCAP-LD v0.3, <c>controller</c> may be a single URI string or an array of
    /// URI strings; <see cref="ControllerSet"/> models both and preserves the wire shape.
    /// Assign a <see cref="string"/> or <c>string[]</c> directly (implicit conversion).
    /// </summary>
    [JsonPropertyName("controller")]
    public ControllerSet Controller { get; set; } = ControllerSet.Empty;

    /// <summary>
    /// The target resource URI this capability grants access to
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    public string InvocationTarget { get; set; } = string.Empty;

    /// <summary>
    /// Actions allowed by this capability (e.g., "read", "write").
    /// Null on root capabilities (unbounded authority); omitted from the wire when null.
    /// Strict cross-language parsers (zcap-py and friends) reject empty arrays here.
    /// </summary>
    [JsonPropertyName("allowedAction")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? AllowedAction { get; set; }

    /// <summary>
    /// Optional expiration timestamp, as the on-the-wire ISO-8601 string. Stored
    /// verbatim so cross-stack JCS canonicalization sees the same bytes the signer
    /// wrote. Use <see cref="ExpiresAt"/> for a parsed DateTime view.
    /// </summary>
    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Expires { get; set; }

    /// <summary>
    /// Parsed UTC DateTime view of <see cref="Expires"/>. Read-only — assign to
    /// <see cref="Expires"/> with a string formatted via <see cref="ZcapTimestamps.Format"/>.
    /// </summary>
    [JsonIgnore]
    public DateTime? ExpiresAt => ZcapTimestamps.ParseOrNull(Expires);

    /// <summary>
    /// Reference to parent capability for delegated capabilities
    /// </summary>
    [JsonPropertyName("parentCapability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ParentCapability { get; set; }

    /// <summary>
    /// List of caveats (restrictions) for this capability.
    /// Null on root capabilities (no restrictions); omitted from the wire when null.
    /// </summary>
    [JsonPropertyName("caveat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Caveat[]? Caveat { get; set; }

    /// <summary>
    /// Cryptographic proof for this capability
    /// </summary>
    [JsonPropertyName("proof")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Proof? Proof { get; set; }

    /// <summary>
    /// Catches any capability fields not declared above and round-trips them
    /// verbatim through both JSON deserialization and JCS canonicalization. Without
    /// this, cross-stack signatures over capabilities carrying unmodeled fields
    /// fail verification because the fields would be silently dropped on our side.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}
