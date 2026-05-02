using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a linked data proof for ZCAP-LD capabilities
/// </summary>
public class Proof
{
    /// <summary>
    /// The signature type (e.g., "Ed25519Signature2020")
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Timestamp when the proof was created, as the on-the-wire ISO-8601 string.
    /// Stored verbatim so cross-stack JCS canonicalization sees the same bytes the
    /// signer wrote — every other Data Integrity verifier JCS-canonicalizes this
    /// field as an opaque string. Use <see cref="CreatedAt"/> for a parsed DateTime view.
    /// </summary>
    [JsonPropertyName("created")]
    public string? Created { get; set; }

    /// <summary>
    /// Parsed UTC DateTime view of <see cref="Created"/>. Read-only — assign to
    /// <see cref="Created"/> with a string formatted via <see cref="ZcapTimestamps.Format"/>.
    /// </summary>
    [JsonIgnore]
    public DateTime? CreatedAt => ZcapTimestamps.ParseOrNull(Created);

    /// <summary>
    /// Purpose of the proof ("capabilityDelegation" or "capabilityInvocation")
    /// </summary>
    [JsonPropertyName("proofPurpose")]
    public string ProofPurpose { get; set; } = string.Empty;

    /// <summary>
    /// DID key URI used for verification
    /// </summary>
    [JsonPropertyName("verificationMethod")]
    public string VerificationMethod { get; set; } = string.Empty;

    /// <summary>
    /// Chain of capabilities for delegation proofs
    /// </summary>
    [JsonPropertyName("capabilityChain")]
    public object[] CapabilityChain { get; set; } = Array.Empty<object>();

    /// <summary>
    /// The cryptographic signature value
    /// </summary>
    [JsonPropertyName("proofValue")]
    public string ProofValue { get; set; } = string.Empty;

    /// <summary>
    /// The capability being invoked (for invocation proofs)
    /// Can be a string (root capability ID) or object (delegated capability)
    /// </summary>
    [JsonPropertyName("capability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Capability { get; set; }

    /// <summary>
    /// The invocation target (for invocation proofs)
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InvocationTarget { get; set; }

    /// <summary>
    /// The capability action being invoked (for invocation proofs)
    /// </summary>
    [JsonPropertyName("capabilityAction")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CapabilityAction { get; set; }

    /// <summary>
    /// Catches any proof fields not declared above (e.g. `domain`, `nonce`, `id`,
    /// `challenge`, custom extensions) and round-trips them verbatim through both
    /// JSON deserialization and JCS canonicalization. Without this, cross-stack
    /// signatures over proofs carrying such fields fail verification because the
    /// fields would be silently dropped on our side.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}
