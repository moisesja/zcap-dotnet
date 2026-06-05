using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a capability invocation request
/// SECURITY FIX S-04: Added id field for replay protection
/// </summary>
public class Invocation
{
    /// <summary>
    /// The <c>capabilityAction</c> value that marks a signed revocation request. Carried in the
    /// signed payload so the verifier can distinguish a revocation from any other invocation.
    /// </summary>
    public const string RevokeAction = "revoke";

    /// <summary>
    /// Unique identifier for this invocation (for replay protection)
    /// SECURITY: This should be a nonce, UUID, or timestamp-based identifier
    /// that is validated to prevent replay attacks
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = $"urn:uuid:{Guid.NewGuid()}";

    /// <summary>
    /// The capability being invoked. Per ZCAP-LD v0.3 this is the root zcap <b>id string</b> for a
    /// root invocation, or the <b>full embedded delegated zcap object</b> for a delegated DI
    /// invocation (Issue #51); <see cref="InvocationCapability"/> models both and preserves the wire
    /// shape. Assign a <see cref="string"/> id directly (implicit conversion) for root invocations and
    /// revocation requests, or <see cref="InvocationCapability.FromCapability"/> to embed a delegated
    /// zcap.
    /// </summary>
    [JsonPropertyName("capability")]
    public InvocationCapability Capability { get; set; } = string.Empty;

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

