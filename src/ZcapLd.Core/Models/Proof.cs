using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a linked data proof for ZCAP-LD capabilities
/// </summary>
public class Proof
{
    /// <summary>
    /// The <c>proofPurpose</c> for a capability invocation proof.
    /// </summary>
    public const string CapabilityInvocationPurpose = "capabilityInvocation";

    /// <summary>
    /// The <c>proofPurpose</c> for a capability delegation proof.
    /// </summary>
    public const string CapabilityDelegationPurpose = "capabilityDelegation";

    /// <summary>
    /// The <c>proofPurpose</c> for a signed capability revocation request. Deliberately distinct
    /// from <see cref="CapabilityInvocationPurpose"/> so a revocation request's signed bytes are
    /// disjoint from any normal invocation — a normal invocation can never be replayed as a
    /// revocation, nor vice-versa, regardless of the <c>capabilityAction</c> an application uses.
    /// </summary>
    public const string CapabilityRevocationPurpose = "capabilityRevocation";

    /// <summary>
    /// Signed proof extension key (in <see cref="AdditionalProperties"/>) carrying a revocation's
    /// human-readable reason. Shared by the signing and verification revocation paths.
    /// </summary>
    internal const string RevocationReasonField = "revocationReason";

    /// <summary>
    /// Signed proof extension key (in <see cref="AdditionalProperties"/>) carrying a revocation's
    /// audit metadata. Shared by the signing and verification revocation paths.
    /// </summary>
    internal const string RevocationMetadataField = "revocationMetadata";

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
    /// Chain of capabilities for delegation proofs.
    /// Null on invocation proofs (which reference the capability via the
    /// <see cref="Capability"/> field instead) and omitted from the wire when null —
    /// strict cross-language parsers reject `"capabilityChain": []` for the same
    /// reason they reject empty `allowedAction`.
    /// </summary>
    [JsonPropertyName("capabilityChain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object[]? CapabilityChain { get; set; }

    /// <summary>
    /// The cryptographic signature value
    /// </summary>
    [JsonPropertyName("proofValue")]
    public string ProofValue { get; set; } = string.Empty;

    /// <summary>
    /// The capability being invoked (for invocation/revocation proofs). Per ZCAP-LD v0.3 this is the
    /// root zcap <b>id string</b> for a root invocation, or the <b>full embedded delegated zcap
    /// object</b> for a delegated DI invocation (Issue #51); <see cref="InvocationCapability"/> models
    /// both and preserves the wire shape so the field canonicalizes identically on the signing and
    /// verification sides. Null on delegation proofs (which reference the chain via
    /// <see cref="CapabilityChain"/> instead) and omitted from the wire when null.
    /// </summary>
    [JsonPropertyName("capability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InvocationCapability? Capability { get; set; }

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
