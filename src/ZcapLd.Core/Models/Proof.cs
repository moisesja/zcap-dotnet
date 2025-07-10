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
    /// Timestamp when the proof was created
    /// </summary>
    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

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
}