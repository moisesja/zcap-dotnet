using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a linked data proof for ZCAP-LD capabilities according to W3C Data Integrity specification.
/// Proofs use Data Integrity (DI) format, not JOSE-based signatures.
/// </summary>
public sealed class Proof
{
    /// <summary>
    /// Common proof purpose for capability delegation.
    /// </summary>
    public const string CapabilityDelegationPurpose = "capabilityDelegation";

    /// <summary>
    /// Common proof purpose for capability invocation.
    /// </summary>
    public const string CapabilityInvocationPurpose = "capabilityInvocation";

    /// <summary>
    /// Ed25519 signature type (2020 suite).
    /// </summary>
    public const string Ed25519Signature2020 = "Ed25519Signature2020";

    /// <summary>
    /// Ed25519 signature type (2018 suite).
    /// </summary>
    public const string Ed25519Signature2018 = "Ed25519Signature2018";

    /// <summary>
    /// Gets or sets the signature type (e.g., "Ed25519Signature2020").
    /// This field is REQUIRED.
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the timestamp when the proof was created.
    /// This field is REQUIRED and MUST be in ISO 8601 format.
    /// </summary>
    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

    /// <summary>
    /// Gets or sets the purpose of the proof.
    /// For delegation proofs: "capabilityDelegation"
    /// For invocation proofs: "capabilityInvocation"
    /// This field is REQUIRED.
    /// </summary>
    [JsonPropertyName("proofPurpose")]
    public string ProofPurpose { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the DID key URI used for verification.
    /// This MUST be a valid URI pointing to the verification method.
    /// This field is REQUIRED.
    /// </summary>
    [JsonPropertyName("verificationMethod")]
    public string VerificationMethod { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the chain of capabilities for delegation proofs.
    /// Per spec: ordered array where:
    /// - First entry: root capability ID (string)
    /// - Intermediate entries: delegated capability IDs (strings)
    /// - Last entry: parent capability (fully embedded object or string ID)
    /// This field is REQUIRED for delegation proofs.
    /// </summary>
    [JsonPropertyName("capabilityChain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object[]? CapabilityChain { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic signature value.
    /// This is typically a multibase-encoded signature (e.g., base58).
    /// This field is REQUIRED.
    /// </summary>
    [JsonPropertyName("proofValue")]
    public string ProofValue { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the capability being invoked (for invocation proofs only).
    /// This field is REQUIRED for invocation proofs.
    /// </summary>
    [JsonPropertyName("capability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Capability { get; set; }

    /// <summary>
    /// Creates a new delegation proof with the specified parameters.
    /// </summary>
    /// <param name="verificationMethod">The DID key URI for verification.</param>
    /// <param name="proofValue">The cryptographic signature value.</param>
    /// <param name="capabilityChain">The capability chain (root ID, intermediate IDs, parent).</param>
    /// <param name="signatureType">The signature type (defaults to Ed25519Signature2020).</param>
    /// <returns>A new delegation proof.</returns>
    public static Proof CreateDelegationProof(
        string verificationMethod,
        string proofValue,
        object[] capabilityChain,
        string signatureType = Ed25519Signature2020)
    {
        if (string.IsNullOrWhiteSpace(verificationMethod))
        {
            throw new ArgumentNullException(nameof(verificationMethod));
        }

        if (string.IsNullOrWhiteSpace(proofValue))
        {
            throw new ArgumentNullException(nameof(proofValue));
        }

        if (capabilityChain == null || capabilityChain.Length == 0)
        {
            throw new ArgumentNullException(nameof(capabilityChain), "Capability chain is required for delegation proofs.");
        }

        return new Proof
        {
            Type = signatureType,
            Created = DateTime.UtcNow,
            ProofPurpose = CapabilityDelegationPurpose,
            VerificationMethod = verificationMethod,
            CapabilityChain = capabilityChain,
            ProofValue = proofValue
        };
    }

    /// <summary>
    /// Creates a new invocation proof with the specified parameters.
    /// </summary>
    /// <param name="verificationMethod">The DID key URI for verification.</param>
    /// <param name="proofValue">The cryptographic signature value.</param>
    /// <param name="capabilityId">The ID of the capability being invoked.</param>
    /// <param name="signatureType">The signature type (defaults to Ed25519Signature2020).</param>
    /// <returns>A new invocation proof.</returns>
    public static Proof CreateInvocationProof(
        string verificationMethod,
        string proofValue,
        string capabilityId,
        string signatureType = Ed25519Signature2020)
    {
        if (string.IsNullOrWhiteSpace(verificationMethod))
        {
            throw new ArgumentNullException(nameof(verificationMethod));
        }

        if (string.IsNullOrWhiteSpace(proofValue))
        {
            throw new ArgumentNullException(nameof(proofValue));
        }

        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId));
        }

        return new Proof
        {
            Type = signatureType,
            Created = DateTime.UtcNow,
            ProofPurpose = CapabilityInvocationPurpose,
            VerificationMethod = verificationMethod,
            Capability = capabilityId,
            ProofValue = proofValue
        };
    }

    /// <summary>
    /// Validates the proof structure according to W3C ZCAP-LD specification.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    public void Validate()
    {
        ValidateCommonFields();

        if (ProofPurpose == CapabilityDelegationPurpose)
        {
            ValidateDelegationProof();
        }
        else if (ProofPurpose == CapabilityInvocationPurpose)
        {
            ValidateInvocationProof();
        }
        else
        {
            throw new CapabilityValidationException(
                $"Invalid proofPurpose. Expected '{CapabilityDelegationPurpose}' or '{CapabilityInvocationPurpose}', got: {ProofPurpose}",
                "INVALID_PROOF_PURPOSE");
        }
    }

    /// <summary>
    /// Validates fields common to all proof types.
    /// </summary>
    private void ValidateCommonFields()
    {
        if (string.IsNullOrWhiteSpace(Type))
        {
            throw new CapabilityValidationException(
                "Proof type is required.",
                "MISSING_PROOF_TYPE");
        }

        if (Created == default)
        {
            throw new CapabilityValidationException(
                "Proof created timestamp is required.",
                "MISSING_PROOF_CREATED");
        }

        if (Created > DateTime.UtcNow.AddMinutes(5)) // Allow 5 min clock skew
        {
            throw new CapabilityValidationException(
                $"Proof created timestamp is in the future: {Created:O}",
                "INVALID_PROOF_CREATED");
        }

        if (string.IsNullOrWhiteSpace(ProofPurpose))
        {
            throw new CapabilityValidationException(
                "Proof purpose is required.",
                "MISSING_PROOF_PURPOSE");
        }

        if (string.IsNullOrWhiteSpace(VerificationMethod))
        {
            throw new CapabilityValidationException(
                "Verification method is required.",
                "MISSING_VERIFICATION_METHOD");
        }

        if (!Uri.TryCreate(VerificationMethod, UriKind.Absolute, out _))
        {
            throw new CapabilityValidationException(
                $"Verification method must be a valid URI: {VerificationMethod}",
                "INVALID_VERIFICATION_METHOD_URI");
        }

        if (string.IsNullOrWhiteSpace(ProofValue))
        {
            throw new CapabilityValidationException(
                "Proof value (signature) is required.",
                "MISSING_PROOF_VALUE");
        }
    }

    /// <summary>
    /// Validates delegation-specific proof requirements.
    /// </summary>
    private void ValidateDelegationProof()
    {
        if (CapabilityChain == null || CapabilityChain.Length == 0)
        {
            throw new CapabilityValidationException(
                "Capability chain is required for delegation proofs.",
                "MISSING_CAPABILITY_CHAIN");
        }

        // Per spec: first entry must be root capability ID
        if (CapabilityChain[0] is not string rootId || string.IsNullOrWhiteSpace(rootId))
        {
            throw new CapabilityValidationException(
                "First entry in capability chain must be the root capability ID (string).",
                "INVALID_CAPABILITY_CHAIN_ROOT");
        }

        // Validate root ID format
        if (!rootId.StartsWith("urn:zcap:root:", StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability ID in chain must start with 'urn:zcap:root:'. Got: {rootId}",
                "INVALID_ROOT_ID_IN_CHAIN");
        }

        // If chain has more than one entry, intermediate entries should be strings (IDs)
        // Last entry is the parent capability (can be embedded object or ID)
        for (int i = 1; i < CapabilityChain.Length - 1; i++)
        {
            if (CapabilityChain[i] is not string intermediateId || string.IsNullOrWhiteSpace(intermediateId))
            {
                throw new CapabilityValidationException(
                    $"Intermediate capability chain entry at index {i} must be a capability ID (string).",
                    "INVALID_CAPABILITY_CHAIN_INTERMEDIATE");
            }
        }
    }

    /// <summary>
    /// Validates invocation-specific proof requirements.
    /// </summary>
    private void ValidateInvocationProof()
    {
        if (string.IsNullOrWhiteSpace(Capability))
        {
            throw new CapabilityValidationException(
                "Capability ID is required for invocation proofs.",
                "MISSING_INVOCATION_CAPABILITY");
        }

        if (!Uri.TryCreate(Capability, UriKind.Absolute, out _))
        {
            throw new CapabilityValidationException(
                $"Capability must be a valid URI: {Capability}",
                "INVALID_INVOCATION_CAPABILITY_URI");
        }
    }

    /// <summary>
    /// Checks if this is a delegation proof.
    /// </summary>
    /// <returns>True if this is a delegation proof; otherwise, false.</returns>
    public bool IsDelegationProof() => ProofPurpose == CapabilityDelegationPurpose;

    /// <summary>
    /// Checks if this is an invocation proof.
    /// </summary>
    /// <returns>True if this is an invocation proof; otherwise, false.</returns>
    public bool IsInvocationProof() => ProofPurpose == CapabilityInvocationPurpose;

    /// <summary>
    /// Gets the capability chain as an array of strings and objects.
    /// </summary>
    /// <returns>The capability chain, or empty array if not set.</returns>
    public object[] GetCapabilityChain()
    {
        return CapabilityChain ?? Array.Empty<object>();
    }

    /// <summary>
    /// Gets the root capability ID from the capability chain.
    /// </summary>
    /// <returns>The root capability ID, or null if chain is not set or invalid.</returns>
    public string? GetRootCapabilityId()
    {
        if (CapabilityChain == null || CapabilityChain.Length == 0)
        {
            return null;
        }

        return CapabilityChain[0] as string;
    }

    /// <summary>
    /// Checks if the proof was created within an acceptable time window.
    /// </summary>
    /// <param name="maxAgeMinutes">Maximum age in minutes (default: 5 minutes).</param>
    /// <returns>True if proof is recent; otherwise, false.</returns>
    public bool IsRecent(int maxAgeMinutes = 5)
    {
        var age = DateTime.UtcNow - Created;
        return age.TotalMinutes <= maxAgeMinutes;
    }
}
