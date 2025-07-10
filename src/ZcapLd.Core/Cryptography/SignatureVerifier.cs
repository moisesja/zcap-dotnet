using ZcapLd.Core.Models;
using System.Text.Json;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Service for verifying cryptographic signatures on ZCAP-LD documents
/// </summary>
public class SignatureVerifier
{
    /// <summary>
    /// Verifies a proof signature against a capability
    /// </summary>
    /// <param name="capability">The capability to verify</param>
    /// <param name="publicKey">The public key for verification</param>
    /// <returns>True if signature is valid</returns>
    public static bool VerifyCapabilitySignature(Capability capability, byte[] publicKey)
    {
        if (capability.Proof == null)
            return false;

        try
        {
            // Create a copy of the capability without the proof for verification
            var capabilityForVerification = new Capability
            {
                Id = capability.Id,
                Context = capability.Context,
                Controller = capability.Controller,
                InvocationTarget = capability.InvocationTarget,
                AllowedAction = capability.AllowedAction,
                Expires = capability.Expires,
                ParentCapability = capability.ParentCapability,
                Caveat = capability.Caveat
                // Note: Proof is excluded for signature verification
            };

            // Canonicalize the document
            var canonicalizedData = Ed25519Signer.CanonicalizeDocument(capabilityForVerification);

            // Decode the signature
            var signature = Ed25519Signer.DecodeSignature(capability.Proof.ProofValue);

            // Verify the signature
            return Ed25519Signer.Verify(canonicalizedData, signature, publicKey);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an invocation signature
    /// </summary>
    /// <param name="invocation">The invocation to verify</param>
    /// <param name="publicKey">The public key for verification</param>
    /// <returns>True if signature is valid</returns>
    public static bool VerifyInvocationSignature(Invocation invocation, byte[] publicKey)
    {
        if (invocation.Proof == null)
            return false;

        try
        {
            // Create a copy of the invocation without the proof for verification
            var invocationForVerification = new Invocation
            {
                Capability = invocation.Capability,
                CapabilityAction = invocation.CapabilityAction,
                InvocationTarget = invocation.InvocationTarget
                // Note: Proof is excluded for signature verification
            };

            // Canonicalize the document
            var canonicalizedData = Ed25519Signer.CanonicalizeDocument(invocationForVerification);

            // Decode the signature
            var signature = Ed25519Signer.DecodeSignature(invocation.Proof.ProofValue);

            // Verify the signature
            return Ed25519Signer.Verify(canonicalizedData, signature, publicKey);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates the structure of a proof object
    /// </summary>
    /// <param name="proof">The proof to validate</param>
    /// <returns>True if proof structure is valid</returns>
    public static bool ValidateProofStructure(Proof proof)
    {
        return !string.IsNullOrEmpty(proof.Type) &&
               !string.IsNullOrEmpty(proof.ProofPurpose) &&
               !string.IsNullOrEmpty(proof.VerificationMethod) &&
               !string.IsNullOrEmpty(proof.ProofValue) &&
               proof.Created != default;
    }
}