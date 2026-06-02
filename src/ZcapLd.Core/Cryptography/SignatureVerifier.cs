using ZcapLd.Core.Models;

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
    /// <param name="suite">The crypto suite to use for verification</param>
    /// <param name="canonicalizer">Optional canonicalizer (defaults to JCS)</param>
    /// <returns>True if signature is valid</returns>
    public static bool VerifyCapabilitySignature(
        Capability capability,
        byte[] publicKey,
        ICryptoSuite suite,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        if (capability.Proof == null || capability.Proof.IsEmpty)
            return false;

        // A delegated zcap's proof may be an array; verify the delegation proof (the one that
        // carries the capabilityChain), falling back to the first proof for non-standard inputs.
        var proof = capability.Proof.FirstDelegationProof() ?? capability.Proof.Primary;

        try
        {
            var capabilityForVerification = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
            var canonicalizedData = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
                capabilityForVerification,
                proof,
                canonicalizer);

            // Decode the signature
            var signature = MultibaseCodec.Decode(proof.ProofValue);

            // Verify the signature
            return suite.Verify(canonicalizedData, signature, publicKey);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an invocation signature using the specified crypto suite.
    /// </summary>
    /// <param name="invocation">The invocation to verify</param>
    /// <param name="publicKey">The public key for verification</param>
    /// <param name="suite">The crypto suite to use for verification</param>
    /// <param name="canonicalizer">Optional canonicalizer (defaults to JCS)</param>
    /// <returns>True if signature is valid</returns>
    public static bool VerifyInvocationSignature(
        Invocation invocation,
        byte[] publicKey,
        ICryptoSuite suite,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        if (invocation.Proof == null)
            return false;

        try
        {
            var invocationForVerification = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
            var canonicalizedData = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
                invocationForVerification,
                invocation.Proof,
                canonicalizer);

            // Decode the signature
            var signature = MultibaseCodec.Decode(invocation.Proof.ProofValue);

            // Verify the signature
            return suite.Verify(canonicalizedData, signature, publicKey);
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
               !string.IsNullOrEmpty(proof.Created);
    }
}
