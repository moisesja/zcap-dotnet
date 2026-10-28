using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Signs an RDFC-1.0 payload with a raw key, bypassing <c>SigningService</c>'s issuer-side checks.
/// An attacker uses their own signer, so adversarial tests must be able to produce a valid
/// signature over input the library would refuse to sign. By default the payload comes from
/// <see cref="LenientRdfcCanonicalizer"/>, as on an attacker's lenient stack, so a document
/// DataProofs refuses to canonicalize still gets the signature such a stack would produce.
/// </summary>
internal static class RawProofSigner
{
    private const string ProofType = "Ed25519Signature2020";

    public static async Task<Proof> SignCapabilityAsync(
        InMemoryDidProvider keys, Capability capability, string signerDid, object[] capabilityChain,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        var proof = new Proof
        {
            Type = ProofType,
            Created = ZcapTimestamps.Format(DateTime.UtcNow),
            ProofPurpose = Proof.CapabilityDelegationPurpose,
            VerificationMethod = await keys.GetVerificationMethodAsync(signerDid),
            CapabilityChain = capabilityChain,
            ProofValue = string.Empty,
        };
        var payload = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability), proof,
            canonicalizer ?? LenientRdfcCanonicalizer.Instance);
        proof.ProofValue = MultibaseCodec.Encode((await keys.SignAsync(signerDid, payload)).Signature);
        return proof;
    }

    public static async Task<Proof> SignInvocationAsync(
        InMemoryDidProvider keys, Invocation invocation, string signerDid,
        string proofPurpose = Proof.CapabilityInvocationPurpose)
    {
        var proof = new Proof
        {
            Type = ProofType,
            Created = ZcapTimestamps.Format(DateTime.UtcNow),
            ProofPurpose = proofPurpose,
            VerificationMethod = await keys.GetVerificationMethodAsync(signerDid),
            Capability = invocation.Capability,
            CapabilityAction = invocation.CapabilityAction,
            InvocationTarget = invocation.InvocationTarget,
            ProofValue = string.Empty,
        };
        var payload = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation), proof, LenientRdfcCanonicalizer.Instance);
        proof.ProofValue = MultibaseCodec.Encode((await keys.SignAsync(signerDid, payload)).Signature);
        return proof;
    }
}
