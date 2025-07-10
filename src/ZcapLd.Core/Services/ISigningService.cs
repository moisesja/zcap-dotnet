using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for cryptographic signing operations
/// </summary>
public interface ISigningService
{
    /// <summary>
    /// Signs a capability with the specified signing key
    /// </summary>
    /// <param name="capability">The capability to sign</param>
    /// <param name="signerDid">The DID of the signer</param>
    /// <param name="proofPurpose">The purpose of the proof</param>
    /// <param name="capabilityChain">The capability chain for delegation proofs</param>
    /// <returns>The signed proof</returns>
    Task<Proof> SignCapabilityAsync(
        Capability capability,
        string signerDid,
        string proofPurpose,
        object[]? capabilityChain = null);

    /// <summary>
    /// Signs an invocation request
    /// </summary>
    /// <param name="invocation">The invocation to sign</param>
    /// <param name="signerDid">The DID of the signer</param>
    /// <returns>The signed proof</returns>
    Task<Proof> SignInvocationAsync(Invocation invocation, string signerDid);

    /// <summary>
    /// Gets the verification method URI for a DID
    /// </summary>
    /// <param name="did">The DID to resolve</param>
    /// <returns>The verification method URI</returns>
    Task<string> GetVerificationMethodAsync(string did);
}