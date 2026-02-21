using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for assembling ZCAP-LD cryptographic proofs.
/// Delegates signing and DID resolution to an <see cref="IDidProvider"/>.
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
}
