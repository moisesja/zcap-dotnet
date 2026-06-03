using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for assembling ZCAP-LD cryptographic proofs.
/// Delegates signing to an <see cref="IDidSigner"/> and DID resolution
/// to an <see cref="IDidResolver"/>.
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
    /// Produces a signed capability revocation request (proof-of-possession) bound to
    /// <paramref name="capabilityId"/>, with <c>proofPurpose = capabilityRevocation</c> and
    /// <c>capabilityAction = revoke</c>. Present the returned <see cref="Invocation"/> (alongside
    /// the full capability) to <see cref="IVerificationService.RevokeCapabilityAsync(Capability, Invocation)"/>.
    /// </summary>
    /// <param name="capabilityId">The id of the capability to revoke (bound into the signed payload).</param>
    /// <param name="signerDid">The DID whose key signs the request (must control the capability or an ancestor).</param>
    /// <param name="invocationTarget">The capability's invocation target (bound into the signed payload).</param>
    /// <param name="reason">Optional human-readable reason, signed and recorded on the revocation.</param>
    /// <param name="metadata">Optional audit metadata, signed and recorded on the revocation.</param>
    /// <returns>A signed revocation invocation.</returns>
    Task<Invocation> SignRevocationAsync(
        string capabilityId,
        string signerDid,
        string invocationTarget,
        string? reason = null,
        IDictionary<string, string>? metadata = null);

    /// <summary>
    /// Resolves the JSON-LD security suite context URL for a signer's key type.
    /// Used by <see cref="CapabilityService"/> to set the correct context on delegated capabilities.
    /// </summary>
    /// <param name="signerDid">The DID of the signer</param>
    /// <returns>The suite's context URL (e.g. "https://w3id.org/security/suites/ed25519-2020/v1")</returns>
    Task<string> ResolveSuiteContextUrlAsync(string signerDid);
}
