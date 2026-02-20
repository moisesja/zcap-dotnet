using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for verifying ZCAP-LD capabilities and invocations
/// </summary>
public interface IVerificationService
{
    /// <summary>
    /// Verifies a capability's cryptographic proof
    /// </summary>
    /// <param name="capability">The capability to verify</param>
    /// <returns>True if the proof is valid</returns>
    Task<bool> VerifyCapabilityProofAsync(Capability capability);

    /// <summary>
    /// Verifies an invocation request
    /// </summary>
    /// <param name="invocation">The invocation to verify</param>
    /// <param name="capability">The capability being invoked</param>
    /// <returns>True if the invocation is valid</returns>
    Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability);

    /// <summary>
    /// Verifies a capability delegation chain
    /// </summary>
    /// <param name="capability">The capability with delegation chain</param>
    /// <returns>True if the chain is valid</returns>
    Task<bool> VerifyCapabilityChainAsync(Capability capability);

    /// <summary>
    /// Resolves a DID to its public key for verification
    /// </summary>
    /// <param name="did">The DID to resolve</param>
    /// <returns>The public key bytes</returns>
    Task<byte[]> ResolvePublicKeyAsync(string did);

    /// <summary>
    /// Revokes a capability by ID
    /// COMPLIANCE FIX: MUST-21, SHOULD-07 - Revocation support
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to revoke</param>
    /// <param name="revokerDid">The DID of the entity performing the revocation</param>
    /// <returns>True if revocation was successful</returns>
    Task<bool> RevokeCapabilityAsync(string capabilityId, string revokerDid);

    /// <summary>
    /// Checks if a capability has been revoked
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to check</param>
    /// <returns>True if the capability has been revoked</returns>
    Task<bool> IsCapabilityRevokedAsync(string capabilityId);
}