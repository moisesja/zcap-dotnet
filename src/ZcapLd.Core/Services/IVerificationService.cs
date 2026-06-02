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
    /// Verifies an invocation request with application-specific context properties.
    /// Properties are merged into <see cref="InvocationContext.Properties"/> before caveat evaluation,
    /// enabling custom caveats to read request-scoped metadata (e.g. content type, schema URI, caller IP).
    /// </summary>
    /// <param name="invocation">The invocation to verify</param>
    /// <param name="capability">The capability being invoked</param>
    /// <param name="contextProperties">Application-specific key/value pairs to inject into the invocation context</param>
    /// <returns>True if the invocation is valid</returns>
    Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability, Dictionary<string, object>? contextProperties);

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
    /// <returns>A <see cref="ResolvedKey"/> containing the public key bytes and key type</returns>
    Task<ResolvedKey> ResolvePublicKeyAsync(string did);

    /// <summary>
    /// Revokes a capability after verifying the revoker is authorized. A revoker is authorized
    /// when it controls the capability itself or any ancestor in its delegation chain (an up-chain
    /// delegator). <paramref name="revokerDid"/> is expected to be a DID the host has already
    /// <i>authenticated</i> — the library performs authorization, not authentication. Returns
    /// <c>false</c> (recording nothing) when the revoker is not authorized or the chain cannot be
    /// cryptographically verified.
    /// COMPLIANCE: MUST-21, SHOULD-07 — revocation support.
    /// </summary>
    /// <param name="capability">The capability to revoke (its chain is cryptographically verified for authorization)</param>
    /// <param name="revokerDid">The authenticated DID requesting revocation</param>
    /// <returns>True if authorized and recorded; false if the revoker is not authorized</returns>
    Task<bool> RevokeCapabilityAsync(Capability capability, string revokerDid);

    /// <summary>
    /// Checks if a capability has been revoked
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to check</param>
    /// <returns>True if the capability has been revoked</returns>
    Task<bool> IsCapabilityRevokedAsync(string capabilityId);
}