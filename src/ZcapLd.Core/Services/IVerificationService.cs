using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for verifying ZCAP-LD capabilities and invocations
/// </summary>
public interface IVerificationService
{
    /// <summary>
    /// Verifies the soundness of a delegated capability's <b>single delegation link</b>: its proof
    /// signature, that the signer is authorized by the embedded immediate parent's controller, that
    /// the parent has not been revoked, that the child does not exceed the parent (attenuation), and
    /// that the child has not expired. A root capability is valid iff it carries no proof.
    /// <para>
    /// This is <b>not</b> a full authorization gate: it does not walk the whole chain back to the
    /// root or independently verify every ancestor's own proof. For an authorization decision, use
    /// <see cref="VerifyCapabilityChainAsync"/> (full chain) or <see cref="VerifyInvocationAsync(Invocation, Capability)"/>.
    /// </para>
    /// </summary>
    /// <param name="capability">The capability whose delegation proof to verify</param>
    /// <returns>True if the single delegation link is sound</returns>
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
    /// Records a revocation for a capability ID <b>without performing any authorization</b>.
    /// This overload only has the capability ID, and a bare <paramref name="revokerDid"/> string
    /// is not proof of control, so it cannot verify the revoker is entitled to revoke. The caller
    /// (host) MUST authorize the revoker before calling; the DID is stored as audit attribution
    /// only. To have the library enforce authorization against the delegation chain, use
    /// <see cref="RevokeCapabilityAsync(Capability, string)"/>.
    /// COMPLIANCE: MUST-21, SHOULD-07 — revocation support.
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to revoke</param>
    /// <param name="revokerDid">DID recorded as the revoker (attribution only; not authorized)</param>
    /// <returns>True once the revocation is recorded; throws on null/empty arguments</returns>
    Task<bool> RevokeCapabilityAsync(string capabilityId, string revokerDid);

    /// <summary>
    /// Revokes a capability after verifying the revoker is authorized. A revoker is authorized
    /// when it controls the capability itself or any ancestor in its delegation chain (an up-chain
    /// delegator). <paramref name="revokerDid"/> is expected to be a DID the host has already
    /// <i>authenticated</i> — the library performs authorization, not authentication. Returns
    /// <c>false</c> (recording nothing) when the revoker is not authorized or the chain cannot be
    /// verified.
    /// </summary>
    /// <param name="capability">The capability to revoke (its chain is used for authorization)</param>
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