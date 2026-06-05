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
    /// the proof-chain ancestry has not been revoked, that the child does not exceed the parent
    /// (attenuation), and that the child has not expired. A root capability is valid iff it carries
    /// no proof.
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
    /// Verifies a capability's cryptographic proof, supplying the root capability explicitly. A
    /// spec-exact delegation chain references the root by id only, so verifying a delegated capability
    /// needs the root to authorize the first delegation. Use this overload when the root is known to
    /// the caller; otherwise configure an <see cref="IRootCapabilityResolver"/> and use
    /// <see cref="VerifyCapabilityProofAsync(Capability)"/>.
    /// </summary>
    /// <param name="capability">The capability to verify</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>True if the proof is valid</returns>
    Task<bool> VerifyCapabilityProofAsync(Capability capability, Capability rootCapability);

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
    /// Verifies an invocation request, supplying the root capability explicitly (see
    /// <see cref="VerifyCapabilityProofAsync(Capability, Capability)"/> for why the root is needed).
    /// Pass <paramref name="contextProperties"/> as <see langword="null"/> when none are required; the
    /// root is a four-argument overload so a bare <c>null</c> third argument stays unambiguous against
    /// <see cref="VerifyInvocationAsync(Invocation, Capability, Dictionary{string, object})"/>.
    /// </summary>
    /// <param name="invocation">The invocation to verify</param>
    /// <param name="capability">The capability being invoked</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <param name="contextProperties">Application-specific key/value pairs to inject into the invocation context</param>
    /// <returns>True if the invocation is valid</returns>
    Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability, Capability rootCapability, Dictionary<string, object>? contextProperties);

    /// <summary>
    /// Verifies a capability delegation chain
    /// </summary>
    /// <param name="capability">The capability with delegation chain</param>
    /// <returns>True if the chain is valid</returns>
    Task<bool> VerifyCapabilityChainAsync(Capability capability);

    /// <summary>
    /// Verifies a capability delegation chain, supplying the root capability explicitly (see
    /// <see cref="VerifyCapabilityProofAsync(Capability, Capability)"/> for why the root is needed).
    /// </summary>
    /// <param name="capability">The capability with delegation chain</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>True if the chain is valid</returns>
    Task<bool> VerifyCapabilityChainAsync(Capability capability, Capability rootCapability);

    /// <summary>
    /// Resolves a DID to its public key for verification
    /// </summary>
    /// <param name="did">The DID to resolve</param>
    /// <returns>A <see cref="ResolvedKey"/> containing the public key bytes and key type</returns>
    Task<ResolvedKey> ResolvePublicKeyAsync(string did);

    /// <summary>
    /// Revokes a capability from a <b>cryptographically signed</b> revocation request
    /// (proof-of-possession). The library both <i>authenticates</i> the revoker — by verifying the
    /// signature against the key resolved from the proof's <c>verificationMethod</c> — and
    /// <i>authorizes</i> it, by requiring that verification method to control the capability or any
    /// ancestor in its (cryptographically verified) delegation chain. This is the <b>only</b>
    /// revocation entrypoint: there is no unauthenticated bare-DID path. Build the request with
    /// <see cref="ISigningService.SignRevocationAsync"/>.
    /// COMPLIANCE: MUST-21, SHOULD-07 — revocation support.
    /// </summary>
    /// <remarks>
    /// <b>Fail-closed:</b> any structural mismatch (wrong <c>proofPurpose</c>/<c>capabilityAction</c>,
    /// wrong capability binding, body/proof inconsistency), an invalid signature, an unauthorized
    /// signer, a replayed request, or any infrastructure error (DID resolution, network, crypto)
    /// returns <c>false</c> and records nothing. Caveats are deliberately <b>not</b> evaluated —
    /// revocation is a control-plane authority action. The recorded <c>RevokedBy</c> is the
    /// authenticated verification method's bare DID; a signed <c>reason</c>/<c>metadata</c> is
    /// recorded. Replay protection keys on the request's <c>id</c>, so each request needs a fresh id.
    /// Only <see cref="System.ArgumentNullException"/> (null capability or request) is thrown.
    /// </remarks>
    /// <param name="capability">The capability to revoke, with its full delegation chain (for authorization).</param>
    /// <param name="signedRevocation">The signed revocation request (from <see cref="ISigningService.SignRevocationAsync"/>).</param>
    /// <returns>True if authenticated, authorized, fresh, and recorded; otherwise false.</returns>
    Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation);

    /// <summary>
    /// Revokes a capability from a signed revocation request, supplying the root capability explicitly.
    /// Revocation authorization verifies the full delegation chain, which references the root by id
    /// only; supply the root here when no <see cref="IRootCapabilityResolver"/> is configured
    /// (otherwise revoking a first-level delegated capability fails closed). Same semantics as
    /// <see cref="RevokeCapabilityAsync(Capability, Invocation)"/> otherwise.
    /// </summary>
    /// <param name="capability">The capability to revoke, with its full delegation chain (for authorization).</param>
    /// <param name="signedRevocation">The signed revocation request (from <see cref="ISigningService.SignRevocationAsync"/>).</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>True if authenticated, authorized, fresh, and recorded; otherwise false.</returns>
    Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation, Capability rootCapability);

    /// <summary>
    /// Checks if a capability has been revoked
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to check</param>
    /// <returns>True if the capability has been revoked</returns>
    Task<bool> IsCapabilityRevokedAsync(string capabilityId);
}
