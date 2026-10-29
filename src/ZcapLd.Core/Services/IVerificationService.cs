using System.Text.Json.Nodes;
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
    /// (attenuation), that the child has not expired, and that the delegation proof's <c>created</c>
    /// is sound — not future-dated beyond the clock skew, nor present-but-unparseable (Issue #99). A
    /// root capability is valid iff it carries no proof.
    /// <para>
    /// This is <b>not</b> a full authorization gate. Revocation records are scoped to the delegator that
    /// signed each capability (#158), so to check the ancestry's revocation this path verifies each
    /// embedded ancestor's delegation proof as a chain link (signature, parent-controller authorization,
    /// attenuation, expiry) up to the resolved or explicit root before trusting its delegator, and a
    /// candidate whose ancestry cannot be authenticated fails closed; below the first level a root
    /// resolver or explicit root is therefore required. It does not apply the delegation-time
    /// (<c>created</c>, Issue #99), expiration-ceiling, required-<c>expires</c> or caveat-policy checks
    /// to ancestors; those are gated only by the full-chain path. Each delegation proof in a set is
    /// evaluated on its own (link first, then its ancestry), the first to pass wins, and a failing proof
    /// never vetoes another, at the leaf or at any embedded ancestor: an ancestor's proof whose own
    /// ancestry cannot be authenticated is discarded, and the ancestor fits through any of its proofs
    /// that reaches the root. When all fail, a revocation found on a verified route is reported, else
    /// the last proof's failure. For an authorization decision, use
    /// <see cref="VerifyCapabilityChainAsync(Capability)"/> (full chain) or
    /// <see cref="VerifyInvocationAsync(Invocation, Capability)"/>. With a caveat registry (#157), a
    /// link that carries caveats or sits below the first delegation level is reported as
    /// <see cref="VerificationOutcome.CaveatEnforcementRequired"/> rather than valid.
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
    /// Structured-result sibling of <see cref="VerifyCapabilityProofAsync(Capability)"/>: returns a
    /// <see cref="VerificationResult"/> whose <see cref="VerificationResult.Outcome"/> names the specific
    /// failure (e.g. <see cref="VerificationOutcome.Revoked"/>, <see cref="VerificationOutcome.InvalidSignature"/>)
    /// instead of a bare <c>false</c> (Issue #70). Fail-closed semantics are identical; the bool overload
    /// returns this result's <see cref="VerificationResult.IsValid"/>.
    /// </summary>
    /// <param name="capability">The capability whose delegation proof to verify</param>
    /// <returns>A <see cref="VerificationResult"/> describing the outcome.</returns>
    Task<VerificationResult> VerifyCapabilityProofDetailedAsync(Capability capability);

    /// <summary>
    /// Structured-result sibling of <see cref="VerifyCapabilityProofAsync(Capability, Capability)"/>
    /// (explicit root). See <see cref="VerifyCapabilityProofDetailedAsync(Capability)"/>.
    /// </summary>
    /// <param name="capability">The capability to verify</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>A <see cref="VerificationResult"/> describing the outcome.</returns>
    Task<VerificationResult> VerifyCapabilityProofDetailedAsync(Capability capability, Capability rootCapability);

    /// <summary>
    /// Verifies a signed invocation envelope, including the full delegation chain, signature,
    /// controller authorization, allowed action, target policy, expiration, revocation, proof
    /// freshness and nonce replay protection. Delegated invocations embed the complete capability;
    /// root invocations reference its ID. Resolve the chain's root through an
    /// <see cref="IRootCapabilityResolver"/> or use the explicit-root overload.
    /// </summary>
    /// <param name="invocation">The signed invocation to verify; its ID is the replay nonce.</param>
    /// <param name="capability">The capability being invoked.</param>
    /// <returns>True only if the invocation and its authority are valid.</returns>
    /// <exception cref="ArgumentNullException">Invocation or capability is null.</exception>
    Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability);

    /// <summary>
    /// Verifies an invocation with an explicit trusted root, using the same checks as
    /// <see cref="VerifyInvocationAsync(Invocation, Capability)"/>. Use this overload when
    /// the caller knows the root and no root resolver is configured.
    /// </summary>
    /// <param name="invocation">The signed invocation to verify.</param>
    /// <param name="capability">The capability being invoked.</param>
    /// <param name="rootCapability">The trusted root referenced by the delegation chain.</param>
    /// <returns>True only if the invocation and its authority are valid.</returns>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability, Capability rootCapability);

    /// <summary>
    /// Structured-result sibling of <see cref="VerifyInvocationAsync(Invocation, Capability)"/>.
    /// Identifies failures such as <see cref="VerificationOutcome.Replayed"/>,
    /// <see cref="VerificationOutcome.ActionNotAllowed"/> or
    /// <see cref="VerificationOutcome.UnauthorizedController"/>. Infrastructure failures yield
    /// <see cref="VerificationOutcome.CouldNotVerify"/>; the bool API returns this result's IsValid.
    /// </summary>
    /// <param name="invocation">The signed invocation to verify.</param>
    /// <param name="capability">The capability being invoked.</param>
    /// <returns>The detailed verification outcome.</returns>
    /// <exception cref="ArgumentNullException">Invocation or capability is null.</exception>
    Task<VerificationResult> VerifyInvocationDetailedAsync(Invocation invocation, Capability capability);

    /// <summary>
    /// Structured-result sibling of <see cref="VerifyInvocationAsync(Invocation, Capability, Capability)"/>.
    /// See <see cref="VerifyInvocationDetailedAsync(Invocation, Capability)"/> for outcome semantics.
    /// </summary>
    /// <param name="invocation">The signed invocation to verify.</param>
    /// <param name="capability">The capability being invoked.</param>
    /// <param name="rootCapability">The trusted root referenced by the delegation chain.</param>
    /// <returns>The detailed verification outcome.</returns>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    Task<VerificationResult> VerifyInvocationDetailedAsync(Invocation invocation, Capability capability, Capability rootCapability);

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
    /// Structured-result sibling of <see cref="VerifyCapabilityChainAsync(Capability)"/>: returns a
    /// <see cref="VerificationResult"/> naming the specific failure (e.g.
    /// <see cref="VerificationOutcome.ChainTooLong"/>, <see cref="VerificationOutcome.Revoked"/>,
    /// <see cref="VerificationOutcome.AttenuationViolation"/>) instead of a bare <c>false</c> (Issue #70).
    /// This is the overload a downstream consumer needs to tell <see cref="VerificationOutcome.Revoked"/>
    /// from a broken chain without reconstructing chain ids itself.
    /// </summary>
    /// <param name="capability">The capability with delegation chain</param>
    /// <returns>A <see cref="VerificationResult"/> describing the outcome.</returns>
    Task<VerificationResult> VerifyCapabilityChainDetailedAsync(Capability capability);

    /// <summary>
    /// Structured-result sibling of <see cref="VerifyCapabilityChainAsync(Capability, Capability)"/>
    /// (explicit root). See <see cref="VerifyCapabilityChainDetailedAsync(Capability)"/>.
    /// </summary>
    /// <param name="capability">The capability with delegation chain</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>A <see cref="VerificationResult"/> describing the outcome.</returns>
    Task<VerificationResult> VerifyCapabilityChainDetailedAsync(Capability capability, Capability rootCapability);

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
    /// returns <c>false</c>. Unsupported caveats remain rejected on this path.
    /// The recorded <c>RevokedBy</c> is the authenticated verification method's bare DID,
    /// never a caller-asserted identity. Reason and metadata are signed but informational.
    /// Replay protection keys on the request's <c>id</c>; mint a fresh ID for each request.
    /// Storage precedes nonce consumption so a failed store write can be retried. A false
    /// result from the subsequent replay check does not roll back a completed write.
    /// <para>
    /// Authorization still requires a valid chain: a capability that is already expired,
    /// revoked, or has a revoked ancestor is already inert and cannot be explicitly re-revoked.
    /// This is by design; callers building audit trails must not expect a new record for it.
    /// Revocation exempts expiration ceilings, delegation-created checks and missing delegated
    /// expiration, but never unsupported vocabulary. Only null arguments throw; other failures
    /// return false.
    /// </para>
    /// <para>
    /// Whether <paramref name="capability"/> names a root is decided by the configured
    /// <see cref="IRootCapabilityResolver"/>, not by its shape. A known root id is authorized against
    /// the resolved root, never the supplied copy. A root-shaped or <c>urn:zcap:root:</c> id that does
    /// not resolve returns false (Issue #155).
    /// </para>
    /// <para>
    /// The record is scoped (#158). A root is recorded in <see cref="RevocationScope.Root"/>. A delegated
    /// capability is recorded in <see cref="RevocationScope.Delegated(string)"/> for the delegator that
    /// signed the delegation proof its verified chain followed, and for each co-signer of the same
    /// chain; that is the scope every verifier looks a link up under. A forged copy of the id under
    /// another chain is signed by someone else and lands in that signer's scope, where no genuine chain
    /// looks. Only the chain the request presents is revoked; a capability that also verifies on another
    /// chain is revoked there by presenting that chain.
    /// </para>
    /// <para>
    /// Consequences of scoping: a capability co-signed by several co-controllers of its parent, presented
    /// with only one of those proofs, is recorded for that signer alone, and a copy carrying another
    /// signer's proof verifies until a request presenting that proof, or that co-controller, revokes it;
    /// present the fullest copy you hold. A revoked delegated id re-presented as a self-asserted root is
    /// not matched by its record, so, as everywhere, never pass a holder-supplied root object to the
    /// chain or envelope verification APIs.
    /// </para>
    /// </remarks>
    /// <param name="capability">The capability to revoke, with its full delegation chain.</param>
    /// <param name="signedRevocation">The signed request from <see cref="ISigningService.SignRevocationAsync"/>.</param>
    /// <returns>True if authenticated, authorized, fresh, recorded and not replayed; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Capability or signedRevocation is null.</exception>
    Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation);

    /// <summary>
    /// Revokes a capability using an explicit trusted root when no root resolver is configured.
    /// The explicit root scopes the call: a delegated capability's chain must end at it, and a root
    /// may be revoked only when it is this root, authorized against this root rather than the
    /// supplied copy. Any other root, including one the resolver knows, returns false.
    /// <para>
    /// When an <see cref="IRootCapabilityResolver"/> is configured it is still consulted for the id
    /// being revoked, unless that id is the explicit root's own, so a forged delegation under the
    /// explicit root cannot borrow another trusted root's id. A resolver fault (including a resolver
    /// that throws for unknown ids instead of returning null) returns false; the request can be
    /// retried because its nonce is not consumed. Without a configured resolver nothing else is
    /// consulted.
    /// </para>
    /// <para>
    /// <paramref name="rootCapability"/> is a trust anchor the caller vouches for: a request to revoke
    /// that root's own id is authorized against this object, not against the resolver. Never build it
    /// from request input, or a root-shaped request naming the caller as controller revokes the root (#155).
    /// </para>
    /// All authentication, authorization, replay and audit semantics of
    /// <see cref="RevokeCapabilityAsync(Capability, Invocation)"/> apply.
    /// </summary>
    /// <param name="capability">The capability to revoke, with its full delegation chain (for authorization).</param>
    /// <param name="signedRevocation">The signed revocation request (from <see cref="ISigningService.SignRevocationAsync"/>).</param>
    /// <param name="rootCapability">The root capability the chain references by id</param>
    /// <returns>True if authenticated, authorized, fresh, and recorded; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation, Capability rootCapability);

    /// <summary>
    /// Checks whether a capability id is revoked in <paramref name="scope"/> (#158): by a record in that
    /// scope, or by an unscoped one. Use <see cref="RevocationScope.Root"/> for a root and
    /// <see cref="RevocationScope.ForDelegationProof"/> with the delegation proof a verifier accepted for
    /// a delegated capability. Chain and invocation verification perform this check for every link.
    /// Passing <see cref="RevocationScope.Unscoped"/> consults only unscoped (migrated or operator)
    /// records and is false for every revocation the signed path recorded; it is not the 5.x bare-id check.
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    /// <param name="capabilityId">The ID of the capability to check</param>
    /// <param name="scope">The scope the capability is verified under.</param>
    /// <returns>True if the capability has been revoked in that scope</returns>
    Task<bool> IsCapabilityRevokedAsync(string capabilityId, RevocationScope scope);

    /// <summary>
    /// Verifies a <c>@digitalbazaar/zcap</c>-compatible ("Path A") Data Integrity invocation — an
    /// application document carrying a <c>capabilityInvocation</c> proof. The relying party MUST declare
    /// the action and target(s) it authorizes; the verifier fails closed unless the proof matches them
    /// (this binding prevents a confused-deputy replay of an invocation signed over a different
    /// capability). See <see cref="VerifyCapabilityInvocationDetailedAsync(JsonObject, string, IReadOnlyCollection{string}, IReadOnlyCollection{string}, Capability)"/>
    /// for structured results and root pinning.
    /// </summary>
    Task<bool> VerifyCapabilityInvocationAsync(
        JsonObject securedDocument, string expectedAction, IReadOnlyCollection<string> expectedTargets);

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject, string, IReadOnlyCollection{string})"/>
    Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(
        JsonObject securedDocument,
        string expectedAction,
        IReadOnlyCollection<string> expectedTargets,
        IReadOnlyCollection<string>? expectedRootCapabilityIds = null,
        Capability? rootCapability = null);

    /// <summary>Single-expected-target convenience overload of
    /// <see cref="VerifyCapabilityInvocationDetailedAsync(JsonObject, string, IReadOnlyCollection{string}, IReadOnlyCollection{string}, Capability)"/>.</summary>
    Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(
        JsonObject securedDocument,
        string expectedAction,
        string expectedTarget,
        Capability? rootCapability = null);
}
