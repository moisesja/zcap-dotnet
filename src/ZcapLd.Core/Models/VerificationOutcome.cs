namespace ZcapLd.Core.Models;

/// <summary>
/// The distinct outcome of a capability / invocation / chain verification. <see cref="Valid"/> is the
/// single success value; every other member is a specific failure reason that previously collapsed to a
/// bare <c>false</c> (Issue #70). Returned inside a <see cref="VerificationResult"/> by the
/// <c>...DetailedAsync</c> methods on <see cref="Services.IVerificationService"/> so callers can react
/// programmatically — e.g. distinguish a <see cref="Revoked"/> capability from an
/// <see cref="InvalidDelegation"/> chain — instead of re-deriving the reason themselves. Verification
/// remains fail-closed: any non-<see cref="Valid"/> outcome denies.
/// </summary>
public enum VerificationOutcome
{
    /// <summary>Verification succeeded; the capability / invocation / chain is valid.</summary>
    Valid = 0,

    /// <summary>
    /// Structurally invalid input: a missing/empty id, a root capability that carries a delegation
    /// proof, a malformed root, a non-spec <c>capabilityChain</c> shape, or an invocation whose
    /// body/proof binding (capability reference, action, target, proofPurpose) is inconsistent.
    /// </summary>
    MalformedCapability,

    /// <summary>A proof signature did not verify, or the resolved key type did not match the proof's suite.</summary>
    InvalidSignature,

    /// <summary>
    /// The proof's <c>verificationMethod</c> is not authorized by the relevant controller for the
    /// required verification relationship (<c>capabilityInvocation</c> / <c>capabilityDelegation</c>).
    /// </summary>
    UnauthorizedController,

    /// <summary>
    /// A delegation link could not be validated (a broken chain link): the immediate parent could not
    /// be resolved/authorized, or the delegation proof was otherwise invalid.
    /// </summary>
    InvalidDelegation,

    /// <summary>
    /// A delegated capability exceeds its parent's authority — a broader <c>invocationTarget</c>,
    /// extra <c>allowedAction</c>s, or a later <c>expires</c> than its parent permits.
    /// </summary>
    AttenuationViolation,

    /// <summary>The delegation chain exceeds the maximum permitted length.</summary>
    ChainTooLong,

    /// <summary>The capability (or a link in its chain) is past its <c>expires</c> timestamp.</summary>
    Expired,

    /// <summary>The capability, or one of its ancestors in the chain, has been revoked.</summary>
    Revoked,

    /// <summary>A caveat — on the leaf or inherited from an ancestor — was not satisfied.</summary>
    CaveatFailed,

    /// <summary>The invocation nonce has already been seen within the replay window — a replay.</summary>
    Replayed,

    /// <summary>The requested invocation target is not permitted by the capability's <c>invocationTarget</c>.</summary>
    InvalidTarget,

    /// <summary>The requested action is not present in the capability's <c>allowedAction</c>.</summary>
    ActionNotAllowed,

    /// <summary>
    /// Verification could not be completed because of a configuration, transient, or infrastructure
    /// fault (e.g. a missing canonicalizer/crypto-suite registration, a DID-resolution error, or an
    /// unobtainable root capability). Distinct from an invalid capability: the request was neither
    /// proven valid nor proven invalid. Still denied (fail-closed); the cause is logged (Issue #64).
    /// </summary>
    CouldNotVerify,
}
