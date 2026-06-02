namespace ZcapLd.Core.Services;

/// <summary>
/// Optional, opt-in verifier policy for W3C ZCAP-LD <b>SHOULD</b>-level checks that are not
/// enforced by default (enforcing them can reject otherwise-valid capabilities, so the decision
/// belongs to the deploying verifier).
/// </summary>
public sealed record VerificationPolicy
{
    /// <summary>
    /// When true, the verifier rejects a delegated zcap whose <c>expires</c> is more than
    /// <see cref="MaxDelegationExpirationMonths"/> in the future, measured at verification time.
    /// This is the W3C ZCAP-LD verifier-side SHOULD ("a verifier SHOULD ensure that an invoked
    /// delegated zcap does not have an expiration date-time more than three months in the future").
    /// Default <c>false</c> — it is a SHOULD, and enforcing it can reject legitimately long-lived
    /// delegations a parent permitted (Issue #73; companion to the removed create-time throw, #61).
    /// </summary>
    public bool EnforceMaxDelegationExpiration { get; init; }

    /// <summary>
    /// The maximum number of months in the future a delegated zcap's expiration may be when
    /// <see cref="EnforceMaxDelegationExpiration"/> is enabled. Defaults to 3 per the spec.
    /// </summary>
    public int MaxDelegationExpirationMonths { get; init; } = 3;

    /// <summary>The default policy: no opt-in SHOULD checks enforced.</summary>
    public static VerificationPolicy Default { get; } = new();
}
