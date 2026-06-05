namespace ZcapLd.Core.Services;

/// <summary>
/// Optional, opt-in verifier policy for W3C ZCAP-LD <b>SHOULD</b>-level checks that are not enforced
/// by default. Enforcing a SHOULD can reject otherwise-valid capabilities, so the decision belongs to
/// the deploying verifier rather than the library. Supply an instance via the full
/// <see cref="VerificationService"/> constructor, or register one in DI
/// (<c>services.AddSingleton(new VerificationPolicy { … })</c> before <c>AddZcapServices()</c>); when
/// absent, <see cref="Default"/> applies and no opt-in check is enforced.
/// </summary>
public sealed record VerificationPolicy
{
    /// <summary>
    /// When <see langword="true"/>, the verifier rejects a delegated zcap whose <c>expires</c> is more
    /// than <see cref="MaxDelegationExpirationMonths"/> in the future, measured at verification time.
    /// This implements the W3C ZCAP-LD verifier-side SHOULD — "a verifier SHOULD ensure that an invoked
    /// delegated zcap does not have an expiration date-time that is more than three months in the
    /// future" — which bounds the verifier's revoked-zcap storage burden.
    /// <para>
    /// The bound is applied to <b>every delegated link in the chain</b> — the invoked leaf and every
    /// intermediate — not only the invoked leaf: the verifier stores each link's revocation until that
    /// link expires, so the storage-burden bound must hold for the whole chain, and under attenuation
    /// (a child's <c>expires</c> is ≤ its parent's) the ancestors are the longest-lived links. A
    /// delegated link with <b>no</b> <c>expires</c> is treated as unbounded and likewise rejected (the
    /// spec independently requires delegated zcaps to carry an expiration), so omitting <c>expires</c>
    /// cannot trivially defeat the ceiling.
    /// </para>
    /// <para>
    /// Default <see langword="false"/>: it is a SHOULD, not a MUST, and enforcing it can reject
    /// legitimately long-lived delegations a parent permitted (Issue #73). The companion create-time
    /// hard throw was removed in Issue #61 — this is the spec-correct home for the ceiling. The check is
    /// applied on the invocation and chain-verification paths but deliberately <b>not</b> on the
    /// revocation-authorization path, so a long-lived delegation can always be revoked.
    /// </para>
    /// </summary>
    public bool EnforceMaxDelegationExpiration { get; init; }

    /// <summary>
    /// The maximum number of months in the future a delegated zcap's <c>expires</c> may be when
    /// <see cref="EnforceMaxDelegationExpiration"/> is enabled. Defaults to <c>3</c> per the spec.
    /// Should be a positive value (a value ≤ 0 rejects every future-dated delegation).
    /// </summary>
    public int MaxDelegationExpirationMonths { get; init; } = 3;

    /// <summary>The default policy: no opt-in SHOULD checks enforced.</summary>
    public static VerificationPolicy Default { get; } = new();
}
