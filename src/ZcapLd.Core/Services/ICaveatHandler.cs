using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Resource-owned enforcement of one caveat type (#157). A verifier denies any invocation whose
/// chain carries a caveat type without a registered handler, so registering a handler is the
/// resource's commitment to enforce that restriction.
/// <para>
/// The verifier calls <see cref="EnforceAsync"/> once per invocation and caveat type, only after
/// the chain, signature, controller authorization, freshness and replay checks have all passed, so
/// a replayed invocation never reaches a handler. Handlers run in ordinal order of caveat type and
/// evaluation stops at the first denial; <see cref="ReleaseAsync"/> is then called on every handler
/// that had already allowed the invocation, so it can undo a reservation.
/// </para>
/// </summary>
/// <remarks>
/// The library authenticates the delegated bounds and enforces that every child narrows its parent.
/// Everything stateful is the resource's responsibility: compute the cost of the request from the
/// signed action and target (never from unsigned request data), check and record consumption
/// atomically across every grant in <see cref="CaveatEnforcementContext.Grants"/> (siblings share
/// their ancestors' budgets), key state by <see cref="CaveatGrant.GrantKey"/>, read each ceiling from
/// the presented grant, and share that state across verifier replicas. Do not cache decisions by
/// <see cref="CaveatEnforcementContext.InvocationId"/>: the invoker chooses it, and once the nonce
/// store forgets it the same id can return with a different action. The verifier's replay check
/// already lets each invocation reach the handlers at most once while the shared nonce store retains
/// its nonce; keep entries for at least the nonce window. The nonce is consumed before handlers run,
/// so a client retries a denied invocation with a new invocation id. On the envelope path the resource
/// must perform exactly the signed <see cref="CaveatEnforcementContext.CapabilityAction"/> and
/// <see cref="CaveatEnforcementContext.InvocationTarget"/>; the Data Integrity form pins both to the
/// relying party's expectations.
/// </remarks>
public interface ICaveatHandler
{
    /// <summary>The registered caveat type this handler enforces.</summary>
    string CaveatType { get; }

    /// <summary>Decides whether the invocation may proceed under this caveat type.</summary>
    /// <param name="context">Authenticated data about the invocation and its grants.</param>
    Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context);

    /// <summary>
    /// Called when a handler that ran later denied or failed, after this handler allowed the same
    /// invocation. The default does nothing.
    /// </summary>
    /// <param name="context">The context this handler allowed.</param>
    Task ReleaseAsync(CaveatEnforcementContext context) => Task.CompletedTask;
}

/// <summary>A caveat handler's decision.</summary>
public sealed record CaveatDecision
{
    private CaveatDecision(bool isSatisfied, string? reason)
    {
        IsSatisfied = isSatisfied;
        Reason = reason;
    }

    /// <summary>True when the invocation may proceed under this caveat type.</summary>
    public bool IsSatisfied { get; }

    /// <summary>Why the invocation was denied, if it was.</summary>
    public string? Reason { get; }

    /// <summary>The invocation may proceed.</summary>
    public static CaveatDecision Satisfied { get; } = new(true, null);

    /// <summary>The invocation is denied.</summary>
    public static CaveatDecision Deny(string reason) => new(false, reason);
}

/// <summary>
/// What a <see cref="ICaveatHandler"/> may rely on. Every value is authenticated by the verified
/// chain or the invocation proof; there is deliberately no free-form property bag.
/// </summary>
public sealed record CaveatEnforcementContext
{
    /// <summary>The caveat type being enforced.</summary>
    public required string CaveatType { get; init; }

    /// <summary>
    /// Every caveat of this type in the chain, root side first. Each delegated link restates (and
    /// may narrow) its parent's caveat, so the last grant belongs to the invoked capability.
    /// </summary>
    public required IReadOnlyList<CaveatGrant> Grants { get; init; }

    /// <summary>The verified chain, root first, invoked capability last.</summary>
    public required IReadOnlyList<Capability> Chain { get; init; }

    /// <summary>The root capability id.</summary>
    public required string RootCapabilityId { get; init; }

    /// <summary>The signed, relying-party-checked action.</summary>
    public required string CapabilityAction { get; init; }

    /// <summary>The signed, relying-party-checked invocation target.</summary>
    public required string InvocationTarget { get; init; }

    /// <summary>
    /// The invocation id, which is its replay nonce. The invoker chooses it, so it identifies this
    /// request only while the nonce store retains it. It is not a key for caching decisions.
    /// </summary>
    public required string InvocationId { get; init; }

    /// <summary>The verification method that signed the invocation.</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>The invocation proof's validated <c>created</c> instant (UTC).</summary>
    public required DateTime Created { get; init; }
}
