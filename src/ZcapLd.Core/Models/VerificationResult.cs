namespace ZcapLd.Core.Models;

/// <summary>
/// The structured result of a verification call: a <see cref="VerificationOutcome"/> plus an optional
/// human-readable <see cref="Message"/>. Returned by the <c>...DetailedAsync</c> methods on
/// <see cref="Services.IVerificationService"/> so callers can distinguish failure modes programmatically
/// (Issue #70) — e.g. surface a granular <c>Revoked</c> vs <c>InvalidDelegation</c> reason — rather than
/// re-deriving them from a bare <c>false</c>. The existing <c>Task&lt;bool&gt;</c> verify methods are thin
/// wrappers that return <see cref="IsValid"/>.
/// </summary>
public sealed record VerificationResult
{
    /// <summary>The specific outcome of verification. <see cref="VerificationOutcome.Valid"/> means success.</summary>
    public required VerificationOutcome Outcome { get; init; }

    /// <summary>
    /// An optional diagnostic message describing a failure. Intended to be non-sensitive and safe to
    /// log; <see langword="null"/> for a successful result.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>True if and only if <see cref="Outcome"/> is <see cref="VerificationOutcome.Valid"/>.</summary>
    public bool IsValid => Outcome == VerificationOutcome.Valid;

    /// <summary>The shared successful result.</summary>
    public static VerificationResult Valid { get; } = new() { Outcome = VerificationOutcome.Valid };

    /// <summary>
    /// Creates a failing result with the given <paramref name="outcome"/> and optional
    /// <paramref name="message"/>. <paramref name="outcome"/> should not be
    /// <see cref="VerificationOutcome.Valid"/>.
    /// </summary>
    public static VerificationResult Fail(VerificationOutcome outcome, string? message = null)
        => new() { Outcome = outcome, Message = message };
}
