using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Base class for capability caveats (restrictions)
/// </summary>
public abstract class Caveat
{
    /// <summary>
    /// The type of caveat
    /// </summary>
    [JsonPropertyName("type")]
    public abstract string Type { get; }

    /// <summary>
    /// Evaluates whether this caveat is satisfied for the given invocation context
    /// </summary>
    /// <param name="context">The invocation context</param>
    /// <returns>True if the caveat is satisfied, false otherwise</returns>
    public abstract bool IsSatisfied(InvocationContext context);
}

/// <summary>
/// Caveat that restricts capability usage until a specific date/time
/// </summary>
public class ExpirationCaveat : Caveat
{
    // STJ on .NET 10 doesn't auto-inherit [JsonPropertyName] from the abstract
    // base override declaration — without an explicit attribute on the override,
    // the runtime catalogues the override as a separate property and emits the
    // CLR name `"Type"` alongside the inherited `"type"`. Two keys on the wire
    // diverge from every other Data Integrity implementation. See #45.
    [JsonPropertyName("type")]
    public override string Type => "Expiration";

    /// <summary>
    /// The expiration date/time
    /// </summary>
    [JsonPropertyName("expires")]
    public DateTime Expires { get; set; }

    public override bool IsSatisfied(InvocationContext context)
    {
        // Evaluate against the invocation's signed time (#71 threads the validated proof.created into
        // InvocationContext.InvocationTime) rather than the verifier's wall clock, so a delegated
        // time-based caveat honours when the invoker actually signed. Falls back to UtcNow when no
        // context is supplied (a direct caller); InvocationTime itself defaults to construction-time UtcNow.
        var evaluationTime = context?.InvocationTime ?? DateTime.UtcNow;
        return evaluationTime < Expires;
    }
}

/// <summary>
/// Caveat that limits the number of times a capability can be used
/// </summary>
public class UsageCountCaveat : Caveat
{
    /// <summary>
    /// <see cref="InvocationContext.Properties"/> key under which the relying party MUST supply the
    /// current number of prior uses for the invoked capability (an <see cref="int"/>, or any value
    /// convertible to one). A usage count is runtime state that cannot live in the signed payload, so
    /// the verifier cannot derive it from the capability alone — the caller MUST inject it from their
    /// own usage store (the same way a remote revocation status backs <see cref="ValidWhileTrueCaveat"/>).
    /// </summary>
    public const string CurrentUsesContextKey = "zcap:usageCount";

    [JsonPropertyName("type")]
    public override string Type => "UsageCount";

    /// <summary>
    /// Maximum number of allowed uses
    /// </summary>
    [JsonPropertyName("maxUses")]
    public int MaxUses { get; set; }

    /// <summary>
    /// Legacy in-process usage counter. Runtime state — NOT serialized (it changes over the
    /// capability's lifetime; the signed policy is <see cref="MaxUses"/>). <b>No longer consulted by
    /// <see cref="IsSatisfied"/></b>: on a wire-deserialized capability it is always 0, so trusting it
    /// made the caveat unenforceable (permanently <c>0 &lt; MaxUses</c> == true). Supply the current
    /// count via <see cref="CurrentUsesContextKey"/> on the invocation context instead.
    /// </summary>
    [JsonIgnore]
    public int CurrentUses { get; set; }

    public override bool IsSatisfied(InvocationContext context)
    {
        // SECURITY: a usage count cannot be carried in the signed payload, so the caveat alone cannot
        // know it. Resolve the count from the caller-supplied invocation context and FAIL CLOSED when
        // it is absent or unusable — mirroring how ValidWhileTrueCaveat fails closed without a handler.
        // Trusting the deserialized CurrentUses (always 0 on the wire) would silently grant unlimited use.
        return TryGetContextUsageCount(context, out var currentUses) && currentUses < MaxUses;
    }

    private static bool TryGetContextUsageCount(InvocationContext? context, out int currentUses)
    {
        currentUses = 0;
        if (context?.Properties == null ||
            !context.Properties.TryGetValue(CurrentUsesContextKey, out var raw) || raw == null)
        {
            return false;
        }

        switch (raw)
        {
            case int i:
                currentUses = i;
                return true;
            case long l when l >= int.MinValue && l <= int.MaxValue:
                currentUses = (int)l;
                return true;
            case string s when int.TryParse(s, out var parsed):
                currentUses = parsed;
                return true;
            case System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.Number
                && je.TryGetInt32(out var fromJson):
                currentUses = fromJson;
                return true;
            default:
                return false;
        }
    }
}