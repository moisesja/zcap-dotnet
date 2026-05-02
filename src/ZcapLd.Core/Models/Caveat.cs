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
    public override string Type => "Expiration";

    /// <summary>
    /// The expiration date/time
    /// </summary>
    [JsonPropertyName("expires")]
    public DateTime Expires { get; set; }

    public override bool IsSatisfied(InvocationContext context)
    {
        return DateTime.UtcNow < Expires;
    }
}

/// <summary>
/// Caveat that limits the number of times a capability can be used
/// </summary>
public class UsageCountCaveat : Caveat
{
    public override string Type => "UsageCount";

    /// <summary>
    /// Maximum number of allowed uses
    /// </summary>
    [JsonPropertyName("maxUses")]
    public int MaxUses { get; set; }

    /// <summary>
    /// Current usage count. Runtime state — NOT serialized because it changes
    /// over the capability's lifetime; the signed policy is <see cref="MaxUses"/>.
    /// Including this in the signed JCS payload would invalidate the signature
    /// on every increment, which is incompatible with how usage tracking works.
    /// </summary>
    [JsonIgnore]
    public int CurrentUses { get; set; }

    public override bool IsSatisfied(InvocationContext context)
    {
        return CurrentUses < MaxUses;
    }
}