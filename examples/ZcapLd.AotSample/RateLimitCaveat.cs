using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.AotSample;

/// <summary>
/// A custom caveat (#157): the most invocations a delegate may make per minute. It describes the
/// restriction and how a child may narrow it; the resource's <see cref="RateLimitLedger"/> enforces it.
/// </summary>
public sealed class RateLimitCaveat : Caveat
{
    public const string TypeName = "RateLimit";

    public override string Type => TypeName;

    [JsonPropertyName("maxPerMinute")]
    public required int MaxPerMinute { get; init; }

    public override void Validate()
    {
        if (MaxPerMinute is < 1 or > 10_000)
            throw new CapabilityValidationException("maxPerMinute must be between 1 and 10000.");
    }

    // A delegate may lower the limit, never raise it.
    public override bool IsAttenuationOf(Caveat parent)
        => parent is RateLimitCaveat limit && MaxPerMinute <= limit.MaxPerMinute;
}

/// <summary>
/// Source-generated serializer metadata for the sample's caveat (#154). Under native AOT, trimming
/// and file-based apps the registry cannot discover the parameters by reflection, so the caveat is
/// registered with <c>SampleJsonContext.Default.RateLimitCaveat</c> through
/// <c>CaveatTypeRegistry.Register(string, JsonTypeInfo&lt;T&gt;)</c> or
/// <c>AddZcapCaveatType(services, string, JsonTypeInfo&lt;T&gt;)</c>. The registry applies its own
/// strict settings through this context's resolver, so no generation options are needed here.
/// </summary>
[JsonSerializable(typeof(RateLimitCaveat))]
internal sealed partial class SampleJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The resource's enforcement of <see cref="RateLimitCaveat"/>: counts invocations per grant within
/// the current minute. A production ledger is a shared store used by every verifier replica.
/// </summary>
public sealed class RateLimitLedger : ICaveatHandler
{
    private readonly Dictionary<string, (long Minute, int Count)> _counts = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public string CaveatType => RateLimitCaveat.TypeName;

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        var minute = context.Created.Ticks / TimeSpan.TicksPerMinute;
        lock (_gate)
        {
            // Every grant in the chain is counted, so a delegate shares its ancestors' limits.
            foreach (var grant in context.Grants)
            {
                var limit = ((RateLimitCaveat)grant.Caveat).MaxPerMinute;
                var current = _counts.TryGetValue(grant.GrantKey, out var entry) && entry.Minute == minute ? entry.Count : 0;
                if (current + 1 > limit)
                    return Task.FromResult(CaveatDecision.Deny($"{grant.CapabilityId} exceeded {limit} invocations this minute."));
            }

            foreach (var grant in context.Grants)
            {
                var current = _counts.TryGetValue(grant.GrantKey, out var entry) && entry.Minute == minute ? entry.Count : 0;
                _counts[grant.GrantKey] = (minute, current + 1);
            }

            return Task.FromResult(CaveatDecision.Satisfied);
        }
    }
}
