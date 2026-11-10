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
/// the current minute of the resource's own clock. A production ledger is a shared store used by every
/// verifier replica.
/// </summary>
/// <param name="clock">The resource's clock, which chooses the enforcement bucket. The host registers
/// <see cref="TimeProvider.System"/>; the self-checks pass a still clock.</param>
public sealed class RateLimitLedger(TimeProvider clock) : ICaveatHandler
{
    private readonly Dictionary<string, (long Minute, int Count)> _counts = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public string CaveatType => RateLimitCaveat.TypeName;

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        // The bucket is the resource's minute, never the holder's. context.Created is the proof time
        // the holder signed, and freshness admits any value inside the window, so a bucket chosen from
        // it lets a holder alternate two minutes and reset its own count (PR #168 review).
        var minute = clock.GetUtcNow().UtcTicks / TimeSpan.TicksPerMinute;
        lock (_gate)
        {
            // Every grant in the chain is counted, so a delegate shares its ancestors' limits.
            foreach (var grant in context.Grants)
            {
                var limit = ((RateLimitCaveat)grant.Caveat).MaxPerMinute;
                if (Live(grant.GrantKey, minute).Count + 1 > limit)
                    return Task.FromResult(CaveatDecision.Deny($"{grant.CapabilityId} exceeded {limit} invocations this minute."));
            }

            foreach (var grant in context.Grants)
            {
                var live = Live(grant.GrantKey, minute);
                _counts[grant.GrantKey] = (live.Minute, live.Count + 1);
            }

            return Task.FromResult(CaveatDecision.Satisfied);
        }
    }

    // The live bucket of a grant: its entry unless the clock has moved past it. An entry is never
    // replaced by an earlier minute, so a clock that steps back cannot erase a consumed minute.
    private (long Minute, int Count) Live(string key, long minute)
        => _counts.TryGetValue(key, out var entry) && entry.Minute >= minute ? entry : (minute, 0);
}
