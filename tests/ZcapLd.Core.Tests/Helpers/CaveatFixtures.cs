using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// The differential-privacy budget from #157: a ceiling a delegate may lower but never raise.
/// </summary>
public sealed class EpsilonBudgetCaveat : Caveat
{
    public const string TypeName = "EpsilonBudget";

    public override string Type => TypeName;

    [JsonPropertyName("maxEpsilon")]
    public required double MaxEpsilon { get; init; }

    public override void Validate()
    {
        if (!(MaxEpsilon > 0 && MaxEpsilon <= 1000))
            throw new CapabilityValidationException("maxEpsilon must be greater than 0 and at most 1000.");
    }

    public override bool IsAttenuationOf(Caveat parent)
        => parent is EpsilonBudgetCaveat budget && MaxEpsilon <= budget.MaxEpsilon;
}

/// <summary>A set-valued caveat: a child may only keep a subset of the parent's regions.</summary>
public sealed class RegionCaveat : Caveat
{
    public const string TypeName = "Region";

    public override string Type => TypeName;

    [JsonPropertyName("allowed")]
    public required string[] Allowed { get; init; }

    public override void Validate()
    {
        if (Allowed.Length == 0)
            throw new CapabilityValidationException("allowed must name at least one region.");
    }

    public override bool IsAttenuationOf(Caveat parent)
        => parent is RegionCaveat region && Allowed.All(region.Allowed.Contains);
}

/// <summary>Carries arbitrary JSON to exercise the literal rules; uses the default (restate) rule.</summary>
public sealed class TagCaveat : Caveat
{
    public const string TypeName = "Tag";

    public override string Type => TypeName;

    [JsonPropertyName("data")]
    public required JsonElement Data { get; init; }
}

/// <summary>
/// Resource-side test adapter for <see cref="EpsilonBudgetCaveat"/>: costs come from the signed
/// action, every grant in the chain is debited atomically (siblings share ancestor budgets), and
/// ceilings are read from the presented grants. It does not cache decisions by invocation id: the
/// verifier's replay check already delivers each live nonce at most once, and an invoker-chosen id
/// can return with a different action after the nonce window.
/// </summary>
public sealed class InMemoryEpsilonLedger : ICaveatHandler
{
    private readonly object _gate = new();
    private readonly Dictionary<string, decimal> _spent = new(StringComparer.Ordinal);
    private readonly IReadOnlyDictionary<string, decimal> _costByAction;
    private int _calls;
    private int _releases;

    public InMemoryEpsilonLedger(IReadOnlyDictionary<string, decimal>? costByAction = null)
        => _costByAction = costByAction ?? new Dictionary<string, decimal> { ["query"] = 1m, ["query-large"] = 2m };

    public string CaveatType => EpsilonBudgetCaveat.TypeName;

    public int Calls => _calls;

    public int Releases => _releases;

    public decimal Spent(string grantKey)
    {
        lock (_gate)
            return _spent.GetValueOrDefault(grantKey);
    }

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        Interlocked.Increment(ref _calls);
        if (!_costByAction.TryGetValue(context.CapabilityAction, out var cost))
            return Task.FromResult(CaveatDecision.Deny($"No cost is defined for '{context.CapabilityAction}'."));

        lock (_gate)
        {
            foreach (var grant in context.Grants)
            {
                var ceiling = (decimal)((EpsilonBudgetCaveat)grant.Caveat).MaxEpsilon;
                if (_spent.GetValueOrDefault(grant.GrantKey) + cost > ceiling)
                    return Task.FromResult(CaveatDecision.Deny($"Epsilon budget of {grant.CapabilityId} is exhausted."));
            }

            foreach (var grant in context.Grants)
                _spent[grant.GrantKey] = _spent.GetValueOrDefault(grant.GrantKey) + cost;
            return Task.FromResult(CaveatDecision.Satisfied);
        }
    }

    // Only called for a context this handler allowed in the same invocation, so refund its cost.
    public Task ReleaseAsync(CaveatEnforcementContext context)
    {
        Interlocked.Increment(ref _releases);
        var cost = _costByAction[context.CapabilityAction];
        lock (_gate)
        {
            foreach (var grant in context.Grants)
                _spent[grant.GrantKey] -= cost;
        }

        return Task.CompletedTask;
    }
}

/// <summary>A handler with a scripted outcome, for ordering, failure and release tests.</summary>
public sealed class ScriptedCaveatHandler(string caveatType, Func<CaveatEnforcementContext, CaveatDecision> decide) : ICaveatHandler
{
    private int _calls;
    private int _releases;

    public string CaveatType { get; } = caveatType;

    public int Calls => _calls;

    public int Releases => _releases;

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        Interlocked.Increment(ref _calls);
        return Task.FromResult(decide(context));
    }

    public Task ReleaseAsync(CaveatEnforcementContext context)
    {
        Interlocked.Increment(ref _releases);
        return Task.CompletedTask;
    }
}

/// <summary>Builds a caveat-enabled issuer and verifier over one in-memory key store.</summary>
public sealed class CaveatTestBed
{
    public const string Target = "https://clinical.example/fhir";

    public CaveatTestBed(params ICaveatHandler[] handlers)
    {
        Registry = NewRegistry();
        Signing = new SigningService(Keys, Keys, Registry);
        Capabilities = new CapabilityService(Signing, Registry);
        Ledger = handlers.OfType<InMemoryEpsilonLedger>().FirstOrDefault() ?? new InMemoryEpsilonLedger();
        Handlers = handlers.Length == 0 ? new ICaveatHandler[] { Ledger } : handlers;
        Verifier = NewVerifier(Handlers);
    }

    public InMemoryDidProvider Keys { get; } = new();

    public CaveatTypeRegistry Registry { get; }

    public SigningService Signing { get; }

    public CapabilityService Capabilities { get; }

    public InMemoryEpsilonLedger Ledger { get; }

    public IReadOnlyList<ICaveatHandler> Handlers { get; }

    public InMemoryNonceStore Nonces { get; } = new();

    public InMemoryRevocationStore Revocations { get; } = new();

    public VerificationService Verifier { get; }

    public static CaveatTypeRegistry NewRegistry() => new CaveatTypeRegistry()
        .Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName)
        .Register<RegionCaveat>(RegionCaveat.TypeName)
        .Register<TagCaveat>(TagCaveat.TypeName);

    public VerificationService NewVerifier(IEnumerable<ICaveatHandler>? handlers, CaveatTypeRegistry? registry = null)
        => new(Keys, new RevocationService(Revocations), Nonces, relationshipResolver: Keys, rootResolver: Keys,
            caveats: registry ?? Registry, caveatHandlers: handlers);

    /// <summary>patient/clinician root → orchestrator (budget 8) → genomics agent (budget 3).</summary>
    public async Task<Chain> BuildChainAsync(double orchestratorBudget = 8, double agentBudget = 3,
        string[]? actions = null, string target = Target)
    {
        actions ??= new[] { "query", "query-large" };
        var patient = Keys.GenerateDidKey();
        var orchestrator = Keys.GenerateDidKey();
        var agent = Keys.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(Capabilities, Keys, patient, target);
        var granted = await Capabilities.DelegateCapabilityAsync(root, orchestrator, actions, DateTime.UtcNow.AddDays(1),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = orchestratorBudget } });
        var leaf = await Capabilities.DelegateCapabilityAsync(granted, agent, actions, DateTime.UtcNow.AddHours(12),
            caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = agentBudget } });
        return new Chain(root, granted, leaf, patient, orchestrator, agent);
    }

    public async Task<Invocation> InvokeAsync(Capability capability, string signer, string action = "query")
    {
        var invocation = Capabilities.CreateInvocation(capability, action);
        invocation.Proof = await Signing.SignInvocationAsync(invocation, signer);
        return invocation;
    }

    public static T RoundTrip<T>(T value)
        => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value, ZcapJsonOptions.Default),
            ZcapJsonOptions.Default)!;

    public sealed record Chain(Capability Root, Capability Orchestrator, Capability Agent,
        string PatientDid, string OrchestratorDid, string AgentDid);
}
