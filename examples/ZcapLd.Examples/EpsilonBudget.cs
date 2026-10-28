using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Examples;

/// <summary>
/// A custom caveat (#157): the maximum differential-privacy budget a delegate may spend. It only
/// describes the restriction and how a child may narrow it; the resource enforces it.
/// </summary>
public sealed class EpsilonBudgetCaveat : Caveat
{
    public override string Type => "EpsilonBudget";

    [JsonPropertyName("maxEpsilon")]
    public required double MaxEpsilon { get; init; }

    public override void Validate()
    {
        if (!(MaxEpsilon > 0 && MaxEpsilon <= 100))
            throw new CapabilityValidationException("maxEpsilon must be greater than 0 and at most 100.");
    }

    // A delegate may lower the budget, never raise it.
    public override bool IsAttenuationOf(Caveat parent)
        => parent is EpsilonBudgetCaveat budget && MaxEpsilon <= budget.MaxEpsilon;
}

/// <summary>
/// The resource's enforcement of <see cref="EpsilonBudgetCaveat"/>. A production ledger is a shared,
/// atomic store (for example Redis or SQL) used by every verifier replica.
/// </summary>
public sealed class EpsilonBudgetLedger : ICaveatHandler
{
    // The resource decides what each action costs, from the signed action only.
    private static readonly Dictionary<string, decimal> CostByAction = new() { ["query"] = 1m, ["cohort-query"] = 2m };
    private readonly Dictionary<string, decimal> _spent = new();
    private readonly object _gate = new();

    public string CaveatType => "EpsilonBudget";

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        if (!CostByAction.TryGetValue(context.CapabilityAction, out var cost))
            return Task.FromResult(CaveatDecision.Deny($"No privacy cost is defined for '{context.CapabilityAction}'."));

        // No cache by invocation id: the invoker chooses it, and the verifier's replay check already
        // delivers each live nonce once. Share the nonce store and this ledger across replicas.
        lock (_gate)
        {
            // Every grant in the chain is debited, so siblings share their ancestors' budgets.
            // Ceilings come from the presented, signed grants; state is keyed by GrantKey.
            foreach (var grant in context.Grants)
            {
                var ceiling = (decimal)((EpsilonBudgetCaveat)grant.Caveat).MaxEpsilon;
                if (_spent.GetValueOrDefault(grant.GrantKey) + cost > ceiling)
                    return Task.FromResult(CaveatDecision.Deny($"The privacy budget of {grant.CapabilityId} is exhausted."));
            }

            foreach (var grant in context.Grants)
                _spent[grant.GrantKey] = _spent.GetValueOrDefault(grant.GrantKey) + cost;
            return Task.FromResult(CaveatDecision.Satisfied);
        }
    }
}
