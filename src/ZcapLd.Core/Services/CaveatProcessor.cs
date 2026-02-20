using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for processing and evaluating capability caveats
/// Implements W3C ZCAP-LD caveat inheritance and evaluation
/// </summary>
public class CaveatProcessor : ICaveatProcessor
{
    /// <summary>
    /// Evaluates all caveats for a capability invocation
    /// Per spec: All caveats in the chain must be satisfied
    /// </summary>
    public Task<bool> EvaluateCaveatsAsync(Capability capability, InvocationContext context)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));
        if (context == null)
            throw new ArgumentNullException(nameof(context));

        try
        {
            // Evaluate all caveats on this capability
            foreach (var caveat in capability.Caveat)
            {
                if (!caveat.IsSatisfied(context))
                {
                    return Task.FromResult(false);
                }
            }

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            throw new CaveatException("Failed to evaluate caveats", ex);
        }
    }

    /// <summary>
    /// Merges caveats from a capability chain
    /// Per spec: Child capabilities inherit ALL parent caveats
    /// </summary>
    public Task<Caveat[]> MergeCaveatsAsync(Capability[] capabilityChain)
    {
        if (capabilityChain == null || capabilityChain.Length == 0)
            throw new ArgumentException("Capability chain cannot be null or empty", nameof(capabilityChain));

        try
        {
            var allCaveats = new List<Caveat>();

            // Iterate from root to leaf, collecting all caveats
            foreach (var capability in capabilityChain)
            {
                if (capability.Caveat != null && capability.Caveat.Length > 0)
                {
                    allCaveats.AddRange(capability.Caveat);
                }
            }

            return Task.FromResult(allCaveats.ToArray());
        }
        catch (Exception ex)
        {
            throw new CaveatException("Failed to merge caveats", ex);
        }
    }

    /// <summary>
    /// Validates that child caveats are compatible with parent caveats
    /// Per spec: Children inherit ALL parent caveats and MAY add new ones
    /// Children CANNOT remove parent caveats
    /// </summary>
    public Task<bool> ValidateCaveatCompatibilityAsync(Caveat[] parentCaveats, Caveat[] childCaveats)
    {
        if (parentCaveats == null)
            parentCaveats = Array.Empty<Caveat>();
        if (childCaveats == null)
            childCaveats = Array.Empty<Caveat>();

        try
        {
            // All parent caveats must be present in child caveats
            // (or child must inherit them implicitly)

            // For now, we consider compatibility valid if:
            // 1. Child has all parent caveats (by type), OR
            // 2. Child will inherit parent caveats during merge

            // Since caveats are merged during chain verification,
            // we just need to ensure child doesn't violate parent restrictions

            // This is primarily validated during chain traversal and evaluation
            // Here we just check for obvious incompatibilities

            foreach (var parentCaveat in parentCaveats)
            {
                // Check if child has explicitly defined a conflicting caveat
                var matchingChildCaveat = childCaveats.FirstOrDefault(c => c.Type == parentCaveat.Type);

                if (matchingChildCaveat != null)
                {
                    // If child explicitly defines the same caveat type,
                    // it should be MORE restrictive, not less

                    // For ExpirationCaveat, child expiration should be earlier
                    if (parentCaveat is ExpirationCaveat parentExpiration &&
                        matchingChildCaveat is ExpirationCaveat childExpiration)
                    {
                        if (childExpiration.Expires > parentExpiration.Expires)
                        {
                            return Task.FromResult(false); // Child is less restrictive
                        }
                    }

                    // For UsageCountCaveat, child max uses should be less or equal
                    if (parentCaveat is UsageCountCaveat parentUsage &&
                        matchingChildCaveat is UsageCountCaveat childUsage)
                    {
                        if (childUsage.MaxUses > parentUsage.MaxUses)
                        {
                            return Task.FromResult(false); // Child is less restrictive
                        }
                    }

                    // Other caveat types can add similar validation
                }
            }

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            throw new CaveatException("Failed to validate caveat compatibility", ex);
        }
    }

    /// <summary>
    /// Helper method to evaluate a complete capability chain's caveats
    /// </summary>
    public async Task<bool> EvaluateCapabilityChainCaveatsAsync(
        Capability[] capabilityChain,
        InvocationContext context)
    {
        if (capabilityChain == null || capabilityChain.Length == 0)
            throw new ArgumentException("Capability chain cannot be null or empty", nameof(capabilityChain));

        if (context == null)
            throw new ArgumentNullException(nameof(context));

        // Merge all caveats from the chain
        var allCaveats = await MergeCaveatsAsync(capabilityChain);

        // Create a temporary capability with merged caveats for evaluation
        var mergedCapability = new Capability
        {
            Caveat = allCaveats
        };

        // Evaluate all merged caveats
        return await EvaluateCaveatsAsync(mergedCapability, context);
    }
}
