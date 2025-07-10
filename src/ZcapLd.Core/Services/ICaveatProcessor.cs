using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for processing and evaluating capability caveats
/// </summary>
public interface ICaveatProcessor
{
    /// <summary>
    /// Evaluates all caveats for a capability invocation
    /// </summary>
    /// <param name="capability">The capability being invoked</param>
    /// <param name="context">The invocation context</param>
    /// <returns>True if all caveats are satisfied</returns>
    Task<bool> EvaluateCaveatsAsync(Capability capability, InvocationContext context);

    /// <summary>
    /// Merges caveats from a capability chain
    /// </summary>
    /// <param name="capabilityChain">The chain of capabilities</param>
    /// <returns>The merged set of caveats</returns>
    Task<Caveat[]> MergeCaveatsAsync(Capability[] capabilityChain);

    /// <summary>
    /// Validates that child caveats are compatible with parent caveats
    /// </summary>
    /// <param name="parentCaveats">The parent capability's caveats</param>
    /// <param name="childCaveats">The child capability's caveats</param>
    /// <returns>True if child caveats are valid</returns>
    Task<bool> ValidateCaveatCompatibilityAsync(Caveat[] parentCaveats, Caveat[] childCaveats);
}