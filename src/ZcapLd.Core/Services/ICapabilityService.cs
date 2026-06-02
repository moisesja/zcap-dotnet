using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for creating and managing ZCAP-LD capabilities
/// </summary>
public interface ICapabilityService
{
    /// <summary>
    /// Creates a new root capability
    /// </summary>
    /// <param name="controller">The controller(s) of the capability — a single DID
    /// (implicit from <see cref="string"/>) or several (implicit from <c>string[]</c>)</param>
    /// <param name="invocationTarget">The target resource URI</param>
    /// <param name="allowedActions">Optional; ignored for root capabilities. A root carries no
    /// <c>allowedAction</c> per W3C ZCAP-LD (it represents complete authority over the resource),
    /// so the implementation discards this. The interface previously declared it required, forcing
    /// callers to pass a throwaway array; the signature now matches the implementation (Issue #66).</param>
    /// <param name="expires">Ignored for root capabilities — a root carries no <c>expires</c> per
    /// W3C ZCAP-LD (it is unbounded; <c>ValidateCapabilityAsync</c> actively rejects a root that
    /// carries one). Supplying it has no effect; it is not honored (Issue #72).</param>
    /// <param name="caveats">Ignored for root capabilities — a root carries no <c>caveat</c> per
    /// W3C ZCAP-LD. Supplying caveats has no effect; apply restrictions on a delegated capability
    /// instead (Issue #72).</param>
    /// <returns>The created capability</returns>
    Task<Capability> CreateRootCapabilityAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null);

    /// <summary>
    /// Delegates a capability to another controller
    /// </summary>
    /// <param name="parentCapability">The parent capability to delegate</param>
    /// <param name="newController">The controller(s) of the new capability — a single DID
    /// (implicit from <see cref="string"/>) or several (implicit from <c>string[]</c>)</param>
    /// <param name="allowedActions">Actions to delegate (must be subset of parent)</param>
    /// <param name="expires">Optional expiration time (must not exceed parent)</param>
    /// <param name="caveats">Optional additional caveats</param>
    /// <param name="signerDid">Which of the parent's controllers signs the delegation.
    /// Defaults to the parent's first controller; must be one of the parent's controllers.</param>
    /// <returns>The delegated capability</returns>
    Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        ControllerSet newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null,
        string? signerDid = null);

    /// <summary>
    /// Validates a capability and its chain
    /// </summary>
    /// <param name="capability">The capability to validate</param>
    /// <returns>True if the capability is valid</returns>
    Task<bool> ValidateCapabilityAsync(Capability capability);
}