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
    /// <param name="controller">The DID of the capability controller</param>
    /// <param name="invocationTarget">The target resource URI</param>
    /// <param name="allowedActions">Actions allowed by this capability</param>
    /// <param name="expires">Optional expiration time</param>
    /// <param name="caveats">Optional caveats to apply</param>
    /// <returns>The created capability</returns>
    Task<Capability> CreateRootCapabilityAsync(
        string controller,
        string invocationTarget,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null);

    /// <summary>
    /// Delegates a capability to another controller
    /// </summary>
    /// <param name="parentCapability">The parent capability to delegate</param>
    /// <param name="newController">The DID of the new controller</param>
    /// <param name="allowedActions">Actions to delegate (must be subset of parent)</param>
    /// <param name="expires">Optional expiration time (must not exceed parent)</param>
    /// <param name="caveats">Optional additional caveats</param>
    /// <returns>The delegated capability</returns>
    Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        string newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null);

    /// <summary>
    /// Validates a capability and its chain
    /// </summary>
    /// <param name="capability">The capability to validate</param>
    /// <returns>True if the capability is valid</returns>
    Task<bool> ValidateCapabilityAsync(Capability capability);
}