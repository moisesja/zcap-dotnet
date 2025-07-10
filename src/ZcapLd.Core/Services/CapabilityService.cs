using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default implementation of capability service
/// </summary>
public class CapabilityService : ICapabilityService
{
    public Task<Capability> CreateRootCapabilityAsync(
        string controller,
        string invocationTarget,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null)
    {
        var capability = new Capability
        {
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = controller,
            InvocationTarget = invocationTarget,
            AllowedAction = allowedActions,
            Expires = expires,
            Caveat = caveats ?? Array.Empty<Caveat>()
        };

        return Task.FromResult(capability);
    }

    public Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        string newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null)
    {
        var delegatedCapability = new Capability
        {
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = newController,
            InvocationTarget = parentCapability.InvocationTarget,
            AllowedAction = allowedActions,
            Expires = expires,
            ParentCapability = parentCapability.Id,
            Caveat = caveats ?? Array.Empty<Caveat>()
        };

        return Task.FromResult(delegatedCapability);
    }

    public Task<bool> ValidateCapabilityAsync(Capability capability)
    {
        // Basic validation - can be expanded later
        var isValid = !string.IsNullOrEmpty(capability.Id) &&
                      !string.IsNullOrEmpty(capability.Controller) &&
                      !string.IsNullOrEmpty(capability.InvocationTarget) &&
                      capability.AllowedAction.Length > 0;

        return Task.FromResult(isValid);
    }
}