using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default implementation of capability service
/// Implements W3C ZCAP-LD specification for creating and delegating capabilities
/// </summary>
public class CapabilityService : ICapabilityService
{
    private readonly ISigningService _signingService;

    public CapabilityService(ISigningService signingService)
    {
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
    }

    /// <summary>
    /// Creates a root capability
    /// Root capabilities do NOT have a proof, expires, or parentCapability
    /// </summary>
    public Task<Capability> CreateRootCapabilityAsync(
        string controller,
        string invocationTarget,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null)
    {
        if (string.IsNullOrEmpty(controller))
        {
            throw new ArgumentException("Controller cannot be null or empty", nameof(controller));
        }

        if (string.IsNullOrEmpty(invocationTarget))
        {
            throw new ArgumentException("InvocationTarget cannot be null or empty", nameof(invocationTarget));
        }

        if (!Uri.IsWellFormedUriString(invocationTarget, UriKind.Absolute))
        {
            throw new ArgumentException("InvocationTarget must be a valid absolute URI", nameof(invocationTarget));
        }

        // Root capability ID format per spec: urn:zcap:root:${encodeURIComponent(invocationTarget)}
        var encodedTarget = Uri.EscapeDataString(invocationTarget);
        var rootId = $"urn:zcap:root:{encodedTarget}";

        var capability = new Capability
        {
            Context = "https://w3id.org/zcap/v1", // Must be string for root capabilities
            Id = rootId,
            Controller = controller,
            InvocationTarget = invocationTarget,
            AllowedAction = allowedActions,
            Caveat = caveats ?? Array.Empty<Caveat>(),
            // Root capabilities MUST NOT have:
            Expires = null,
            ParentCapability = null,
            Proof = null
        };

        return Task.FromResult(capability);
    }

    /// <summary>
    /// Delegates a capability to a new controller with proper attenuation and caveat inheritance
    /// </summary>
    public async Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        string newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null)
    {
        if (parentCapability == null)
        {
            throw new ArgumentNullException(nameof(parentCapability));
        }

        if (string.IsNullOrEmpty(newController))
        {
            throw new ArgumentException("New controller cannot be null or empty", nameof(newController));
        }

        // Validate attenuation rules (delegated capability must be more restrictive)
        ValidateAttenuation(parentCapability, allowedActions, expires);

        // Inherit parent caveats (children inherit ALL parent caveats)
        var inheritedCaveats = InheritCaveats(parentCapability.Caveat, caveats);

        // Create the delegated capability (without proof initially)
        var delegatedCapability = new Capability
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = newController,
            InvocationTarget = parentCapability.InvocationTarget,
            AllowedAction = allowedActions,
            Expires = expires ?? parentCapability.Expires, // Use parent's expiration if not specified
            ParentCapability = parentCapability.Id,
            Caveat = inheritedCaveats
        };

        // Build capability chain for the proof
        var capabilityChain = BuildCapabilityChain(parentCapability);

        // Sign the capability with the parent's controller
        // Note: In practice, you'd need to have access to the parent controller's key
        // For now, we assume the parent controller signs
        var proof = await _signingService.SignCapabilityAsync(
            delegatedCapability,
            parentCapability.Controller,
            "capabilityDelegation",
            capabilityChain);

        delegatedCapability.Proof = proof;

        return delegatedCapability;
    }

    /// <summary>
    /// Validates capability according to W3C ZCAP-LD specification
    /// </summary>
    public Task<bool> ValidateCapabilityAsync(Capability capability)
    {
        try
        {
            // Basic required fields
            if (string.IsNullOrEmpty(capability.Id))
            {
                return Task.FromResult(false);
            }

            if (string.IsNullOrEmpty(capability.Controller))
            {
                return Task.FromResult(false);
            }

            if (string.IsNullOrEmpty(capability.InvocationTarget))
            {
                return Task.FromResult(false);
            }

            // Validate invocation target is a URI
            if (!Uri.IsWellFormedUriString(capability.InvocationTarget, UriKind.Absolute))
            {
                return Task.FromResult(false);
            }

            // Check if it's a root or delegated capability
            bool isRoot = capability.ParentCapability == null;

            if (isRoot)
            {
                // Root capability validation
                // Context MUST be string
                if (capability.Context is not string)
                {
                    return Task.FromResult(false);
                }

                // ID MUST follow urn:zcap:root format (SHOULD)
                if (!capability.Id.StartsWith("urn:zcap:root:"))
                {
                    // Warning: Not following SHOULD requirement, but not invalid
                }

                // Root capabilities MUST NOT have proof, expires, or parentCapability
                if (capability.Proof != null || capability.Expires != null || capability.ParentCapability != null)
                {
                    return Task.FromResult(false);
                }
            }
            else
            {
                // Delegated capability validation
                // Context MUST be array
                if (capability.Context is not object[])
                {
                    return Task.FromResult(false);
                }

                // MUST have expires
                if (capability.Expires == null)
                {
                    return Task.FromResult(false);
                }

                // MUST have proof
                if (capability.Proof == null)
                {
                    return Task.FromResult(false);
                }

                // ID SHOULD be urn:uuid format
                if (!capability.Id.StartsWith("urn:uuid:"))
                {
                    // Warning: Not following SHOULD requirement, but not invalid
                }
            }

            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Validates attenuation rules: delegated capability must be more restrictive than parent
    /// </summary>
    private void ValidateAttenuation(Capability parentCapability, string[] allowedActions, DateTime? expires)
    {
        // Validate allowed actions (child must not add actions not in parent)
        if (parentCapability.AllowedAction != null && parentCapability.AllowedAction.Length > 0)
        {
            foreach (var action in allowedActions)
            {
                if (!parentCapability.AllowedAction.Contains(action))
                {
                    throw new InvalidOperationException(
                        $"Action '{action}' is not allowed by parent capability. " +
                        $"Child capabilities cannot expand authority.");
                }
            }
        }

        // Validate expiration (child must not be less restrictive)
        if (expires.HasValue && parentCapability.Expires.HasValue)
        {
            if (expires.Value > parentCapability.Expires.Value)
            {
                throw new InvalidOperationException(
                    "Child capability expiration cannot be later than parent's expiration. " +
                    "Child capabilities cannot expand authority.");
            }
        }

        // Validate 3-month maximum expiration (SHOULD requirement)
        if (expires.HasValue)
        {
            var threeMonthsFromNow = DateTime.UtcNow.AddMonths(3);
            if (expires.Value > threeMonthsFromNow)
            {
                // This is a SHOULD, not MUST, so we just warn but don't throw
                // In production, you might want to log this warning
            }
        }
    }

    /// <summary>
    /// Inherits caveats from parent and merges with new caveats
    /// Per spec: children inherit ALL parent caveats and MAY add new ones
    /// </summary>
    private Caveat[] InheritCaveats(Caveat[] parentCaveats, Caveat[]? newCaveats)
    {
        var allCaveats = new List<Caveat>();

        // Add all parent caveats first
        if (parentCaveats != null && parentCaveats.Length > 0)
        {
            allCaveats.AddRange(parentCaveats);
        }

        // Add new caveats
        if (newCaveats != null && newCaveats.Length > 0)
        {
            allCaveats.AddRange(newCaveats);
        }

        return allCaveats.ToArray();
    }

    /// <summary>
    /// Builds the capability chain for a delegation proof
    /// Per spec:
    /// - First element: root capability ID (string)
    /// - Middle elements: intermediate capability IDs (strings)
    /// - Last element: immediate parent capability (full object)
    /// </summary>
    private object[] BuildCapabilityChain(Capability parentCapability)
    {
        var chain = new List<object>();

        // If parent is delegated (has a proof with chain), it's not the root
        if (parentCapability.Proof?.CapabilityChain != null && parentCapability.Proof.CapabilityChain.Length > 0)
        {
            // Parent is delegated, so copy its chain
            // The parent's chain already contains: [root, ...intermediates, parent's parent]
            chain.AddRange(parentCapability.Proof.CapabilityChain);

            // Now add the parent itself as the last element (full object)
            // But first, we need to check if the last element is the parent's parent object
            // If so, replace it with parent's parent ID and add parent object

            // Get all IDs (strings) from the chain
            var ids = chain.Where(x => x is string).ToList();

            // Add parent's ID to the intermediate chain
            // Actually, we need to reconstruct: [root, ...intermediates, parent object]
            chain = new List<object>();

            // Add root ID (first element of parent's chain)
            if (parentCapability.Proof.CapabilityChain.Length > 0)
            {
                var rootId = parentCapability.Proof.CapabilityChain[0];
                if (rootId is string)
                {
                    chain.Add(rootId);
                }
            }

            // Add intermediate IDs (if parent was delegated from a chain)
            // The parent's chain structure: [root, intermediates..., parent's parent object]
            // We need to extract intermediate IDs and add parent's ID
            for (int i = 1; i < parentCapability.Proof.CapabilityChain.Length; i++)
            {
                var element = parentCapability.Proof.CapabilityChain[i];
                if (element is string strId)
                {
                    chain.Add(strId);
                }
                else
                {
                    // This is the parent's parent object, extract its ID
                    if (element is Capability cap)
                    {
                        chain.Add(cap.Id);
                    }
                    else if (element is System.Text.Json.JsonElement jsonEl)
                    {
                        if (jsonEl.TryGetProperty("id", out var idProp))
                        {
                            chain.Add(idProp.GetString() ?? "");
                        }
                    }
                }
            }

            // Add parent ID as intermediate
            chain.Add(parentCapability.Id);
        }
        else
        {
            // Parent is a root capability, so just add its ID
            chain.Add(parentCapability.Id);
        }

        return chain.ToArray();
    }
}
