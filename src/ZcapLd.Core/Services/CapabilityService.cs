using System.Text.Json;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default implementation of capability service
/// Implements W3C ZCAP-LD specification for creating and delegating capabilities
/// </summary>
public class CapabilityService : ICapabilityService
{
    private readonly ISigningService _signingService;

    // https://w3c-ccg.github.io/zcap-spec/#:~:text=expiration%20date%2Dtime.-,A,-verifier%20SHOULD%20ensure
    private const short MaxExpirationMonths = 3;

    public CapabilityService(ISigningService signingService)
    {
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
    }

    /// <summary>
    /// Creates a root capability
    /// Root capabilities do NOT have a proof, expires, or parentCapability
    /// NOTE C-01: Per strict W3C interpretation, root capabilities might not need allowedAction/caveat,
    /// but we include them for practical use. Consider using serialization options to omit when null/empty.
    /// </summary>
    public Task<Capability> CreateRootCapabilityAsync(
        string controller,
        string invocationTarget,
        string[]? allowedActions = null,
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
            // COMPLIANCE FIX: MUST-03 - Root capabilities MUST NOT have allowedAction/caveat/expires
            // These fields are only for delegated capabilities
            // Root capabilities represent complete authority over the resource
            AllowedAction = Array.Empty<string>(), // Always empty for root capabilities
            Caveat = Array.Empty<Caveat>(), // Always empty for root capabilities
            Expires = null, // Always null for root capabilities
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

        // Resolve the signer's crypto suite context URL dynamically
        var suiteContextUrl = await _signingService.ResolveSuiteContextUrlAsync(parentCapability.Controller);

        // Create the delegated capability (without proof initially)
        var delegatedCapability = new Capability
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1",
                suiteContextUrl
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

            // COMPLIANCE FIX: SHOULD-05 - Validate action names (should be read/write)
            if (capability.AllowedAction != null && capability.AllowedAction.Length > 0)
            {
                var validActions = new[] { "read", "write" };
                foreach (var action in capability.AllowedAction)
                {
                    if (!validActions.Contains(action, StringComparer.OrdinalIgnoreCase))
                    {
                        // SHOULD requirement: non-standard actions should fail validation
                        return Task.FromResult(false);
                    }
                }
            }

            // Check if it's a root or delegated capability
            bool isRoot = capability.ParentCapability == null;

            if (isRoot)
            {
                // Root capability validation
                // Context MUST be string (handles both native string and JsonElement after deserialization)
                if (!IsStringContext(capability.Context))
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
                // Context MUST be array (handles both native object[] and JsonElement after deserialization)
                if (!IsArrayContext(capability.Context))
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
            // Allow a small tolerance (1 second) for clock skew between delegation calls
            var tolerance = TimeSpan.FromSeconds(1);
            if (expires.Value > parentCapability.Expires.Value.Add(tolerance))
            {
                throw new InvalidOperationException(
                    "Child capability expiration cannot be later than parent's expiration. " +
                    "Child capabilities cannot expand authority.");
            }
        }

        // COMPLIANCE FIX: SHOULD-04 - Enforce 3-month maximum expiration
        if (expires.HasValue)
        {
            var maximumExpirationDate = DateTime.UtcNow.AddMonths(MaxExpirationMonths);
            if (expires.Value > maximumExpirationDate)
            {
                throw new InvalidOperationException(
                    $"Capability expiration exceeds recommended {MaxExpirationMonths}-month limit. " +
                    $"Requested: {expires.Value:O}, Maximum allowed: {maximumExpirationDate:O}");
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
    /// COMPLIANCE FIX C-03: Per W3C ZCAP-LD spec section 3.3:
    /// - First element: root capability ID (string)
    /// - Middle elements: intermediate capability IDs (strings)
    /// - Last element: immediate parent capability (FULL OBJECT with proof)
    /// </summary>
    private object[] BuildCapabilityChain(Capability parentCapability)
    {
        var chain = new List<object>();

        // If parent is delegated (has a proof with chain), it's not the root
        if (parentCapability.Proof?.CapabilityChain != null && parentCapability.Proof.CapabilityChain.Length > 0)
        {
            // Parent is delegated
            // Its chain structure: [rootId, ...intermediateIds, grandparentObject]

            // Extract all string IDs from parent's chain (these are root + intermediates)
            var stringIds = new List<string>();
            for (int i = 0; i < parentCapability.Proof.CapabilityChain.Length; i++)
            {
                var element = parentCapability.Proof.CapabilityChain[i];
                if (element is string strId)
                {
                    stringIds.Add(strId);
                }
                else if (element is System.Text.Json.JsonElement jsonEl && jsonEl.ValueKind == JsonValueKind.String)
                {
                    stringIds.Add(jsonEl.GetString() ?? "");
                }
                else
                {
                    // This is the embedded parent object (grandparent from our perspective)
                    // Extract its ID to add as intermediate
                    if (element is Capability cap)
                    {
                        stringIds.Add(cap.Id);
                    }
                    else if (element is System.Text.Json.JsonElement jsonObj && jsonObj.ValueKind == JsonValueKind.Object)
                    {
                        if (jsonObj.TryGetProperty("id", out var idProp))
                        {
                            stringIds.Add(idProp.GetString() ?? "");
                        }
                    }
                }
            }

            // Add all IDs (root + intermediates from parent's chain)
            chain.AddRange(stringIds);

            // Add parent's ID as intermediate
            chain.Add(parentCapability.Id);

            // CRITICAL: Add parent as full embedded object (last element)
            chain.Add(parentCapability);
        }
        else
        {
            // Parent is a root capability
            // Chain should be: [rootId, rootObject]
            chain.Add(parentCapability.Id);
            chain.Add(parentCapability);
        }

        return chain.ToArray();
    }

    /// <summary>
    /// Checks if Context is a string value, handling both native string
    /// and JsonElement (which occurs after JSON deserialization of object-typed properties).
    /// </summary>
    private static bool IsStringContext(object? context) =>
        context is string ||
        (context is JsonElement je && je.ValueKind == JsonValueKind.String);

    /// <summary>
    /// Checks if Context is an array value, handling both native object[]
    /// and JsonElement (which occurs after JSON deserialization of object-typed properties).
    /// </summary>
    private static bool IsArrayContext(object? context) =>
        context is object[] ||
        (context is JsonElement je && je.ValueKind == JsonValueKind.Array);
}
