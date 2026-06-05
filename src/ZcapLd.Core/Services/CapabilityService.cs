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

    public CapabilityService(ISigningService signingService)
    {
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
    }

    /// <summary>
    /// Creates a root capability. Per W3C ZCAP-LD, a root capability represents
    /// complete authority over the resource — optional fields (allowedAction, caveat,
    /// expires, parentCapability, proof) are left unset so JSON serialization omits
    /// them entirely. Strict cross-language parsers (zcap-py and friends) reject
    /// empty arrays / null for these fields when present.
    /// </summary>
    public Task<Capability> CreateRootCapabilityAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null)
    {
        if (controller is null || controller.IsEmpty)
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
            // AllowedAction, Caveat, Expires, ParentCapability, Proof intentionally unset.
        };

        return Task.FromResult(capability);
    }

    /// <summary>
    /// Delegates a capability to a new controller with proper attenuation and caveat inheritance
    /// </summary>
    public async Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        ControllerSet newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null,
        string? signerDid = null)
    {
        if (parentCapability == null)
        {
            throw new ArgumentNullException(nameof(parentCapability));
        }

        if (newController is null || newController.IsEmpty)
        {
            throw new ArgumentException("New controller cannot be null or empty", nameof(newController));
        }

        // Determine which of the parent's controllers signs this delegation. A parent
        // may have several controllers; any one of them is authorized to delegate, so
        // the caller picks via signerDid (defaulting to the first controller).
        var parentControllers = parentCapability.Controller;
        if (parentControllers is null || parentControllers.IsEmpty)
        {
            throw new InvalidOperationException(
                "Parent capability has no controller authorized to sign the delegation.");
        }

        var effectiveSigner = signerDid ?? parentControllers.Primary;
        if (!parentControllers.Contains(effectiveSigner))
        {
            throw new ArgumentException(
                $"Signer '{effectiveSigner}' is not among the parent capability's controllers.",
                nameof(signerDid));
        }

        // Validate attenuation rules (delegated capability must be more restrictive)
        ValidateAttenuation(parentCapability, allowedActions, expires);

        // Inherit parent caveats (children inherit ALL parent caveats).
        // Returns null when neither parent nor child supplies any — keeps the field
        // off the wire so cross-language parsers see absence, not an empty array.
        var inheritedCaveats = InheritCaveats(parentCapability.Caveat, caveats);

        // Resolve the signer's crypto suite context URL dynamically
        var suiteContextUrl = await _signingService.ResolveSuiteContextUrlAsync(effectiveSigner);

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
            // Use parent's verbatim Expires string if caller didn't specify one;
            // format the caller-supplied DateTime canonically otherwise.
            Expires = expires.HasValue ? ZcapTimestamps.Format(expires.Value) : parentCapability.Expires,
            ParentCapability = parentCapability.Id,
            Caveat = inheritedCaveats
        };

        // Build capability chain for the proof
        var capabilityChain = BuildCapabilityChain(parentCapability);

        // Sign the capability with the selected parent controller's key.
        var proof = await _signingService.SignCapabilityAsync(
            delegatedCapability,
            effectiveSigner,
            "capabilityDelegation",
            capabilityChain);

        delegatedCapability.Proof = proof;

        return delegatedCapability;
    }

    /// <inheritdoc />
    public Invocation CreateInvocation(Capability capability, string capabilityAction, string? invocationTarget = null)
    {
        ArgumentNullException.ThrowIfNull(capability);
        if (string.IsNullOrEmpty(capability.Id))
        {
            throw new ArgumentException("Capability must have an id.", nameof(capability));
        }
        if (string.IsNullOrEmpty(capabilityAction))
        {
            throw new ArgumentException("Capability action cannot be null or empty", nameof(capabilityAction));
        }

        var target = invocationTarget ?? capability.InvocationTarget;
        if (string.IsNullOrEmpty(target))
        {
            throw new ArgumentException(
                "Invocation target cannot be null or empty (the capability has none to default to).",
                nameof(invocationTarget));
        }

        // Root capability → reference by id string; delegated → embed the full zcap object so the
        // verifier receives the delegated authority inline (Issue #51). The verifier enforces this
        // exact root-vs-delegated shape, so picking it here keeps callers spec-correct by construction.
        var reference = string.IsNullOrEmpty(capability.ParentCapability)
            ? InvocationCapability.FromId(capability.Id)
            : InvocationCapability.FromCapability(capability);

        return new Invocation
        {
            Capability = reference,
            CapabilityAction = capabilityAction,
            InvocationTarget = target
        };
    }

    /// <inheritdoc />
    public Invocation CreateRootInvocation(string rootCapabilityId, string capabilityAction, string invocationTarget)
    {
        if (string.IsNullOrEmpty(rootCapabilityId))
        {
            throw new ArgumentException("Root capability id cannot be null or empty", nameof(rootCapabilityId));
        }
        if (string.IsNullOrEmpty(capabilityAction))
        {
            throw new ArgumentException("Capability action cannot be null or empty", nameof(capabilityAction));
        }
        if (string.IsNullOrEmpty(invocationTarget))
        {
            throw new ArgumentException("Invocation target cannot be null or empty", nameof(invocationTarget));
        }

        return new Invocation
        {
            Capability = InvocationCapability.FromId(rootCapabilityId),
            CapabilityAction = capabilityAction,
            InvocationTarget = invocationTarget
        };
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

            if (capability.Controller is null || capability.Controller.IsEmpty)
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

                // Root zcaps MUST contain only @context, id, controller, invocationTarget.
                // "A root zcap MUST NOT have any other fields." (W3C CCG ZCAP-LD v0.3, Root Capability)
                // Strict policy: allowedAction/caveat must be absent (null), not empty — the spec
                // omits them on roots and CreateRootCapabilityAsync leaves them null, so no real
                // producer emits empty arrays. Unknown extension fields land in AdditionalProperties.
                if (capability.Proof != null ||
                    capability.Expires != null ||
                    capability.ParentCapability != null ||
                    capability.AllowedAction != null ||
                    capability.Caveat != null ||
                    capability.AdditionalProperties is { Count: > 0 })
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

                // MUST have proof, and at least one MUST be a capabilityDelegation proof
                // (the proof set may also carry other DI proofs alongside it).
                if (capability.Proof == null ||
                    capability.Proof.FirstDelegationProof() == null)
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
        var parentExpiresAt = parentCapability.ExpiresAt;
        if (expires.HasValue && parentExpiresAt.HasValue)
        {
            // Allow a small tolerance (1 second) for clock skew between delegation calls
            var tolerance = TimeSpan.FromSeconds(1);
            if (expires.Value > parentExpiresAt.Value.Add(tolerance))
            {
                throw new InvalidOperationException(
                    "Child capability expiration cannot be later than parent's expiration. " +
                    "Child capabilities cannot expand authority.");
            }
        }

        // The W3C ZCAP-LD 3-month expiration ceiling is a verifier-side SHOULD measured at
        // invocation time — NOT a create-time MUST (Issue #61). Enforcing it here as a hard throw
        // blocked even constructing a legitimately long-lived delegation the parent permits, and
        // mislocated the check (wrong actor, wrong time). The ceiling now lives on the verify path
        // behind a policy flag (Issue #73). Attenuation (child ≤ parent expiry) is still enforced
        // above.
    }

    /// <summary>
    /// Inherits caveats from parent and merges with new caveats.
    /// Per spec: children inherit ALL parent caveats and MAY add new ones.
    /// Returns null when neither side supplies any caveats so the field stays
    /// off the wire (vs. emitting an empty array, which strict cross-language
    /// parsers reject).
    /// </summary>
    private Caveat[]? InheritCaveats(Caveat[]? parentCaveats, Caveat[]? newCaveats)
    {
        var allCaveats = new List<Caveat>();

        if (parentCaveats != null && parentCaveats.Length > 0)
        {
            allCaveats.AddRange(parentCaveats);
        }

        if (newCaveats != null && newCaveats.Length > 0)
        {
            allCaveats.AddRange(newCaveats);
        }

        return allCaveats.Count == 0 ? null : allCaveats.ToArray();
    }

    /// <summary>
    /// Builds the <c>capabilityChain</c> for a delegation proof in the exact shape W3C ZCAP-LD
    /// requires (Issue #50): the root is referenced by ID only (never embedded), every other
    /// ancestor is referenced by ID, and ONLY the immediate parent delegated zcap is fully embedded
    /// — as the last entry. So a first-level delegation (parent is the root) yields <c>[rootId]</c>;
    /// deeper delegations yield <c>[rootId, ...ancestorIds, {immediateParent}]</c>. Because the chain
    /// is part of the signed/canonicalized proof, this minimal shape is what strict cross-language
    /// verifiers expect.
    /// </summary>
    private object[] BuildCapabilityChain(Capability parentCapability)
    {
        // A delegated parent carries its delegation chain on a capabilityDelegation proof; a root has
        // no such proof. When the parent is the root, the chain is just the root id — the root is
        // referenced by ID only and is NEVER embedded.
        var parentChainProof = parentCapability.Proof?.FirstDelegationProofWithChain();
        if (parentChainProof?.CapabilityChain is not { Length: > 0 } parentChain)
        {
            return new object[] { parentCapability.Id };
        }

        // The parent is itself delegated. Its own chain is [rootId, ...ancestorIds, {grandparent}].
        // Re-reference every entry by ID (the embedded grandparent collapses to its id string), then
        // append the parent as the single embedded object — i.e. the parent's chain with its trailing
        // embedded ancestor demoted to an id and the new immediate parent embedded in its place.
        var chain = new List<object>(parentChain.Length + 1);
        foreach (var entry in parentChain)
        {
            chain.Add(ExtractEntryId(entry));
        }
        chain.Add(parentCapability);
        return chain.ToArray();
    }

    /// <summary>
    /// Extracts the capability id from a <c>capabilityChain</c> entry, handling every form an entry
    /// can take: a CLR <see cref="string"/>, an embedded <see cref="Capability"/>, or a
    /// <see cref="JsonElement"/> string/object (after a JSON round-trip of a wire-received parent).
    /// Throws when no id can be read — a chain entry without an id is never valid.
    /// </summary>
    private static string ExtractEntryId(object entry) => entry switch
    {
        string s when s.Length > 0 => s,
        Capability cap when !string.IsNullOrEmpty(cap.Id) => cap.Id,
        JsonElement je when je.ValueKind == JsonValueKind.String &&
                            je.GetString() is { Length: > 0 } js => js,
        JsonElement je when je.ValueKind == JsonValueKind.Object &&
                            je.TryGetProperty("id", out var idProp) &&
                            idProp.ValueKind == JsonValueKind.String &&
                            idProp.GetString() is { Length: > 0 } objId => objId,
        _ => throw new InvalidOperationException(
            "capabilityChain entry has no readable id; cannot build a spec-exact delegation chain."),
    };

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
