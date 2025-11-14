using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a capability invocation request according to W3C ZCAP-LD specification.
/// An invocation activates a capability to perform an operation on a resource.
/// </summary>
public sealed class Invocation
{
    /// <summary>
    /// Gets or sets the unique identifier for this invocation (optional).
    /// Can serve as a nonce to prevent replay attacks.
    /// </summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets the reference to the capability being invoked.
    /// This MUST be the ID of a valid capability.
    /// </summary>
    [JsonPropertyName("capability")]
    public string Capability { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the action being requested.
    /// This SHOULD match one of the capability's allowedAction values.
    /// </summary>
    [JsonPropertyName("capabilityAction")]
    public string CapabilityAction { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the target resource URI for the invocation.
    /// This MUST match or be a valid subset of the capability's invocationTarget.
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    public string InvocationTarget { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the DID of the entity invoking the capability.
    /// </summary>
    [JsonPropertyName("invoker")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Invoker { get; set; }

    /// <summary>
    /// Gets or sets the proof of invocation.
    /// This MUST contain a valid capabilityInvocation proof.
    /// </summary>
    [JsonPropertyName("proof")]
    public Proof? Proof { get; set; }

    /// <summary>
    /// Gets or sets additional invocation arguments.
    /// These are operation-specific parameters passed with the invocation.
    /// </summary>
    [JsonPropertyName("arguments")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, object>? Arguments { get; set; }

    /// <summary>
    /// Creates a new invocation with the specified parameters.
    /// </summary>
    /// <param name="capabilityId">The ID of the capability being invoked.</param>
    /// <param name="action">The action being requested.</param>
    /// <param name="target">The target resource URI.</param>
    /// <param name="invoker">The DID of the invoker (optional).</param>
    /// <param name="id">Optional invocation ID (generated if not provided).</param>
    /// <returns>A new invocation.</returns>
    public static Invocation Create(
        string capabilityId,
        string action,
        string target,
        string? invoker = null,
        string? id = null)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId), "Capability ID is required.");
        }

        if (string.IsNullOrWhiteSpace(action))
        {
            throw new ArgumentNullException(nameof(action), "Action is required.");
        }

        if (string.IsNullOrWhiteSpace(target))
        {
            throw new ArgumentNullException(nameof(target), "Target is required.");
        }

        return new Invocation
        {
            Id = id ?? $"urn:uuid:{Guid.NewGuid()}",
            Capability = capabilityId,
            CapabilityAction = action,
            InvocationTarget = target,
            Invoker = invoker
        };
    }

    /// <summary>
    /// Validates the invocation structure.
    /// </summary>
    /// <exception cref="InvocationException">Thrown when validation fails.</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Capability))
        {
            throw new InvocationException(
                "Invocation must reference a capability.",
                null);
        }

        if (!Uri.TryCreate(Capability, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"Capability must be a valid URI: {Capability}",
                Capability);
        }

        if (string.IsNullOrWhiteSpace(CapabilityAction))
        {
            throw new InvocationException(
                "Invocation must specify an action.",
                Capability);
        }

        if (string.IsNullOrWhiteSpace(InvocationTarget))
        {
            throw new InvocationException(
                "Invocation must specify a target.",
                Capability);
        }

        if (!Uri.TryCreate(InvocationTarget, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"InvocationTarget must be a valid URI: {InvocationTarget}",
                Capability);
        }

        if (!string.IsNullOrWhiteSpace(Invoker) &&
            !Uri.TryCreate(Invoker, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"Invoker must be a valid DID URI: {Invoker}",
                Capability);
        }

        // Validate proof if present
        Proof?.Validate();

        // Ensure proof is an invocation proof
        if (Proof != null && !Proof.IsInvocationProof())
        {
            throw new InvocationException(
                "Invocation proof must have proofPurpose 'capabilityInvocation'.",
                Capability);
        }
    }

    /// <summary>
    /// Validates the invocation against a specific capability.
    /// </summary>
    /// <param name="capability">The capability being invoked.</param>
    /// <exception cref="InvocationException">Thrown when validation fails.</exception>
    public void ValidateAgainstCapability(CapabilityBase capability)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        // Ensure capability ID matches
        if (!string.Equals(Capability, capability.Id, StringComparison.Ordinal))
        {
            throw new InvocationException(
                $"Invocation capability ID '{Capability}' does not match provided capability '{capability.Id}'.",
                Capability);
        }

        // Validate invocation target matches or is subset of capability's target
        ValidateTargetMatch(capability.InvocationTarget);

        // For delegated capabilities, validate action is allowed
        if (capability is DelegatedCapability delegated)
        {
            if (!delegated.AllowsAction(CapabilityAction))
            {
                throw new InvocationException(
                    $"Action '{CapabilityAction}' is not allowed by capability. Allowed: [{string.Join(", ", delegated.GetAllowedActions())}]",
                    Capability);
            }

            // Validate not expired
            if (delegated.IsExpired())
            {
                throw new InvocationException(
                    $"Capability has expired: {delegated.Expires:O}",
                    Capability);
            }
        }
    }

    /// <summary>
    /// Validates that the invocation target matches or is a valid subset of the capability's target.
    /// </summary>
    /// <param name="capabilityTarget">The capability's invocationTarget.</param>
    private void ValidateTargetMatch(string capabilityTarget)
    {
        // Exact match is always valid
        if (string.Equals(InvocationTarget, capabilityTarget, StringComparison.Ordinal))
        {
            return;
        }

        // Check if invocation target is a valid subset (URL-based attenuation)
        if (!InvocationTarget.StartsWith(capabilityTarget, StringComparison.Ordinal))
        {
            throw new InvocationException(
                $"Invocation target '{InvocationTarget}' does not match capability target '{capabilityTarget}'.",
                Capability);
        }
    }

    /// <summary>
    /// Creates an invocation context for caveat evaluation.
    /// </summary>
    /// <returns>An invocation context.</returns>
    public InvocationContext ToContext()
    {
        return new InvocationContext(
            Capability,
            Invoker ?? "unknown",
            CapabilityAction,
            InvocationTarget,
            DateTime.UtcNow,
            Arguments);
    }

    /// <summary>
    /// Adds an argument to the invocation.
    /// </summary>
    /// <param name="key">The argument key.</param>
    /// <param name="value">The argument value.</param>
    /// <returns>This invocation for fluent chaining.</returns>
    public Invocation WithArgument(string key, object value)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentNullException(nameof(key));
        }

        Arguments ??= new Dictionary<string, object>();
        Arguments[key] = value;
        return this;
    }

    /// <summary>
    /// Sets the proof for this invocation.
    /// </summary>
    /// <param name="proof">The invocation proof.</param>
    /// <returns>This invocation for fluent chaining.</returns>
    public Invocation WithProof(Proof proof)
    {
        Proof = proof ?? throw new ArgumentNullException(nameof(proof));
        return this;
    }

    /// <summary>
    /// Gets an argument value by key.
    /// </summary>
    /// <typeparam name="T">The type of the argument value.</typeparam>
    /// <param name="key">The argument key.</param>
    /// <returns>The argument value, or default if not found.</returns>
    public T? GetArgument<T>(string key)
    {
        if (string.IsNullOrWhiteSpace(key) || Arguments == null)
        {
            return default;
        }

        if (Arguments.TryGetValue(key, out var value) && value is T typedValue)
        {
            return typedValue;
        }

        return default;
    }
}
