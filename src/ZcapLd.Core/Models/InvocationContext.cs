using System.Collections.Concurrent;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Provides context information for capability invocation evaluation.
/// This class is thread-safe and immutable after construction.
/// </summary>
public sealed class InvocationContext
{
    private readonly ConcurrentDictionary<string, object> _properties;

    /// <summary>
    /// Gets the timestamp of the invocation.
    /// </summary>
    public DateTime InvocationTime { get; }

    /// <summary>
    /// Gets the action being requested.
    /// </summary>
    public string RequestedAction { get; }

    /// <summary>
    /// Gets the target resource URI.
    /// </summary>
    public string TargetResource { get; }

    /// <summary>
    /// Gets the DID of the entity invoking the capability.
    /// </summary>
    public string Invoker { get; }

    /// <summary>
    /// Gets the capability ID being invoked.
    /// </summary>
    public string CapabilityId { get; }

    /// <summary>
    /// Gets additional context properties in a thread-safe manner.
    /// </summary>
    public IReadOnlyDictionary<string, object> Properties => _properties;

    /// <summary>
    /// Initializes a new instance of the <see cref="InvocationContext"/> class.
    /// </summary>
    /// <param name="capabilityId">The capability ID being invoked.</param>
    /// <param name="invoker">The DID of the invoker.</param>
    /// <param name="requestedAction">The action being requested.</param>
    /// <param name="targetResource">The target resource URI.</param>
    /// <param name="invocationTime">The invocation timestamp (defaults to current UTC time).</param>
    /// <param name="properties">Optional additional properties.</param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null or empty.</exception>
    public InvocationContext(
        string capabilityId,
        string invoker,
        string requestedAction,
        string targetResource,
        DateTime? invocationTime = null,
        IDictionary<string, object>? properties = null)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId), "Capability ID is required.");
        }

        if (string.IsNullOrWhiteSpace(invoker))
        {
            throw new ArgumentNullException(nameof(invoker), "Invoker DID is required.");
        }

        if (string.IsNullOrWhiteSpace(requestedAction))
        {
            throw new ArgumentNullException(nameof(requestedAction), "Requested action is required.");
        }

        if (string.IsNullOrWhiteSpace(targetResource))
        {
            throw new ArgumentNullException(nameof(targetResource), "Target resource is required.");
        }

        CapabilityId = capabilityId;
        Invoker = invoker;
        RequestedAction = requestedAction;
        TargetResource = targetResource;
        InvocationTime = invocationTime ?? DateTime.UtcNow;

        _properties = properties != null
            ? new ConcurrentDictionary<string, object>(properties)
            : new ConcurrentDictionary<string, object>();
    }

    /// <summary>
    /// Creates a new invocation context with the specified parameters.
    /// </summary>
    /// <param name="capabilityId">The capability ID being invoked.</param>
    /// <param name="invoker">The DID of the invoker.</param>
    /// <param name="requestedAction">The action being requested.</param>
    /// <param name="targetResource">The target resource URI.</param>
    /// <returns>A new invocation context.</returns>
    public static InvocationContext Create(
        string capabilityId,
        string invoker,
        string requestedAction,
        string targetResource)
    {
        return new InvocationContext(
            capabilityId,
            invoker,
            requestedAction,
            targetResource);
    }

    /// <summary>
    /// Gets a property value by key.
    /// </summary>
    /// <typeparam name="T">The type of the property value.</typeparam>
    /// <param name="key">The property key.</param>
    /// <returns>The property value, or default if not found.</returns>
    public T? GetProperty<T>(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return default;
        }

        if (_properties.TryGetValue(key, out var value) && value is T typedValue)
        {
            return typedValue;
        }

        return default;
    }

    /// <summary>
    /// Checks if a property exists.
    /// </summary>
    /// <param name="key">The property key.</param>
    /// <returns>True if the property exists; otherwise, false.</returns>
    public bool HasProperty(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        return _properties.ContainsKey(key);
    }

    /// <summary>
    /// Validates the invocation context.
    /// </summary>
    /// <exception cref="InvocationException">Thrown when validation fails.</exception>
    public void Validate()
    {
        if (!Uri.TryCreate(CapabilityId, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"Capability ID must be a valid URI: {CapabilityId}",
                CapabilityId);
        }

        if (!Uri.TryCreate(Invoker, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"Invoker must be a valid DID URI: {Invoker}",
                CapabilityId);
        }

        if (!Uri.TryCreate(TargetResource, UriKind.Absolute, out _))
        {
            throw new InvocationException(
                $"Target resource must be a valid URI: {TargetResource}",
                CapabilityId);
        }

        if (InvocationTime > DateTime.UtcNow.AddMinutes(5)) // Allow 5 min clock skew
        {
            throw new InvocationException(
                $"Invocation time cannot be in the future: {InvocationTime:O}",
                CapabilityId);
        }
    }

    /// <summary>
    /// Creates a new context with updated properties.
    /// </summary>
    /// <param name="additionalProperties">Additional properties to add.</param>
    /// <returns>A new invocation context with the updated properties.</returns>
    public InvocationContext WithProperties(IDictionary<string, object> additionalProperties)
    {
        if (additionalProperties == null || additionalProperties.Count == 0)
        {
            return this;
        }

        var mergedProperties = new Dictionary<string, object>(_properties);
        foreach (var kvp in additionalProperties)
        {
            mergedProperties[kvp.Key] = kvp.Value;
        }

        return new InvocationContext(
            CapabilityId,
            Invoker,
            RequestedAction,
            TargetResource,
            InvocationTime,
            mergedProperties);
    }

    /// <summary>
    /// Checks if the invocation is recent (within specified time window).
    /// </summary>
    /// <param name="maxAgeMinutes">Maximum age in minutes (default: 5 minutes).</param>
    /// <returns>True if invocation is recent; otherwise, false.</returns>
    public bool IsRecent(int maxAgeMinutes = 5)
    {
        var age = DateTime.UtcNow - InvocationTime;
        return age.TotalMinutes <= maxAgeMinutes;
    }
}
