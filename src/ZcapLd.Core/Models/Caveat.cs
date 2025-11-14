using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Base class for capability caveats (restrictions).
/// Caveats represent restrictions on how a capability may be used.
/// Per W3C spec, child capabilities inherit all parent caveats.
/// </summary>
public abstract class Caveat
{
    /// <summary>
    /// Gets the type identifier for this caveat.
    /// </summary>
    [JsonPropertyName("type")]
    public abstract string Type { get; }

    /// <summary>
    /// Evaluates whether this caveat is satisfied for the given invocation context.
    /// </summary>
    /// <param name="context">The invocation context.</param>
    /// <returns>True if the caveat is satisfied; false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when context is null.</exception>
    public abstract bool IsSatisfied(InvocationContext context);

    /// <summary>
    /// Validates the caveat structure.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    public abstract void Validate();

    /// <summary>
    /// Gets a human-readable description of this caveat.
    /// </summary>
    /// <returns>A description of the caveat's restriction.</returns>
    public abstract string GetDescription();
}

/// <summary>
/// Caveat that restricts capability usage until a specific date/time.
/// This is redundant with the DelegatedCapability.Expires field but can be used
/// for additional time-based restrictions.
/// </summary>
public sealed class ExpirationCaveat : Caveat
{
    /// <summary>
    /// The caveat type identifier.
    /// </summary>
    public const string CaveatType = "Expiration";

    /// <summary>
    /// Gets the caveat type.
    /// </summary>
    public override string Type => CaveatType;

    /// <summary>
    /// Gets or sets the expiration date/time (UTC).
    /// </summary>
    [JsonPropertyName("expires")]
    public DateTime Expires { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExpirationCaveat"/> class.
    /// </summary>
    public ExpirationCaveat()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExpirationCaveat"/> class.
    /// </summary>
    /// <param name="expires">The expiration timestamp.</param>
    public ExpirationCaveat(DateTime expires)
    {
        Expires = expires;
    }

    /// <summary>
    /// Creates an expiration caveat.
    /// </summary>
    /// <param name="expires">The expiration timestamp.</param>
    /// <returns>A new expiration caveat.</returns>
    public static ExpirationCaveat Create(DateTime expires)
    {
        return new ExpirationCaveat(expires);
    }

    /// <inheritdoc/>
    public override bool IsSatisfied(InvocationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        return context.InvocationTime < Expires;
    }

    /// <inheritdoc/>
    public override void Validate()
    {
        if (Expires == default)
        {
            throw new CapabilityValidationException(
                "Expiration caveat must have a valid expiration timestamp.",
                "INVALID_EXPIRATION_CAVEAT");
        }
    }

    /// <inheritdoc/>
    public override string GetDescription()
    {
        return $"Expires at {Expires:O}";
    }
}

/// <summary>
/// Caveat that limits the number of times a capability can be used.
/// Note: Tracking CurrentUses requires stateful tracking in the verification system.
/// </summary>
public sealed class UsageCountCaveat : Caveat
{
    /// <summary>
    /// The caveat type identifier.
    /// </summary>
    public const string CaveatType = "UsageCount";

    /// <summary>
    /// Gets the caveat type.
    /// </summary>
    public override string Type => CaveatType;

    /// <summary>
    /// Gets or sets the maximum number of allowed uses.
    /// </summary>
    [JsonPropertyName("maxUses")]
    public int MaxUses { get; set; }

    /// <summary>
    /// Gets or sets the current usage count.
    /// This should be tracked externally and updated by the verification system.
    /// </summary>
    [JsonPropertyName("currentUses")]
    public int CurrentUses { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="UsageCountCaveat"/> class.
    /// </summary>
    public UsageCountCaveat()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UsageCountCaveat"/> class.
    /// </summary>
    /// <param name="maxUses">The maximum number of uses.</param>
    /// <param name="currentUses">The current usage count (defaults to 0).</param>
    public UsageCountCaveat(int maxUses, int currentUses = 0)
    {
        MaxUses = maxUses;
        CurrentUses = currentUses;
    }

    /// <summary>
    /// Creates a usage count caveat.
    /// </summary>
    /// <param name="maxUses">The maximum number of uses.</param>
    /// <returns>A new usage count caveat.</returns>
    public static UsageCountCaveat Create(int maxUses)
    {
        if (maxUses <= 0)
        {
            throw new ArgumentException("Max uses must be greater than zero.", nameof(maxUses));
        }

        return new UsageCountCaveat(maxUses);
    }

    /// <inheritdoc/>
    public override bool IsSatisfied(InvocationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        return CurrentUses < MaxUses;
    }

    /// <inheritdoc/>
    public override void Validate()
    {
        if (MaxUses <= 0)
        {
            throw new CapabilityValidationException(
                "Usage count caveat must have maxUses greater than zero.",
                "INVALID_USAGE_COUNT_CAVEAT");
        }

        if (CurrentUses < 0)
        {
            throw new CapabilityValidationException(
                "Usage count caveat currentUses cannot be negative.",
                "INVALID_CURRENT_USES");
        }
    }

    /// <inheritdoc/>
    public override string GetDescription()
    {
        return $"Limited to {MaxUses} uses (current: {CurrentUses})";
    }

    /// <summary>
    /// Increments the usage count.
    /// </summary>
    /// <returns>The new usage count.</returns>
    public int IncrementUsage()
    {
        return Interlocked.Increment(ref CurrentUses);
    }
}

/// <summary>
/// Caveat that restricts the capability to specific time windows.
/// </summary>
public sealed class TimeWindowCaveat : Caveat
{
    /// <summary>
    /// The caveat type identifier.
    /// </summary>
    public const string CaveatType = "TimeWindow";

    /// <summary>
    /// Gets the caveat type.
    /// </summary>
    public override string Type => CaveatType;

    /// <summary>
    /// Gets or sets the start time (UTC) when the capability becomes active.
    /// </summary>
    [JsonPropertyName("validFrom")]
    public DateTime ValidFrom { get; set; }

    /// <summary>
    /// Gets or sets the end time (UTC) when the capability becomes inactive.
    /// </summary>
    [JsonPropertyName("validUntil")]
    public DateTime ValidUntil { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TimeWindowCaveat"/> class.
    /// </summary>
    public TimeWindowCaveat()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TimeWindowCaveat"/> class.
    /// </summary>
    /// <param name="validFrom">The start time.</param>
    /// <param name="validUntil">The end time.</param>
    public TimeWindowCaveat(DateTime validFrom, DateTime validUntil)
    {
        ValidFrom = validFrom;
        ValidUntil = validUntil;
    }

    /// <summary>
    /// Creates a time window caveat.
    /// </summary>
    /// <param name="validFrom">The start time.</param>
    /// <param name="validUntil">The end time.</param>
    /// <returns>A new time window caveat.</returns>
    public static TimeWindowCaveat Create(DateTime validFrom, DateTime validUntil)
    {
        if (validFrom >= validUntil)
        {
            throw new ArgumentException("ValidFrom must be before ValidUntil.");
        }

        return new TimeWindowCaveat(validFrom, validUntil);
    }

    /// <inheritdoc/>
    public override bool IsSatisfied(InvocationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var time = context.InvocationTime;
        return time >= ValidFrom && time < ValidUntil;
    }

    /// <inheritdoc/>
    public override void Validate()
    {
        if (ValidFrom == default)
        {
            throw new CapabilityValidationException(
                "Time window caveat must have a valid ValidFrom timestamp.",
                "INVALID_TIME_WINDOW_FROM");
        }

        if (ValidUntil == default)
        {
            throw new CapabilityValidationException(
                "Time window caveat must have a valid ValidUntil timestamp.",
                "INVALID_TIME_WINDOW_UNTIL");
        }

        if (ValidFrom >= ValidUntil)
        {
            throw new CapabilityValidationException(
                "Time window caveat ValidFrom must be before ValidUntil.",
                "INVALID_TIME_WINDOW_RANGE");
        }
    }

    /// <inheritdoc/>
    public override string GetDescription()
    {
        return $"Valid from {ValidFrom:O} until {ValidUntil:O}";
    }
}

/// <summary>
/// Caveat that restricts actions to a specific set.
/// This can be used to further restrict actions beyond the capability's allowedAction.
/// </summary>
public sealed class ActionCaveat : Caveat
{
    /// <summary>
    /// The caveat type identifier.
    /// </summary>
    public const string CaveatType = "Action";

    /// <summary>
    /// Gets the caveat type.
    /// </summary>
    public override string Type => CaveatType;

    /// <summary>
    /// Gets or sets the allowed actions.
    /// </summary>
    [JsonPropertyName("allowedActions")]
    public string[] AllowedActions { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Initializes a new instance of the <see cref="ActionCaveat"/> class.
    /// </summary>
    public ActionCaveat()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ActionCaveat"/> class.
    /// </summary>
    /// <param name="allowedActions">The allowed actions.</param>
    public ActionCaveat(params string[] allowedActions)
    {
        AllowedActions = allowedActions ?? Array.Empty<string>();
    }

    /// <summary>
    /// Creates an action caveat.
    /// </summary>
    /// <param name="allowedActions">The allowed actions.</param>
    /// <returns>A new action caveat.</returns>
    public static ActionCaveat Create(params string[] allowedActions)
    {
        if (allowedActions == null || allowedActions.Length == 0)
        {
            throw new ArgumentException("At least one action must be specified.", nameof(allowedActions));
        }

        return new ActionCaveat(allowedActions);
    }

    /// <inheritdoc/>
    public override bool IsSatisfied(InvocationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (AllowedActions.Length == 0)
        {
            return true; // No restrictions
        }

        return AllowedActions.Contains(context.RequestedAction, StringComparer.Ordinal);
    }

    /// <inheritdoc/>
    public override void Validate()
    {
        if (AllowedActions.Any(string.IsNullOrWhiteSpace))
        {
            throw new CapabilityValidationException(
                "Action caveat contains empty or null action values.",
                "INVALID_ACTION_CAVEAT");
        }
    }

    /// <inheritdoc/>
    public override string GetDescription()
    {
        if (AllowedActions.Length == 0)
        {
            return "No action restrictions";
        }

        return $"Allowed actions: {string.Join(", ", AllowedActions)}";
    }
}

/// <summary>
/// Caveat that restricts invocations based on IP address ranges (CIDR notation).
/// </summary>
public sealed class IpAddressCaveat : Caveat
{
    /// <summary>
    /// The caveat type identifier.
    /// </summary>
    public const string CaveatType = "IpAddress";

    /// <summary>
    /// Gets the caveat type.
    /// </summary>
    public override string Type => CaveatType;

    /// <summary>
    /// Gets or sets the allowed IP address ranges in CIDR notation.
    /// Example: ["192.168.1.0/24", "10.0.0.0/8"]
    /// </summary>
    [JsonPropertyName("allowedRanges")]
    public string[] AllowedRanges { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Initializes a new instance of the <see cref="IpAddressCaveat"/> class.
    /// </summary>
    public IpAddressCaveat()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IpAddressCaveat"/> class.
    /// </summary>
    /// <param name="allowedRanges">The allowed IP ranges in CIDR notation.</param>
    public IpAddressCaveat(params string[] allowedRanges)
    {
        AllowedRanges = allowedRanges ?? Array.Empty<string>();
    }

    /// <summary>
    /// Creates an IP address caveat.
    /// </summary>
    /// <param name="allowedRanges">The allowed IP ranges in CIDR notation.</param>
    /// <returns>A new IP address caveat.</returns>
    public static IpAddressCaveat Create(params string[] allowedRanges)
    {
        if (allowedRanges == null || allowedRanges.Length == 0)
        {
            throw new ArgumentException("At least one IP range must be specified.", nameof(allowedRanges));
        }

        return new IpAddressCaveat(allowedRanges);
    }

    /// <inheritdoc/>
    public override bool IsSatisfied(InvocationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (AllowedRanges.Length == 0)
        {
            return true; // No restrictions
        }

        // Check if context has IP address property
        var ipAddress = context.GetProperty<string>("ipAddress");
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return false; // IP address required but not provided
        }

        // Note: Full CIDR matching would require System.Net.IPNetwork or similar
        // For now, we do simple string matching - implement proper CIDR matching in production
        return AllowedRanges.Any(range => ipAddress.StartsWith(range.Split('/')[0]));
    }

    /// <inheritdoc/>
    public override void Validate()
    {
        if (AllowedRanges.Any(string.IsNullOrWhiteSpace))
        {
            throw new CapabilityValidationException(
                "IP address caveat contains empty or null range values.",
                "INVALID_IP_ADDRESS_CAVEAT");
        }

        // TODO: Validate CIDR notation format
    }

    /// <inheritdoc/>
    public override string GetDescription()
    {
        if (AllowedRanges.Length == 0)
        {
            return "No IP address restrictions";
        }

        return $"Allowed IP ranges: {string.Join(", ", AllowedRanges)}";
    }
}
