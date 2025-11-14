using System;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Configuration options for capability delegation operations.
/// </summary>
public sealed class DelegationOptions
{
    /// <summary>
    /// Gets or sets the maximum depth of a capability chain.
    /// Prevents infinite delegation chains.
    /// Default: 10.
    /// </summary>
    public int MaxChainDepth { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum allowed clock skew for timestamp validation.
    /// Used when validating proof timestamps and expiration times.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan MaxClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets whether to enforce strict URL-based attenuation.
    /// When true, delegated capabilities must have invocation targets that are
    /// prefixes of or equal to their parent's invocation target.
    /// Default: true.
    /// </summary>
    public bool EnforceUrlAttenuation { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to enforce caveat inheritance.
    /// When true, child capabilities must satisfy all parent caveats.
    /// Default: true.
    /// </summary>
    public bool EnforceCaveatInheritance { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to check for capability revocation.
    /// When true, the revocation status of capabilities will be checked during validation.
    /// Default: false (revocation checking is optional).
    /// </summary>
    public bool CheckRevocation { get; set; } = false;

    /// <summary>
    /// Gets or sets the default expiration duration for delegated capabilities
    /// when no expiration is explicitly specified.
    /// Default: 30 days.
    /// </summary>
    public TimeSpan DefaultExpirationDuration { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Gets or sets whether to allow delegation without expiration.
    /// When false, all delegated capabilities must have an expiration time.
    /// Default: false.
    /// </summary>
    public bool AllowNoExpiration { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to validate proof signatures during delegation.
    /// When true, all proofs in the capability chain will be verified.
    /// Default: true.
    /// </summary>
    public bool ValidateProofSignatures { get; set; } = true;

    /// <summary>
    /// Validates the options configuration.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when options are invalid.</exception>
    public void Validate()
    {
        if (MaxChainDepth < 1)
        {
            throw new InvalidOperationException(
                $"{nameof(MaxChainDepth)} must be at least 1. Current value: {MaxChainDepth}");
        }

        if (MaxChainDepth > 100)
        {
            throw new InvalidOperationException(
                $"{nameof(MaxChainDepth)} cannot exceed 100 to prevent excessive chain depth. Current value: {MaxChainDepth}");
        }

        if (MaxClockSkew < TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"{nameof(MaxClockSkew)} cannot be negative. Current value: {MaxClockSkew}");
        }

        if (MaxClockSkew > TimeSpan.FromHours(24))
        {
            throw new InvalidOperationException(
                $"{nameof(MaxClockSkew)} cannot exceed 24 hours. Current value: {MaxClockSkew}");
        }

        if (DefaultExpirationDuration < TimeSpan.FromMinutes(1))
        {
            throw new InvalidOperationException(
                $"{nameof(DefaultExpirationDuration)} must be at least 1 minute. Current value: {DefaultExpirationDuration}");
        }
    }

    /// <summary>
    /// Creates a new instance with default values.
    /// </summary>
    public static DelegationOptions Default => new();

    /// <summary>
    /// Creates a new instance configured for strict security.
    /// Enforces all validations with conservative limits.
    /// </summary>
    public static DelegationOptions Strict => new()
    {
        MaxChainDepth = 5,
        MaxClockSkew = TimeSpan.FromMinutes(1),
        EnforceUrlAttenuation = true,
        EnforceCaveatInheritance = true,
        CheckRevocation = true,
        DefaultExpirationDuration = TimeSpan.FromDays(7),
        AllowNoExpiration = false,
        ValidateProofSignatures = true
    };

    /// <summary>
    /// Creates a new instance configured for lenient/testing scenarios.
    /// Relaxes some validations for development purposes.
    /// WARNING: Not recommended for production use.
    /// </summary>
    public static DelegationOptions Lenient => new()
    {
        MaxChainDepth = 20,
        MaxClockSkew = TimeSpan.FromMinutes(15),
        EnforceUrlAttenuation = false,
        EnforceCaveatInheritance = false,
        CheckRevocation = false,
        DefaultExpirationDuration = TimeSpan.FromDays(365),
        AllowNoExpiration = true,
        ValidateProofSignatures = false
    };
}
