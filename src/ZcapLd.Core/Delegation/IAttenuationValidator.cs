using System;
using System.Threading;
using System.Threading.Tasks;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Validates capability attenuation, ensuring that delegated capabilities
/// have equal or lesser authority than their parent capabilities.
/// </summary>
public interface IAttenuationValidator
{
    /// <summary>
    /// Validates that a delegated capability is properly attenuated from its parent.
    /// Checks URL-based attenuation, expiration, allowed actions, and caveats.
    /// </summary>
    /// <param name="parent">The parent capability.</param>
    /// <param name="delegated">The delegated (child) capability.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure with details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when parent or delegated is null.</exception>
    Task<ValidationResult> ValidateAttenuationAsync(
        CapabilityBase parent,
        DelegatedCapability delegated,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates URL-based attenuation between parent and child invocation targets.
    /// The child's invocation target must be equal to or a path suffix of the parent's target.
    /// </summary>
    /// <param name="parentTarget">The parent's invocation target URL.</param>
    /// <param name="delegatedTarget">The delegated capability's invocation target URL.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any target is null or empty.</exception>
    ValidationResult ValidateUrlAttenuation(string parentTarget, string delegatedTarget);

    /// <summary>
    /// Validates that a delegated capability's expiration is not later than its parent's.
    /// For root capabilities (no expiration), child capabilities can have any expiration.
    /// </summary>
    /// <param name="parent">The parent capability.</param>
    /// <param name="delegated">The delegated capability.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when parent or delegated is null.</exception>
    ValidationResult ValidateExpirationAttenuation(
        CapabilityBase parent,
        DelegatedCapability delegated);

    /// <summary>
    /// Validates that a delegated capability's allowed actions are a subset of the parent's.
    /// If the parent has no allowed actions, any actions are permitted.
    /// </summary>
    /// <param name="parent">The parent capability.</param>
    /// <param name="delegated">The delegated capability.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when parent or delegated is null.</exception>
    ValidationResult ValidateActionAttenuation(
        CapabilityBase parent,
        DelegatedCapability delegated);

    /// <summary>
    /// Validates that all parent caveats are inherited by the delegated capability.
    /// The child must have all parent caveats plus optionally additional caveats.
    /// </summary>
    /// <param name="parent">The parent capability.</param>
    /// <param name="delegated">The delegated capability.</param>
    /// <param name="context">The invocation context for caveat evaluation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when parent or delegated is null.</exception>
    Task<ValidationResult> ValidateCaveatInheritanceAsync(
        CapabilityBase parent,
        DelegatedCapability delegated,
        InvocationContext? context = null,
        CancellationToken cancellationToken = default);
}
