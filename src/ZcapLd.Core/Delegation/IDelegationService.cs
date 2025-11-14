using System;
using System.Threading;
using System.Threading.Tasks;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Provides capability delegation operations including creation, validation, and revocation.
/// Orchestrates chain building, attenuation enforcement, and proof generation.
/// </summary>
public interface IDelegationService
{
    /// <summary>
    /// Delegates a capability to a new controller with optional attenuation.
    /// Creates a new delegated capability, validates attenuation, and generates a cryptographic proof.
    /// </summary>
    /// <param name="parentCapability">The parent capability to delegate from.</param>
    /// <param name="delegateeController">The DID of the new controller (delegatee).</param>
    /// <param name="delegatorKeyPair">The key pair of the delegator (parent capability controller).</param>
    /// <param name="attenuatedTarget">Optional attenuated invocation target (must be suffix of parent).</param>
    /// <param name="allowedAction">Optional allowed actions for the delegated capability.</param>
    /// <param name="expires">Optional expiration time (must be before parent expiration).</param>
    /// <param name="caveats">Optional additional caveats (added to inherited parent caveats).</param>
    /// <param name="invoker">Optional specific invoker DID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new delegated capability with proof.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    /// <exception cref="Exceptions.CapabilityValidationException">Thrown when delegation violates attenuation rules.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when proof generation fails.</exception>
    Task<DelegatedCapability> DelegateCapabilityAsync(
        CapabilityBase parentCapability,
        string delegateeController,
        KeyPair delegatorKeyPair,
        string? attenuatedTarget = null,
        object? allowedAction = null,
        DateTime? expires = null,
        Caveat[]? caveats = null,
        object? invoker = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Builds a complete capability chain from root to the specified capability.
    /// </summary>
    /// <param name="capability">The capability to build a chain for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The capability chain as an array of objects.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability is null.</exception>
    Task<object[]> BuildCapabilityChainAsync(
        CapabilityBase capability,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a complete delegation chain from root to leaf.
    /// Checks structural integrity, depth limits, proof signatures, and attenuation at each level.
    /// </summary>
    /// <param name="capability">The capability to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure with details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability is null.</exception>
    Task<ValidationResult> ValidateCapabilityAsync(
        CapabilityBase capability,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a capability chain without loading additional data.
    /// Useful when you already have the complete chain.
    /// </summary>
    /// <param name="capability">The capability to validate.</param>
    /// <param name="chain">The complete capability chain.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure with details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability or chain is null.</exception>
    Task<ValidationResult> ValidateCapabilityChainAsync(
        CapabilityBase capability,
        object[] chain,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a capability has been revoked.
    /// This is optional and requires configuration to enable revocation checking.
    /// </summary>
    /// <param name="capabilityId">The capability ID to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the capability is revoked; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capabilityId is null or empty.</exception>
    Task<bool> IsRevokedAsync(string capabilityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a capability, preventing its future use.
    /// This is optional and requires configuration to enable revocation.
    /// </summary>
    /// <param name="capabilityId">The capability ID to revoke.</param>
    /// <param name="revokerKeyPair">The key pair of the revoker (must be capability controller).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    /// <exception cref="Exceptions.CapabilityValidationException">Thrown when revocation is not authorized.</exception>
    Task RevokeCapabilityAsync(
        string capabilityId,
        KeyPair revokerKeyPair,
        CancellationToken cancellationToken = default);
}
