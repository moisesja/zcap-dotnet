using System;
using System.Threading;
using System.Threading.Tasks;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Validates capability delegation chains for structural integrity and cryptographic validity.
/// </summary>
public interface ICapabilityChainValidator
{
    /// <summary>
    /// Validates a complete capability chain from root to leaf.
    /// Checks chain structure, depth limits, proof signatures, and attenuation at each level.
    /// </summary>
    /// <param name="capability">The capability to validate (can be root or delegated).</param>
    /// <param name="chain">The complete capability chain from root to this capability.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure with details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability or chain is null.</exception>
    Task<ValidationResult> ValidateChainAsync(
        CapabilityBase capability,
        object[] chain,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the structure of a capability chain.
    /// Ensures the chain is properly formatted per W3C ZCAP-LD spec:
    /// - First element must be root capability ID (string)
    /// - Intermediate elements are capability IDs (strings)
    /// - Last element is the parent capability (object)
    /// </summary>
    /// <param name="chain">The capability chain to validate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when chain is null.</exception>
    ValidationResult ValidateChainStructure(object[] chain);

    /// <summary>
    /// Validates that a capability chain does not exceed the maximum allowed depth.
    /// </summary>
    /// <param name="chain">The capability chain to validate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when chain is null.</exception>
    ValidationResult ValidateChainDepth(object[] chain);

    /// <summary>
    /// Validates the proof of a delegated capability against its parent.
    /// Verifies the cryptographic signature and proof structure.
    /// </summary>
    /// <param name="capability">The delegated capability with proof.</param>
    /// <param name="parentCapability">The parent capability.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability or parentCapability is null.</exception>
    /// <exception cref="ArgumentException">Thrown when capability is not a DelegatedCapability.</exception>
    Task<ValidationResult> ValidateProofAsync(
        DelegatedCapability capability,
        CapabilityBase parentCapability,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the continuity of a capability chain.
    /// Ensures each capability in the chain properly references its parent.
    /// </summary>
    /// <param name="capability">The leaf capability to validate.</param>
    /// <param name="chain">The complete capability chain.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    /// <exception cref="ArgumentNullException">Thrown when capability or chain is null.</exception>
    ValidationResult ValidateChainContinuity(CapabilityBase capability, object[] chain);

    /// <summary>
    /// Extracts the root capability from a capability chain.
    /// </summary>
    /// <param name="chain">The capability chain.</param>
    /// <returns>The root capability, or null if chain is invalid.</returns>
    CapabilityBase? ExtractRootCapability(object[] chain);

    /// <summary>
    /// Extracts the parent capability from a capability chain.
    /// The parent is the last element in the chain (as an object).
    /// </summary>
    /// <param name="chain">The capability chain.</param>
    /// <returns>The parent capability, or null if chain is invalid.</returns>
    CapabilityBase? ExtractParentCapability(object[] chain);
}
