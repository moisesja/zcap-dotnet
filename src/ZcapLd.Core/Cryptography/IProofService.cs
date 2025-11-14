using System.Threading;
using System.Threading.Tasks;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Provides proof generation and verification for ZCAP-LD capabilities.
/// Handles Data Integrity proofs per W3C specification.
/// </summary>
public interface IProofService
{
    /// <summary>
    /// Creates a capability delegation proof for a delegated capability.
    /// This proof authorizes the delegation from parent to child capability.
    /// </summary>
    /// <param name="capability">The delegated capability to sign.</param>
    /// <param name="keyPair">The key pair of the delegator (parent capability controller).</param>
    /// <param name="capabilityChain">The capability chain (root ID, intermediate IDs, parent object).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Data Integrity proof with proofPurpose "capabilityDelegation".</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when capabilityChain is empty or invalid.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when proof generation fails.</exception>
    Task<Proof> CreateDelegationProofAsync(
        DelegatedCapability capability,
        KeyPair keyPair,
        object[] capabilityChain,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a capability invocation proof for invoking a capability.
    /// This proof authorizes the invocation of a specific action.
    /// </summary>
    /// <param name="invocation">The invocation to sign.</param>
    /// <param name="keyPair">The key pair of the invoker.</param>
    /// <param name="capabilityId">The ID of the capability being invoked.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Data Integrity proof with proofPurpose "capabilityInvocation".</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when proof generation fails.</exception>
    Task<Proof> CreateInvocationProofAsync(
        Invocation invocation,
        KeyPair keyPair,
        string capabilityId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a capability delegation proof.
    /// </summary>
    /// <param name="capability">The delegated capability with proof.</param>
    /// <param name="parentPublicKey">The public key of the parent capability controller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the proof is valid; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when capability has no proof.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when verification fails unexpectedly.</exception>
    Task<bool> VerifyDelegationProofAsync(
        DelegatedCapability capability,
        PublicKey parentPublicKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a capability invocation proof.
    /// </summary>
    /// <param name="invocation">The invocation with proof.</param>
    /// <param name="invokerPublicKey">The public key of the invoker.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the proof is valid; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when invocation has no proof.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when verification fails unexpectedly.</exception>
    Task<bool> VerifyInvocationProofAsync(
        Invocation invocation,
        PublicKey invokerPublicKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a proof by signing canonical JSON-LD representation.
    /// This is a lower-level method for custom proof scenarios.
    /// </summary>
    /// <param name="document">The JSON-LD document to sign.</param>
    /// <param name="keyPair">The key pair for signing.</param>
    /// <param name="proofPurpose">The proof purpose (e.g., "capabilityDelegation").</param>
    /// <param name="capabilityChain">Optional capability chain for delegation proofs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The generated proof.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when proof generation fails.</exception>
    Task<Proof> CreateProofAsync(
        object document,
        KeyPair keyPair,
        string proofPurpose,
        object[]? capabilityChain = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a proof against a JSON-LD document.
    /// This is a lower-level method for custom proof scenarios.
    /// </summary>
    /// <param name="document">The JSON-LD document that was signed.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the proof is valid; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when verification fails unexpectedly.</exception>
    Task<bool> VerifyProofAsync(
        object document,
        Proof proof,
        PublicKey publicKey,
        CancellationToken cancellationToken = default);
}
