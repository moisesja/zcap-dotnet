using System.Threading;
using System.Threading.Tasks;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Provides cryptographic key management operations for ZCAP-LD.
/// Implementations should handle secure key storage and retrieval.
/// </summary>
public interface IKeyProvider
{
    /// <summary>
    /// Generates a new Ed25519 key pair.
    /// </summary>
    /// <param name="keyId">The key identifier (typically a DID with fragment).</param>
    /// <param name="verificationMethod">Optional verification method URI. Defaults to keyId if null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new Ed25519 key pair.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null or empty.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when key generation fails.</exception>
    Task<KeyPair> GenerateKeyPairAsync(
        string keyId,
        string? verificationMethod = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a key pair by its key identifier.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The key pair if found; otherwise null.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null or empty.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when key retrieval fails.</exception>
    Task<KeyPair?> GetKeyPairAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a public key by its key identifier.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The public key if found; otherwise null.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null or empty.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when key retrieval fails.</exception>
    Task<PublicKey?> GetPublicKeyAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a key pair.
    /// </summary>
    /// <param name="keyPair">The key pair to store.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentNullException">Thrown when keyPair is null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when storage fails.</exception>
    Task StoreKeyPairAsync(KeyPair keyPair, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a key pair by its key identifier.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the key was deleted; false if not found.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null or empty.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when deletion fails.</exception>
    Task<bool> DeleteKeyPairAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a public key from a verification method URI.
    /// This may involve DID resolution or other key discovery mechanisms.
    /// </summary>
    /// <param name="verificationMethod">The verification method URI (e.g., "did:example:alice#key-1").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved public key if found; otherwise null.</returns>
    /// <exception cref="ArgumentNullException">Thrown when verificationMethod is null or empty.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when resolution fails.</exception>
    Task<PublicKey?> ResolvePublicKeyAsync(
        string verificationMethod,
        CancellationToken cancellationToken = default);
}
