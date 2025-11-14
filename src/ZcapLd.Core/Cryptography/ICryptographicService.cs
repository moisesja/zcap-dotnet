using System.Threading;
using System.Threading.Tasks;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Provides cryptographic signing and verification operations for ZCAP-LD.
/// Supports Ed25519 signatures per W3C Data Integrity specification.
/// </summary>
public interface ICryptographicService
{
    /// <summary>
    /// Gets the signature algorithm identifier.
    /// For Ed25519, this should return "Ed25519Signature2020".
    /// </summary>
    string SignatureAlgorithm { get; }

    /// <summary>
    /// Signs data using the provided private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="privateKey">The private key bytes (32 bytes for Ed25519).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or privateKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKey has invalid length.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when signing fails.</exception>
    Task<byte[]> SignAsync(
        byte[] data,
        byte[] privateKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a signature using the provided public key.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKey">The public key bytes (32 bytes for Ed25519).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if signature is valid; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data, signature, or publicKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when publicKey has invalid length.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when verification fails unexpectedly.</exception>
    Task<bool> VerifyAsync(
        byte[] data,
        byte[] signature,
        byte[] publicKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs data using a key pair.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="keyPair">The key pair containing the private key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or keyPair is null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when signing fails.</exception>
    Task<byte[]> SignAsync(
        byte[] data,
        KeyPair keyPair,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a signature using a public key object.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKey">The public key object.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if signature is valid; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data, signature, or publicKey is null.</exception>
    /// <exception cref="Exceptions.CryptographicException">Thrown when verification fails unexpectedly.</exception>
    Task<bool> VerifyAsync(
        byte[] data,
        byte[] signature,
        PublicKey publicKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a new Ed25519 key pair.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A tuple containing the public key and private key bytes.</returns>
    /// <exception cref="Exceptions.CryptographicException">Thrown when key generation fails.</exception>
    Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync(
        CancellationToken cancellationToken = default);
}
