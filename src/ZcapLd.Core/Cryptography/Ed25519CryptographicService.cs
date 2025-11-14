using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Ed25519 cryptographic service implementation using System.Security.Cryptography.
/// Provides Ed25519 signature creation and verification per W3C Data Integrity specification.
/// Thread-safe.
/// </summary>
public sealed class Ed25519CryptographicService : ICryptographicService
{
    private const int Ed25519PublicKeyLength = 32;
    private const int Ed25519PrivateKeyLength = 32;
    private const int Ed25519SignatureLength = 64;

    private readonly ILogger<Ed25519CryptographicService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Ed25519CryptographicService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    public Ed25519CryptographicService(ILogger<Ed25519CryptographicService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public string SignatureAlgorithm => Models.Proof.Ed25519Signature2020;

    /// <inheritdoc/>
    public async Task<byte[]> SignAsync(
        byte[] data,
        byte[] privateKey,
        CancellationToken cancellationToken = default)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data), "Data to sign cannot be null.");
        }

        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey), "Private key cannot be null.");
        }

        if (privateKey.Length != Ed25519PrivateKeyLength)
        {
            throw new ArgumentException(
                $"Ed25519 private key must be exactly {Ed25519PrivateKeyLength} bytes. Received: {privateKey.Length} bytes.",
                nameof(privateKey));
        }

        try
        {
            // Ed25519 signing is CPU-bound, so use Task.Run
            var signature = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var key = System.Security.Cryptography.Ed25519.Create(privateKey);
                var sig = key.SignData(data);

                _logger.LogDebug(
                    "Signed {DataLength} bytes with Ed25519, produced signature of {SignatureLength} bytes",
                    data.Length,
                    sig.Length);

                return sig;
            }, cancellationToken).ConfigureAwait(false);

            return signature;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign data with Ed25519");
            throw new CryptographicException("Failed to sign data with Ed25519.", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyAsync(
        byte[] data,
        byte[] signature,
        byte[] publicKey,
        CancellationToken cancellationToken = default)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data), "Data to verify cannot be null.");
        }

        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature), "Signature cannot be null.");
        }

        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey), "Public key cannot be null.");
        }

        if (publicKey.Length != Ed25519PublicKeyLength)
        {
            throw new ArgumentException(
                $"Ed25519 public key must be exactly {Ed25519PublicKeyLength} bytes. Received: {publicKey.Length} bytes.",
                nameof(publicKey));
        }

        if (signature.Length != Ed25519SignatureLength)
        {
            _logger.LogDebug(
                "Signature verification failed: invalid signature length. Expected {Expected}, received {Actual}",
                Ed25519SignatureLength,
                signature.Length);
            return false;
        }

        try
        {
            // Ed25519 verification is CPU-bound, so use Task.Run
            var isValid = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var key = System.Security.Cryptography.Ed25519.Create(publicKey);
                var valid = key.VerifyData(data, signature);

                _logger.LogDebug(
                    "Verified signature for {DataLength} bytes: {IsValid}",
                    data.Length,
                    valid);

                return valid;
            }, cancellationToken).ConfigureAwait(false);

            return isValid;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (CryptographicException ex)
        {
            _logger.LogDebug(ex, "Signature verification failed due to cryptographic error");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during signature verification");
            throw new CryptographicException("Unexpected error during signature verification.", ex);
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> SignAsync(
        byte[] data,
        KeyPair keyPair,
        CancellationToken cancellationToken = default)
    {
        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }

        return SignAsync(data, keyPair.PrivateKey, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<bool> VerifyAsync(
        byte[] data,
        byte[] signature,
        PublicKey publicKey,
        CancellationToken cancellationToken = default)
    {
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        return VerifyAsync(data, signature, publicKey.KeyBytes, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Key generation is CPU-bound, so use Task.Run
            var keyPair = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var key = System.Security.Cryptography.Ed25519.Create();

                // Export the private key (contains both private and public key data)
                var privateKeyBytes = key.ExportPrivateKey();

                // Export the public key
                var publicKeyBytes = key.ExportPublicKey();

                _logger.LogDebug(
                    "Generated Ed25519 key pair: public key {PublicKeyLength} bytes, private key {PrivateKeyLength} bytes",
                    publicKeyBytes.Length,
                    privateKeyBytes.Length);

                return (publicKeyBytes, privateKeyBytes);
            }, cancellationToken).ConfigureAwait(false);

            return keyPair;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate Ed25519 key pair");
            throw new CryptographicException("Failed to generate Ed25519 key pair.", ex);
        }
    }
}
