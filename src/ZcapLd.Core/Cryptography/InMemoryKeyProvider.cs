using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// In-memory implementation of <see cref="IKeyProvider"/>.
/// Stores keys in memory using a thread-safe concurrent dictionary.
/// WARNING: Keys are lost when the application restarts. Not suitable for production.
/// Use this for testing, development, or scenarios where key persistence is handled externally.
/// Thread-safe.
/// </summary>
public sealed class InMemoryKeyProvider : IKeyProvider
{
    private readonly ICryptographicService _cryptoService;
    private readonly ILogger<InMemoryKeyProvider> _logger;
    private readonly ConcurrentDictionary<string, KeyPair> _keyStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryKeyProvider"/> class.
    /// </summary>
    /// <param name="cryptoService">The cryptographic service for key generation.</param>
    /// <param name="logger">The logger instance.</param>
    public InMemoryKeyProvider(
        ICryptographicService cryptoService,
        ILogger<InMemoryKeyProvider> logger)
    {
        _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _keyStore = new ConcurrentDictionary<string, KeyPair>(StringComparer.Ordinal);
    }

    /// <inheritdoc/>
    public async Task<KeyPair> GenerateKeyPairAsync(
        string keyId,
        string? verificationMethod = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentNullException(nameof(keyId), "Key ID cannot be null or empty.");
        }

        try
        {
            _logger.LogDebug("Generating new key pair with ID: {KeyId}", keyId);

            var (publicKey, privateKey) = await _cryptoService
                .GenerateKeyPairAsync(cancellationToken)
                .ConfigureAwait(false);

            var keyPair = new KeyPair(publicKey, privateKey, keyId, verificationMethod);

            // Store the key pair
            if (!_keyStore.TryAdd(keyId, keyPair))
            {
                throw new CryptographicException(
                    $"A key with ID '{keyId}' already exists. Use a unique key ID or delete the existing key first.");
            }

            _logger.LogInformation(
                "Successfully generated and stored key pair with ID: {KeyId}",
                keyId);

            return keyPair;
        }
        catch (Exception ex) when (ex is not CryptographicException && ex is not ArgumentException)
        {
            _logger.LogError(ex, "Failed to generate key pair with ID: {KeyId}", keyId);
            throw new CryptographicException($"Failed to generate key pair with ID '{keyId}'.", ex);
        }
    }

    /// <inheritdoc/>
    public Task<KeyPair?> GetKeyPairAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentNullException(nameof(keyId), "Key ID cannot be null or empty.");
        }

        _keyStore.TryGetValue(keyId, out var keyPair);

        _logger.LogDebug(
            "Key pair retrieval for ID '{KeyId}': {Found}",
            keyId,
            keyPair != null ? "Found" : "Not found");

        return Task.FromResult(keyPair);
    }

    /// <inheritdoc/>
    public Task<PublicKey?> GetPublicKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentNullException(nameof(keyId), "Key ID cannot be null or empty.");
        }

        if (_keyStore.TryGetValue(keyId, out var keyPair))
        {
            var publicKey = new PublicKey(
                keyPair.PublicKey,
                keyPair.KeyId,
                keyPair.VerificationMethod);

            _logger.LogDebug("Retrieved public key for ID: {KeyId}", keyId);
            return Task.FromResult<PublicKey?>(publicKey);
        }

        _logger.LogDebug("Public key not found for ID: {KeyId}", keyId);
        return Task.FromResult<PublicKey?>(null);
    }

    /// <inheritdoc/>
    public Task StoreKeyPairAsync(KeyPair keyPair, CancellationToken cancellationToken = default)
    {
        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }

        _keyStore.AddOrUpdate(
            keyPair.KeyId,
            keyPair,
            (_, _) => keyPair);

        _logger.LogInformation("Stored key pair with ID: {KeyId}", keyPair.KeyId);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<bool> DeleteKeyPairAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentNullException(nameof(keyId), "Key ID cannot be null or empty.");
        }

        var removed = _keyStore.TryRemove(keyId, out var keyPair);

        if (removed && keyPair != null)
        {
            // Clear the private key from memory for security
            keyPair.Clear();
            _logger.LogInformation("Deleted and cleared key pair with ID: {KeyId}", keyId);
        }
        else
        {
            _logger.LogDebug("Key pair not found for deletion: {KeyId}", keyId);
        }

        return Task.FromResult(removed);
    }

    /// <inheritdoc/>
    public Task<PublicKey?> ResolvePublicKeyAsync(
        string verificationMethod,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(verificationMethod))
        {
            throw new ArgumentNullException(
                nameof(verificationMethod),
                "Verification method cannot be null or empty.");
        }

        // Simple resolution: look for a key with matching verification method
        foreach (var kvp in _keyStore)
        {
            if (kvp.Value.VerificationMethod.Equals(verificationMethod, StringComparison.Ordinal))
            {
                var publicKey = new PublicKey(
                    kvp.Value.PublicKey,
                    kvp.Value.KeyId,
                    kvp.Value.VerificationMethod);

                _logger.LogDebug(
                    "Resolved verification method '{VerificationMethod}' to key ID: {KeyId}",
                    verificationMethod,
                    kvp.Key);

                return Task.FromResult<PublicKey?>(publicKey);
            }
        }

        _logger.LogDebug(
            "Could not resolve verification method: {VerificationMethod}",
            verificationMethod);

        return Task.FromResult<PublicKey?>(null);
    }

    /// <summary>
    /// Gets the number of keys currently stored.
    /// Useful for testing and monitoring.
    /// </summary>
    public int KeyCount => _keyStore.Count;

    /// <summary>
    /// Clears all stored keys and securely wipes private keys from memory.
    /// WARNING: This operation cannot be undone.
    /// </summary>
    public void ClearAll()
    {
        _logger.LogWarning("Clearing all stored keys from memory");

        foreach (var kvp in _keyStore)
        {
            kvp.Value.Clear();
        }

        _keyStore.Clear();

        _logger.LogInformation("Successfully cleared all keys from memory");
    }
}
