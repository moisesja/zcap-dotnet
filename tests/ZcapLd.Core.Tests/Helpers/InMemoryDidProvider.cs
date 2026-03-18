using System.Collections.Concurrent;
using NetDid.Core.Crypto;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Test-only IDidSigner + IDidResolver backed by in-memory Ed25519 keys.
/// NOT for production use — private keys are stored in plaintext memory.
/// </summary>
public class InMemoryDidProvider : IDidSigner, IDidResolver
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();
    private readonly DidKeyResolver _didKeyResolver = new();

    // --- IDidSigner ---

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Crypto.Sign(KeyType.Ed25519, privateKey, data);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    // --- IDidResolver ---

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        // Try registered keys first (derive public from stored private)
        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
        {
            var publicKey = KeyGen.FromPrivateKey(KeyType.Ed25519, privateKey).PublicKey;
            return Task.FromResult(new ResolvedKey(publicKey, "Ed25519VerificationKey2020"));
        }

        // Fall back to did:key resolver for public-key-in-DID resolution
        return _didKeyResolver.ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        if (did.StartsWith("did:key:"))
        {
            return _didKeyResolver.GetVerificationMethodAsync(did);
        }

        // For other DID methods, return with a standard key fragment
        return Task.FromResult($"{did}#key-1");
    }

    // --- Convenience methods ---

    public void RegisterKey(string did, byte[] privateKey)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes for Ed25519", nameof(privateKey));

        _keyStore[did] = privateKey;
    }

    public (byte[] PrivateKey, byte[] PublicKey) GenerateAndRegisterKeyPair(string did)
    {
        var kp = KeyGen.Generate(KeyType.Ed25519);
        RegisterKey(did, kp.PrivateKey);
        return (kp.PrivateKey, kp.PublicKey);
    }

    public string GenerateDidKey()
    {
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        RegisterKey(did, keyPair.PrivateKey);
        return did;
    }
}
