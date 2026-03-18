using System.Collections.Concurrent;
using NetDid.Core.Crypto;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Examples;

/// <summary>
/// Example IDidSigner + IDidResolver for demonstration purposes.
/// Stores Ed25519 private keys in plaintext memory — NOT for production use.
///
/// In production, implement IDidSigner backed by your secure key management system
/// (HSM, Azure Key Vault, AWS KMS, Trinsic, etc.) and IDidResolver backed by a
/// universal resolver or DID method-specific resolver.
/// </summary>
public class InMemoryDidProvider : IDidSigner, IDidResolver
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();
    private readonly DidKeyResolver _didKeyResolver = new();

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Crypto.Sign(KeyType.Ed25519, privateKey, data);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
        {
            var publicKey = KeyGen.FromPrivateKey(KeyType.Ed25519, privateKey).PublicKey;
            return Task.FromResult(new ResolvedKey(publicKey, "Ed25519VerificationKey2020"));
        }

        return _didKeyResolver.ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (did.StartsWith("did:key:"))
            return _didKeyResolver.GetVerificationMethodAsync(did);

        return Task.FromResult($"{did}#key-1");
    }

    public void GenerateAndRegisterKeyPair(string did)
    {
        // Notice that this is unsecured. Make sure to use a secure key management solution in production.
        var kp = KeyGen.Generate(KeyType.Ed25519);
        _keyStore[did] = kp.PrivateKey;
    }
}
