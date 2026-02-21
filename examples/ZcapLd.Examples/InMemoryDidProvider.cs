using System.Collections.Concurrent;
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
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();
    private readonly DidKeyResolver _didKeyResolver = new();

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Ed25519Signer.Sign(data, privateKey);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
            return Task.FromResult(new ResolvedKey(Ed25519Signer.GetPublicKey(privateKey), "Ed25519VerificationKey2020"));

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
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();
        _keyStore[did] = privateKey;
    }
}
