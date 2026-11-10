using System.Collections.Concurrent;
using NetCrypto;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.AotSample;

/// <summary>
/// A sample-only <see cref="IDidSigner"/>: Ed25519 private keys held in plaintext memory behind real
/// <c>did:key:z6Mk…</c> identifiers.
/// <para>
/// <b>NOT FOR PRODUCTION.</b> A production signer wraps an HSM, a cloud KMS or a key vault and never
/// exposes the private key; <see cref="IDidSigner.SignAsync"/> exists so the library never needs to.
/// </para>
/// <para>
/// This class only signs. Resolution goes through <see cref="CompositeDidResolver"/> routing
/// <c>did:key:</c> to the library's <see cref="DidKeyResolver"/>: a <c>did:key</c> embeds its public
/// key, so a verifier checks these signatures, and authorizes the key for its controller, without
/// ever seeing this keyring.
/// </para>
/// </summary>
public sealed class SampleKeyring : IDidSigner
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _privateKeys = new(StringComparer.Ordinal);

    /// <summary>Generates a fresh Ed25519 key, keeps its private half, and returns its <c>did:key</c>.</summary>
    public string GenerateDidKey()
    {
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        _privateKeys[did] = keyPair.PrivateKey;
        return did;
    }

    /// <inheritdoc />
    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        ArgumentException.ThrowIfNullOrEmpty(did);
        ArgumentNullException.ThrowIfNull(data);

        if (!_privateKeys.TryGetValue(did, out var privateKey))
        {
            throw new InvalidOperationException($"This keyring holds no key for {did}.");
        }

        return Task.FromResult(new SignatureResult(Crypto.Sign(KeyType.Ed25519, privateKey, data), "Ed25519Signature2020"));
    }
}
