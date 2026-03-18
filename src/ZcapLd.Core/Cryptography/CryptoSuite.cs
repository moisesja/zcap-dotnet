using NetDid.Core.Crypto;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Parameterized <see cref="ICryptoSuite"/> implementation that delegates all
/// cryptographic operations to NetDid's <see cref="DefaultCryptoProvider"/>.
/// Use the static factory methods (<see cref="Ed25519"/>, <see cref="P256"/>)
/// for built-in suites, or construct directly for custom key types.
/// </summary>
public class CryptoSuite : ICryptoSuite
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private readonly NetDid.Core.Crypto.KeyType _netDidKeyType;

    public CryptoSuite(string proofType, string keyType, string contextUrl,
        NetDid.Core.Crypto.KeyType netDidKeyType)
    {
        ProofType = proofType ?? throw new ArgumentNullException(nameof(proofType));
        KeyType = keyType ?? throw new ArgumentNullException(nameof(keyType));
        ContextUrl = contextUrl ?? throw new ArgumentNullException(nameof(contextUrl));
        _netDidKeyType = netDidKeyType;
    }

    public string ProofType { get; }
    public string KeyType { get; }
    public string ContextUrl { get; }

    public byte[] Sign(byte[] data, byte[] privateKey)
        => Crypto.Sign(_netDidKeyType, privateKey, data);

    public bool Verify(byte[] data, byte[] signature, byte[] publicKey)
        => Crypto.Verify(_netDidKeyType, publicKey, data, signature);

    /// <summary>
    /// Ed25519Signature2020 suite.
    /// </summary>
    public static CryptoSuite Ed25519() => new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        NetDid.Core.Crypto.KeyType.Ed25519);

    /// <summary>
    /// EcdsaSecp256r1Signature2019 (P-256) suite.
    /// </summary>
    public static CryptoSuite P256() => new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        "https://w3id.org/security/suites/ecdsa-2019/v1",
        NetDid.Core.Crypto.KeyType.P256);
}
