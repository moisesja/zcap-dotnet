using NetCrypto;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Parameterized <see cref="ICryptoSuite"/> implementation that delegates all
/// cryptographic operations to NetCrypto's <see cref="DefaultCryptoProvider"/>.
/// Use the static factory methods (<see cref="Ed25519"/>, <see cref="P256"/>)
/// for built-in suites, or construct directly for custom key types.
/// </summary>
public class CryptoSuite : ICryptoSuite
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private readonly NetCrypto.KeyType _keyType;

    public CryptoSuite(string proofType, string keyType, string contextUrl,
        NetCrypto.KeyType cryptoKeyType)
    {
        ProofType = proofType ?? throw new ArgumentNullException(nameof(proofType));
        KeyType = keyType ?? throw new ArgumentNullException(nameof(keyType));
        ContextUrl = contextUrl ?? throw new ArgumentNullException(nameof(contextUrl));
        _keyType = cryptoKeyType;
    }

    public string ProofType { get; }
    public string KeyType { get; }
    public string ContextUrl { get; }

    // W3C Data Integrity suites (ecdsa-2019 / EcdsaSecp256r1Signature2019) and JOSE put the raw
    // ECDSA signature on the wire as IEEE P1363 fixed-width r‖s — NOT ASN.1 DER. NetCrypto
    // defaults its ECDSA Sign/Verify overloads to DER, so we explicitly request P1363 via the
    // format-aware overloads. Non-ECDSA key types (Ed25519, secp256k1, BLS) ignore the format and
    // return their algorithm-native wire form, so passing P1363 unconditionally is safe.
    public byte[] Sign(byte[] data, byte[] privateKey)
        => Crypto.Sign(_keyType, privateKey, data, EcdsaSignatureFormat.IeeeP1363);

    public bool Verify(byte[] data, byte[] signature, byte[] publicKey)
        => Crypto.Verify(_keyType, publicKey, data, signature, EcdsaSignatureFormat.IeeeP1363);

    /// <summary>
    /// Ed25519Signature2020 suite.
    /// </summary>
    public static CryptoSuite Ed25519() => new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        NetCrypto.KeyType.Ed25519);

    /// <summary>
    /// EcdsaSecp256r1Signature2019 (P-256) suite.
    /// </summary>
    public static CryptoSuite P256() => new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        "https://w3id.org/security/suites/ecdsa-2019/v1",
        NetCrypto.KeyType.P256);
}
