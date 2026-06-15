namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Parameterized <see cref="ICryptoSuite"/> metadata record. Use the static factory methods
/// (<see cref="Ed25519"/>, <see cref="P256"/>) for the built-in suites, or construct directly for
/// custom proof/key vocabularies. The cryptography is delegated to DataProofs' legacy cryptosuites
/// (see <c>LegacyProofCrypto</c>); this type only describes the suite.
/// </summary>
public class CryptoSuite : ICryptoSuite
{
    public CryptoSuite(string proofType, string keyType, string contextUrl)
    {
        ProofType = proofType ?? throw new ArgumentNullException(nameof(proofType));
        KeyType = keyType ?? throw new ArgumentNullException(nameof(keyType));
        ContextUrl = contextUrl ?? throw new ArgumentNullException(nameof(contextUrl));
    }

    public string ProofType { get; }
    public string KeyType { get; }
    public string ContextUrl { get; }

    /// <summary>
    /// Ed25519Signature2020 suite.
    /// </summary>
    public static CryptoSuite Ed25519() => new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        "https://w3id.org/security/suites/ed25519-2020/v1");

    /// <summary>
    /// EcdsaSecp256r1Signature2019 (P-256) suite.
    /// </summary>
    public static CryptoSuite P256() => new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        "https://w3id.org/security/suites/ecdsa-2019/v1");
}
