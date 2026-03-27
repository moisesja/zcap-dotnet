namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Bundles algorithm-specific cryptographic operations for a single signature suite.
/// Implementations are stateless and thread-safe.
///
/// Note: Multibase encoding/decoding lives in <see cref="MultibaseCodec"/>.
/// Canonicalization method is determined per suite via <see cref="CanonicalizationMethod"/>.
/// </summary>
public interface ICryptoSuite
{
    /// <summary>
    /// The proof type string used in ZCAP-LD proofs (e.g. "Ed25519Signature2020").
    /// </summary>
    string ProofType { get; }

    /// <summary>
    /// The key type string (e.g. "Ed25519VerificationKey2020").
    /// </summary>
    string KeyType { get; }

    /// <summary>
    /// The JSON-LD context URL for this signature suite
    /// (e.g. "https://w3id.org/security/suites/ed25519-2020/v1").
    /// </summary>
    string ContextUrl { get; }

    /// <summary>
    /// Signs data using a raw private key.
    /// </summary>
    byte[] Sign(byte[] data, byte[] privateKey);

    /// <summary>
    /// Verifies a signature against data and a public key.
    /// </summary>
    bool Verify(byte[] data, byte[] signature, byte[] publicKey);

    /// <summary>
    /// The canonicalization method this suite requires (e.g. "JCS", "RDFC-1.0").
    /// Defaults to "JCS" for backward compatibility.
    /// </summary>
    string CanonicalizationMethod => "JCS";
}
