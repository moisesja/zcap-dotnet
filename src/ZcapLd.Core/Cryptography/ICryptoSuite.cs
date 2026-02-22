namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Bundles algorithm-specific cryptographic operations for a single signature suite.
/// Implementations are stateless and thread-safe.
///
/// Note: Canonicalization (RFC 8785) and multibase encoding/decoding are NOT
/// algorithm-specific — they live in <see cref="MultibaseCodec"/>.
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
    /// The multicodec prefix bytes that identify this key type in did:key encoding.
    /// For Ed25519: [0xed, 0x01]. For P-256: [0x80, 0x24].
    /// </summary>
    byte[] MulticodecPrefix { get; }

    /// <summary>
    /// The expected public key length in bytes (e.g. 32 for Ed25519, 33 for compressed P-256).
    /// </summary>
    int PublicKeyLength { get; }

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
}
