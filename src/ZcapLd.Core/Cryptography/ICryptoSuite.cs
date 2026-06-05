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
    /// <para>
    /// Contract: verification binds the suite to the resolved key by comparing this value against
    /// <see cref="Models.ResolvedKey.KeyType"/> with an exact ordinal match (Issue #68). An
    /// <see cref="Services.IDidResolver"/> paired with this suite MUST emit this exact string, not a
    /// synonym (<c>Multikey</c>, <c>JsonWebKey2020</c>, <c>Ed25519VerificationKey2018</c>); otherwise a
    /// legitimately matching key is rejected. The in-library resolver/suite pairs already align.
    /// </para>
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
