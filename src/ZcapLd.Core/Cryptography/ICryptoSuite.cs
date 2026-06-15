namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Metadata describing a single ZCAP-LD signature suite: its proof/key vocabulary, JSON-LD
/// security context, and canonicalization method. Stateless and thread-safe.
/// </summary>
/// <remarks>
/// As of Stage C (#108) the cryptography itself is delegated to DataProofs' legacy cryptosuites
/// (see <c>LegacyProofCrypto</c>); this interface only carries the metadata the signing/verification
/// services need — the proof <c>type</c> to emit, the resolver↔suite key-type binding (Issue #68),
/// the suite context URL, and which canonicalization the proof bytes use.
/// </remarks>
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
    /// The canonicalization method this suite's proof bytes use (e.g. "JCS", "RDFC-1.0").
    /// Defaults to "JCS". Drives which DataProofs legacy-suite variant verifies/creates the proof.
    /// </summary>
    string CanonicalizationMethod => "JCS";
}
