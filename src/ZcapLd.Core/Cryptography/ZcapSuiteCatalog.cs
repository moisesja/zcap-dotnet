namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Fixed metadata for a ZCAP-LD signature suite: the proof <c>type</c> emitted, the W3C
/// verification-method key type it binds to (Issue #68), and the suite's JSON-LD context URL.
/// </summary>
internal sealed record ZcapSuiteInfo(string ProofType, string KeyType, string ContextUrl);

/// <summary>
/// The closed set of signature suites zcap supports, with the W3C metadata DataProofs does not
/// carry (the suite key-type string and context URL). The cryptography itself is delegated to
/// DataProofs' legacy cryptosuites via <see cref="LegacyProofCrypto"/>.
/// </summary>
/// <remarks>
/// This is deliberately <b>not</b> a consumer-extensible registry. New curves/suites are added in
/// the foundation — a primitive in NetCrypto and a cryptosuite in DataProofs — and then wired here
/// (one entry) plus in <see cref="LegacyProofCrypto"/>; they are never registered through zcap's
/// public surface. See <c>docs/crypto-suite-extensibility-decision.md</c>.
/// </remarks>
internal static class ZcapSuiteCatalog
{
    private static readonly ZcapSuiteInfo Ed25519 = new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        "https://w3id.org/security/suites/ed25519-2020/v1");

    // CROSS-STACK: @digitalbazaar/zcap ships/tests Ed25519 only and serves no ecdsa-2019/v1 context,
    // so a P-256 (EcdsaSecp256r1Signature2019) capability will NOT verify against an out-of-the-box
    // @digitalbazaar/zcap deployment. Use Ed25519Signature2020 for guaranteed cross-stack interop.
    // (Not a spec violation — ZCAP-LD is suite-neutral.)
    private static readonly ZcapSuiteInfo P256 = new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        "https://w3id.org/security/suites/ecdsa-2019/v1");

    private static readonly ZcapSuiteInfo[] All = [Ed25519, P256];

    /// <summary>The suite whose key type equals the resolved verification-method key type, or <c>null</c>.</summary>
    public static ZcapSuiteInfo? GetByKeyType(string? keyType)
        => string.IsNullOrEmpty(keyType)
            ? null
            : Array.Find(All, s => string.Equals(s.KeyType, keyType, StringComparison.Ordinal));

    /// <summary>The suite whose proof type equals <paramref name="proofType"/>, or <c>null</c>.</summary>
    public static ZcapSuiteInfo? GetByProofType(string? proofType)
        => string.IsNullOrEmpty(proofType)
            ? null
            : Array.Find(All, s => string.Equals(s.ProofType, proofType, StringComparison.Ordinal));
}
