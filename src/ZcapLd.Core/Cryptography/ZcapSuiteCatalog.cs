namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Fixed metadata for a ZCAP-LD signature suite: the proof <c>type</c> emitted, the W3C
/// verification-method key type it binds to (Issue #68), the suite's JSON-LD context URL and the
/// embedded resource that serves it (#159: the loader derives its suite entries from here, so a
/// catalog suite can never name a context the loader does not serve).
/// </summary>
internal sealed record ZcapSuiteInfo(string ProofType, string KeyType, string ContextUrl, string ContextResource);

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
    /// <summary>The ZCAP-LD v1 context every capability begins with.</summary>
    internal const string ZcapContextUrl = "https://w3id.org/zcap/v1";

    /// <summary>The published Ed25519Signature2020 suite context.</summary>
    internal const string Ed25519ContextUrl = "https://w3id.org/security/suites/ed25519-2020/v1";

    private static readonly ZcapSuiteInfo Ed25519 = new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        Ed25519ContextUrl,
        "ZcapLd.Core.Cryptography.Contexts.ed25519-2020-v1.jsonld");

    /// <summary>
    /// The context a P-256 capability carries (#159). No published context defines
    /// <c>EcdsaSecp256r1Signature2019</c> on its own: the <c>…/suites/ecdsa-2019/v1</c> URL of the 2022
    /// CG draft was never published (404), and <c>https://w3id.org/security/v2</c> defines it only
    /// together with the whole unprotected security vocabulary and its prefixes. This context is
    /// zcap-dotnet's own, served from an embedded resource and never fetched: the ed25519-2020/v1 shape
    /// (type-scoped, <c>@protected</c>) with the P-256 suite and key type names. It signs the same
    /// N-Quads as either published definition in a one-off probe (recorded in the #159 plan, not pinned
    /// by a test), so it could be swapped without changing a signed byte.
    /// </summary>
    internal const string P256ContextUrl = "urn:zcap-dotnet:ecdsa-secp256r1-2019-context:v1";

    // CROSS-STACK: P-256 is a zcap-dotnet-only profile. @digitalbazaar/zcap has no
    // EcdsaSecp256r1Signature2019 suite (it ships/tests Ed25519Signature2020 only), the proofValue
    // convention (base58-btc over IEEE P1363) is zcap-dotnet's, and the context above is local. Use
    // Ed25519Signature2020 for cross-stack interop. (Not a spec violation — ZCAP-LD is suite-neutral.)
    private static readonly ZcapSuiteInfo P256 = new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        P256ContextUrl,
        "ZcapLd.Core.Cryptography.Contexts.ecdsa-secp256r1-2019-v1.jsonld");

    private static readonly ZcapSuiteInfo[] All = [Ed25519, P256];

    /// <summary>Every supported suite, in catalog order.</summary>
    internal static IReadOnlyList<ZcapSuiteInfo> Suites => All;

    /// <summary>The context URL of every supported suite, in catalog order.</summary>
    internal static IEnumerable<string> ContextUrls => All.Select(s => s.ContextUrl);

    /// <summary>Only contexts defining the supported proof suites belong in a capability.</summary>
    internal static bool IsSupportedContext(string? contextUrl)
        => All.Any(s => string.Equals(s.ContextUrl, contextUrl, StringComparison.Ordinal));

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
