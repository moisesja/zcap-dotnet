using ZcapLd.Core.Cryptography;

namespace ZcapLd.Examples;

/// <summary>
/// Ed25519 suite configured for RDFC-1.0 (RDF Dataset Canonicalization) instead of JCS.
/// Wraps the standard Ed25519 CryptoSuite but overrides the canonicalization method
/// so the signing/verification pipeline uses N-Quads canonicalization per W3C Data Integrity.
///
/// In production, you would create similar wrappers for any suite that should use RDFC-1.0.
/// </summary>
public class RdfcEd25519CryptoSuite : ICryptoSuite
{
    private readonly ICryptoSuite _inner = CryptoSuite.Ed25519();

    public string ProofType => _inner.ProofType;
    public string KeyType => _inner.KeyType;
    public string ContextUrl => _inner.ContextUrl;
    public string CanonicalizationMethod => "RDFC-1.0";
}
