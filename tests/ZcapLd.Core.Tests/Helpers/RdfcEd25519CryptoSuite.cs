using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Ed25519 suite configured for RDFC-1.0 canonicalization.
/// Test helper only — wraps the standard Ed25519 CryptoSuite.
/// </summary>
public class RdfcEd25519CryptoSuite : ICryptoSuite
{
    private readonly ICryptoSuite _inner = CryptoSuite.Ed25519();

    public string ProofType => _inner.ProofType;
    public string KeyType => _inner.KeyType;
    public string ContextUrl => _inner.ContextUrl;
    public string CanonicalizationMethod => "RDFC-1.0";
}
