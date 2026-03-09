namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Ed25519 crypto suite implementation wrapping the existing <see cref="Ed25519Signer"/> static methods.
/// </summary>
public class Ed25519CryptoSuite : ICryptoSuite
{
    public string ProofType => "Ed25519Signature2020";

    public string KeyType => "Ed25519VerificationKey2020";

    public string ContextUrl => "https://w3id.org/security/suites/ed25519-2020/v1";

    public byte[] Sign(byte[] data, byte[] privateKey)
        => Ed25519Signer.Sign(data, privateKey);

    public bool Verify(byte[] data, byte[] signature, byte[] publicKey)
        => Ed25519Signer.Verify(data, signature, publicKey);
}
