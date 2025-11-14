namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Represents a cryptographic key pair for signing and verification.
/// </summary>
public sealed class KeyPair
{
    /// <summary>
    /// Gets the public key bytes.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Gets the private key bytes (sensitive data).
    /// </summary>
    public byte[] PrivateKey { get; }

    /// <summary>
    /// Gets the key identifier (typically a DID with key fragment).
    /// Example: "did:example:alice#key-1"
    /// </summary>
    public string KeyId { get; }

    /// <summary>
    /// Gets the verification method URI for this key.
    /// This is used in proofs to identify the key.
    /// </summary>
    public string VerificationMethod { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class.
    /// </summary>
    /// <param name="publicKey">The public key bytes.</param>
    /// <param name="privateKey">The private key bytes.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="verificationMethod">The verification method URI.</param>
    public KeyPair(byte[] publicKey, byte[] privateKey, string keyId, string? verificationMethod = null)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
        VerificationMethod = verificationMethod ?? keyId;
    }

    /// <summary>
    /// Clears the private key from memory (security measure).
    /// Should be called when the key pair is no longer needed.
    /// </summary>
    public void Clear()
    {
        Array.Clear(PrivateKey, 0, PrivateKey.Length);
    }
}

/// <summary>
/// Represents a public key for signature verification.
/// </summary>
public sealed class PublicKey
{
    /// <summary>
    /// Gets the public key bytes.
    /// </summary>
    public byte[] KeyBytes { get; }

    /// <summary>
    /// Gets the key identifier.
    /// </summary>
    public string KeyId { get; }

    /// <summary>
    /// Gets the verification method URI for this key.
    /// </summary>
    public string VerificationMethod { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKey"/> class.
    /// </summary>
    /// <param name="keyBytes">The public key bytes.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="verificationMethod">The verification method URI.</param>
    public PublicKey(byte[] keyBytes, string keyId, string? verificationMethod = null)
    {
        KeyBytes = keyBytes ?? throw new ArgumentNullException(nameof(keyBytes));
        KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
        VerificationMethod = verificationMethod ?? keyId;
    }
}
