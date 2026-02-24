namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Registry for looking up crypto suites by proof type or multicodec prefix.
/// Typically registered as a singleton in DI.
/// </summary>
public interface ICryptoSuiteProvider
{
    /// <summary>
    /// Looks up a crypto suite by its proof type string (e.g. "Ed25519Signature2020").
    /// Used during verification to select the correct algorithm for a proof.
    /// </summary>
    ICryptoSuite? GetByProofType(string proofType);

    /// <summary>
    /// Looks up a crypto suite by the multicodec prefix found in a did:key.
    /// The prefix parameter is the raw decoded bytes (first N bytes after multibase decoding).
    /// </summary>
    ICryptoSuite? GetByMulticodecPrefix(ReadOnlySpan<byte> prefix);

    /// <summary>
    /// Looks up a crypto suite by its key type string (e.g. "Ed25519VerificationKey2020").
    /// Used to resolve the correct suite for a DID's key material.
    /// </summary>
    ICryptoSuite? GetByKeyType(string keyType);
}
