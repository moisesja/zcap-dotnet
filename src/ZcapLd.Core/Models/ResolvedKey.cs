namespace ZcapLd.Core.Models;

/// <summary>
/// Result of resolving a DID to its public key material.
/// Bundles the raw key bytes with the key type so the verification service
/// knows which crypto suite to use.
/// </summary>
/// <param name="PublicKeyBytes">The raw public key bytes</param>
/// <param name="KeyType">The key type string (e.g. "Ed25519VerificationKey2020")</param>
public record ResolvedKey(byte[] PublicKeyBytes, string KeyType);
