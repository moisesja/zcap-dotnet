namespace ZcapLd.Core.Models;

/// <summary>
/// Result of resolving a DID to its public key material.
/// Bundles the raw key bytes with the key type so the verification service
/// knows which crypto suite to use.
/// </summary>
/// <param name="PublicKeyBytes">The raw public key bytes</param>
/// <param name="KeyType">
/// The key type string (e.g. "Ed25519VerificationKey2020"). Contract: verification binds the resolved
/// key to the proof-selected suite by comparing this against <see cref="Cryptography.ICryptoSuite.KeyType"/>
/// with an exact ordinal match (Issue #68), so a resolver MUST emit the exact string its suite uses —
/// not a synonym (<c>Multikey</c>, <c>JsonWebKey2020</c>, <c>Ed25519VerificationKey2018</c>), or a
/// legitimately matching key is rejected.
/// </param>
public record ResolvedKey(byte[] PublicKeyBytes, string KeyType);
