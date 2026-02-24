using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Resolves DID public keys and verification method URIs.
/// This is a read-only, secret-free interface — implementations never access private keys.
///
/// The library ships <see cref="DidKeyResolver"/> for the did:key method.
/// Implement this interface for other DID methods (did:web, did:ion, etc.)
/// and compose them via <see cref="CompositeDidResolver"/>.
/// </summary>
public interface IDidResolver
{
    /// <summary>
    /// Resolves a DID or verification method URI to its public key material.
    /// </summary>
    /// <param name="didOrVerificationMethod">A DID or verification method URI (e.g. did:key:z...#z...)</param>
    /// <returns>A <see cref="ResolvedKey"/> containing the raw public key bytes and key type</returns>
    Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod);

    /// <summary>
    /// Gets the verification method URI for a DID.
    /// This URI is embedded in proofs as the verificationMethod field.
    /// </summary>
    /// <param name="did">The DID to resolve</param>
    /// <returns>The full verification method URI (e.g. did:key:z...#z...)</returns>
    Task<string> GetVerificationMethodAsync(string did);
}
