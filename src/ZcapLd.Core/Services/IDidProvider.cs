using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Provides DID-based cryptographic operations including signing, key resolution,
/// and verification method resolution. Implementations can use in-memory keys,
/// HSMs, Azure Key Vault, Trinsic, or any DID method.
/// </summary>
public interface IDidProvider
{
    /// <summary>
    /// Signs raw bytes using the private key associated with a DID.
    /// The private key never leaves the provider, enabling HSM/vault implementations.
    /// </summary>
    /// <param name="did">The DID whose private key should sign the data</param>
    /// <param name="data">The raw bytes to sign</param>
    /// <returns>A <see cref="SignatureResult"/> containing the raw signature bytes and signature type</returns>
    Task<SignatureResult> SignAsync(string did, byte[] data);

    /// <summary>
    /// Resolves a DID or verification method URI to its public key bytes.
    /// Supports any DID method (did:key, did:web, did:ion, etc.).
    /// </summary>
    /// <param name="didOrVerificationMethod">A DID or verification method URI (e.g. did:key:z...#z...)</param>
    /// <returns>The public key bytes for signature verification</returns>
    Task<byte[]> ResolvePublicKeyAsync(string didOrVerificationMethod);

    /// <summary>
    /// Gets the verification method URI for a DID.
    /// This URI is embedded in proofs as the verificationMethod field.
    /// </summary>
    /// <param name="did">The DID to resolve</param>
    /// <returns>The full verification method URI (e.g. did:key:z...#z...)</returns>
    Task<string> GetVerificationMethodAsync(string did);
}
