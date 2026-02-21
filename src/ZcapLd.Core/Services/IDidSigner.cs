using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Signs data using the private key associated with a DID.
/// The private key never leaves the provider, enabling HSM, Key Vault,
/// and cloud KMS implementations.
///
/// No default implementation ships in the core library — consumers must
/// provide their own backed by a secure key management system.
/// </summary>
public interface IDidSigner
{
    /// <summary>
    /// Signs raw bytes using the private key associated with a DID.
    /// </summary>
    /// <param name="did">The DID whose private key should sign the data</param>
    /// <param name="data">The raw bytes to sign</param>
    /// <returns>A <see cref="SignatureResult"/> containing the raw signature bytes and signature type</returns>
    Task<SignatureResult> SignAsync(string did, byte[] data);
}
