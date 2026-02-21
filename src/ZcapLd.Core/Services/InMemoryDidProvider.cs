using System.Collections.Concurrent;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Default in-memory IDidProvider using Ed25519 keys.
/// Suitable for development, testing, and simple deployments.
/// For production, implement IDidProvider backed by HSM, Key Vault, or Trinsic.
///
/// SECURITY WARNING: This implementation stores private keys in plaintext memory.
/// For production use, integrate with a secure key management system and implement
/// key zeroization on disposal.
/// </summary>
public class InMemoryDidProvider : IDidProvider
{
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();

    /// <summary>
    /// Signs raw bytes using the Ed25519 private key associated with a DID.
    /// </summary>
    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Ed25519Signer.Sign(data, privateKey);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    /// <summary>
    /// Resolves a DID or verification method URI to its public key bytes.
    /// Supports registered keys and did:key: format with multibase/multicodec decoding.
    /// SECURITY: Non-recursive implementation with depth limit to prevent DoS.
    /// </summary>
    public Task<byte[]> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        const int maxResolutionDepth = 3;
        int depth = 0;
        string currentDid = didOrVerificationMethod;

        while (depth < maxResolutionDepth)
        {
            // Try to resolve via registered keys first (depth 0 only)
            if (depth == 0)
            {
                var baseDid = currentDid.Split('#')[0];
                if (_keyStore.TryGetValue(baseDid, out var privateKey))
                {
                    return Task.FromResult(Ed25519Signer.GetPublicKey(privateKey));
                }
            }

            // For did:key format, extract the public key directly
            if (currentDid.StartsWith("did:key:"))
            {
                var keyPart = currentDid.Replace("did:key:", "").Split('#')[0];

                if (!keyPart.StartsWith("z"))
                {
                    throw new CapabilityValidationException(
                        $"Invalid did:key format (must start with 'z'): {currentDid}");
                }

                try
                {
                    var decoded = Ed25519Signer.DecodeSignature(keyPart);

                    // For Ed25519, the decoded value includes a multicodec prefix
                    // 0xed01 for Ed25519 public key, so we skip the first 2 bytes
                    if (decoded.Length >= 34 && decoded[0] == 0xed && decoded[1] == 0x01)
                    {
                        return Task.FromResult(decoded.Skip(2).ToArray());
                    }

                    // If it's exactly 32 bytes, it's already the raw public key
                    if (decoded.Length == 32)
                    {
                        return Task.FromResult(decoded);
                    }

                    throw new CapabilityValidationException(
                        $"Invalid did:key decoded length: {decoded.Length} bytes for {currentDid}");
                }
                catch (CapabilityValidationException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw new CapabilityValidationException(
                        $"Failed to decode did:key public key: {currentDid}", ex);
                }
            }

            // For other DID methods at depth 0, try verification method resolution
            if (depth == 0)
            {
                var verificationMethod = GetVerificationMethodSync(currentDid);

                // If verification method is the same as current DID, we're in a loop
                if (verificationMethod == currentDid)
                {
                    throw new CapabilityValidationException(
                        $"DID resolution loop detected for: {currentDid}");
                }

                currentDid = verificationMethod;
                depth++;
                continue;
            }

            // If we get here at depth > 0, we have an unsupported DID method
            throw new CapabilityValidationException(
                $"Unsupported DID method or invalid DID format: {currentDid}");
        }

        throw new CapabilityValidationException(
            $"DID resolution exceeded maximum depth ({maxResolutionDepth}). " +
            $"Possible circular reference starting from: {didOrVerificationMethod}");
    }

    /// <summary>
    /// Gets the verification method URI for a DID.
    /// For did:key, returns did#keyId. For others, returns did#key-1.
    /// </summary>
    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        return Task.FromResult(GetVerificationMethodSync(did));
    }

    // --- Convenience methods (not on the interface) ---

    /// <summary>
    /// Registers a signing key for a DID.
    /// SECURITY WARNING: Keys are stored in plaintext memory.
    /// </summary>
    /// <param name="did">The DID to register the key for</param>
    /// <param name="privateKey">The Ed25519 private key (32 bytes)</param>
    public void RegisterKey(string did, byte[] privateKey)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes for Ed25519", nameof(privateKey));

        _keyStore[did] = privateKey;
    }

    /// <summary>
    /// Generates a new Ed25519 key pair and registers it for a DID.
    /// </summary>
    /// <param name="did">The DID to register the key pair for</param>
    /// <returns>Tuple of (privateKey, publicKey)</returns>
    public (byte[] PrivateKey, byte[] PublicKey) GenerateAndRegisterKeyPair(string did)
    {
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        RegisterKey(did, privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Generates a proper did:key DID from a freshly generated Ed25519 keypair,
    /// registers the private key, and returns the DID string.
    /// The DID is constructed using multicodec (0xed01) prefix and multibase (base58-btc) encoding.
    /// </summary>
    /// <returns>The generated did:key string</returns>
    public string GenerateDidKey()
    {
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();

        // Multicodec prefix for Ed25519 public keys: 0xed01
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        Buffer.BlockCopy(publicKey, 0, prefixed, 2, 32);

        var multibaseKey = Ed25519Signer.EncodeSignature(prefixed);
        var did = $"did:key:{multibaseKey}";

        RegisterKey(did, privateKey);
        return did;
    }

    private string GetVerificationMethodSync(string did)
    {
        // For did:key, the verification method is typically the DID itself with a fragment
        // Format: did:key:{multibase-encoded-public-key}#{multibase-encoded-public-key}
        if (did.StartsWith("did:key:"))
        {
            var keyId = did.Substring("did:key:".Length);
            return $"{did}#{keyId}";
        }

        // For other DID methods, return with a standard key fragment
        return $"{did}#key-1";
    }
}
