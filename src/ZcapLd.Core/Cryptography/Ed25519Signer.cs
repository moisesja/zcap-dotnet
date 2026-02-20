using NSec.Cryptography;
using SimpleBase;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Ed25519 signature implementation for ZCAP-LD using NSec cryptography library
/// Implements W3C Ed25519Signature2020 format with multibase encoding
/// </summary>
public static class Ed25519Signer
{
    private static readonly SignatureAlgorithm Ed25519 = SignatureAlgorithm.Ed25519;

    /// <summary>
    /// Signs data using Ed25519 algorithm
    /// </summary>
    /// <param name="data">The data to sign</param>
    /// <param name="privateKeyBytes">The Ed25519 private key (32 bytes seed)</param>
    /// <returns>The signature bytes (64 bytes)</returns>
    public static byte[] Sign(byte[] data, byte[] privateKeyBytes)
    {
        if (privateKeyBytes == null || privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBytes));
        }

        if (data == null || data.Length == 0)
        {
            throw new ArgumentException("Data cannot be null or empty", nameof(data));
        }

        try
        {
            // Import the key from seed bytes
            using var key = Key.Import(Ed25519, privateKeyBytes, KeyBlobFormat.RawPrivateKey);

            // Sign the data
            var signature = Ed25519.Sign(key, data);

            return signature;
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to sign data with Ed25519", ex);
        }
    }

    /// <summary>
    /// Verifies an Ed25519 signature
    /// </summary>
    /// <param name="data">The signed data</param>
    /// <param name="signature">The signature to verify (64 bytes)</param>
    /// <param name="publicKeyBytes">The Ed25519 public key (32 bytes)</param>
    /// <returns>True if signature is valid</returns>
    public static bool Verify(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        if (publicKeyBytes == null || publicKeyBytes.Length != 32)
        {
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKeyBytes));
        }

        if (signature == null || signature.Length != 64)
        {
            throw new ArgumentException("Ed25519 signature must be 64 bytes", nameof(signature));
        }

        if (data == null || data.Length == 0)
        {
            throw new ArgumentException("Data cannot be null or empty", nameof(data));
        }

        try
        {
            // Import the public key (PublicKey is not IDisposable, so no using statement needed)
            var publicKey = PublicKey.Import(Ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);

            // Verify the signature
            return Ed25519.Verify(publicKey, data, signature);
        }
        catch
        {
            // Verification failures return false, not exceptions
            return false;
        }
    }

    /// <summary>
    /// Canonicalizes JSON document for signing
    /// Uses deterministic JSON serialization (RFC 8785 style)
    /// </summary>
    /// <param name="document">The JSON document to canonicalize</param>
    /// <returns>Canonicalized bytes</returns>
    public static byte[] CanonicalizeDocument(object document)
    {
        return JsonCanonicalizer.Canonicalize(document);
    }

    /// <summary>
    /// Encodes signature as base58-btc multibase string (Ed25519Signature2020 format)
    /// Format: 'z' prefix + base58-btc encoded signature
    /// </summary>
    /// <param name="signature">The signature bytes</param>
    /// <returns>Multibase-encoded signature (e.g., "z...")</returns>
    public static string EncodeSignature(byte[] signature)
    {
        if (signature == null || signature.Length == 0)
        {
            throw new ArgumentException("Signature cannot be null or empty", nameof(signature));
        }

        try
        {
            // Encode as base58-btc (Bitcoin alphabet)
            var base58 = Base58.Bitcoin.Encode(signature);

            // Add multibase prefix 'z' for base58-btc
            return "z" + base58;
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to encode signature", ex);
        }
    }

    /// <summary>
    /// Decodes base58-btc multibase signature
    /// </summary>
    /// <param name="encodedSignature">The multibase-encoded signature</param>
    /// <returns>Signature bytes</returns>
    public static byte[] DecodeSignature(string encodedSignature)
    {
        if (string.IsNullOrEmpty(encodedSignature))
        {
            throw new ArgumentException("Encoded signature cannot be null or empty", nameof(encodedSignature));
        }

        try
        {
            // Check for multibase prefix 'z' (base58-btc)
            if (!encodedSignature.StartsWith("z"))
            {
                throw new ArgumentException("Signature must start with 'z' multibase prefix", nameof(encodedSignature));
            }

            // Remove multibase prefix and decode
            var base58String = encodedSignature.Substring(1);
            var signature = Base58.Bitcoin.Decode(base58String);

            return signature.ToArray();
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to decode signature", ex);
        }
    }

    /// <summary>
    /// Generates a new Ed25519 key pair
    /// </summary>
    /// <returns>Tuple of (privateKey, publicKey) as byte arrays</returns>
    public static (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        try
        {
            using var key = Key.Create(Ed25519, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });

            var privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
            var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to generate key pair", ex);
        }
    }

    /// <summary>
    /// Exports public key from private key
    /// </summary>
    /// <param name="privateKeyBytes">The private key (32 bytes)</param>
    /// <returns>Public key bytes (32 bytes)</returns>
    public static byte[] GetPublicKey(byte[] privateKeyBytes)
    {
        if (privateKeyBytes == null || privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBytes));
        }

        try
        {
            using var key = Key.Import(Ed25519, privateKeyBytes, KeyBlobFormat.RawPrivateKey);
            return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to extract public key", ex);
        }
    }

    /// <summary>
    /// Signs a JSON object and returns the signature
    /// </summary>
    /// <param name="jsonObject">The object to sign</param>
    /// <param name="privateKeyBytes">The private key</param>
    /// <returns>Multibase-encoded signature</returns>
    public static string SignJson(object jsonObject, byte[] privateKeyBytes)
    {
        var canonicalBytes = CanonicalizeDocument(jsonObject);
        var signatureBytes = Sign(canonicalBytes, privateKeyBytes);
        return EncodeSignature(signatureBytes);
    }

    /// <summary>
    /// Verifies a JSON object signature
    /// </summary>
    /// <param name="jsonObject">The object that was signed</param>
    /// <param name="encodedSignature">The multibase-encoded signature</param>
    /// <param name="publicKeyBytes">The public key</param>
    /// <returns>True if signature is valid</returns>
    public static bool VerifyJson(object jsonObject, string encodedSignature, byte[] publicKeyBytes)
    {
        var canonicalBytes = CanonicalizeDocument(jsonObject);
        var signatureBytes = DecodeSignature(encodedSignature);
        return Verify(canonicalBytes, signatureBytes, publicKeyBytes);
    }
}