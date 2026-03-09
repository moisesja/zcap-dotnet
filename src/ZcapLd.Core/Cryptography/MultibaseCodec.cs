using NetCid;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Algorithm-agnostic utilities for multibase encoding/decoding and document canonicalization.
/// Delegates multibase operations to NetCid.
/// </summary>
public static class MultibaseCodec
{
    /// <summary>
    /// Canonicalizes a JSON document for signing using deterministic serialization (RFC 8785 style).
    /// </summary>
    /// <param name="document">The JSON document to canonicalize</param>
    /// <returns>Canonicalized bytes</returns>
    public static byte[] CanonicalizeDocument(object document)
    {
        return JsonCanonicalizer.Canonicalize(document);
    }

    /// <summary>
    /// Encodes raw bytes as a base58-btc multibase string.
    /// Format: 'z' prefix + base58-btc encoded data.
    /// </summary>
    /// <param name="data">The bytes to encode</param>
    /// <returns>Multibase-encoded string (e.g., "z...")</returns>
    public static string Encode(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            throw new ArgumentException("Data cannot be null or empty", nameof(data));
        }

        try
        {
            return Multibase.Encode(data, MultibaseEncoding.Base58Btc);
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to encode data", ex);
        }
    }

    /// <summary>
    /// Decodes a base58-btc multibase string back to raw bytes.
    /// </summary>
    /// <param name="encoded">The multibase-encoded string (must start with 'z')</param>
    /// <returns>Decoded bytes</returns>
    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            throw new ArgumentException("Encoded string cannot be null or empty", nameof(encoded));
        }

        try
        {
            if (!encoded.StartsWith("z"))
            {
                throw new Exceptions.CryptographicException(
                    "Multibase string must start with 'z' prefix");
            }

            return Multibase.Decode(encoded);
        }
        catch (Exceptions.CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to decode multibase string", ex);
        }
    }
}
