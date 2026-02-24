using SimpleBase;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Algorithm-agnostic utilities for multibase encoding/decoding and document canonicalization.
/// These operations are shared across all crypto suites — they are NOT signature-algorithm-specific.
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
            var base58 = Base58.Bitcoin.Encode(data);
            return "z" + base58;
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
                throw new ArgumentException("Multibase string must start with 'z' prefix", nameof(encoded));
            }

            var base58String = encoded.Substring(1);
            var decoded = Base58.Bitcoin.Decode(base58String);
            return decoded.ToArray();
        }
        catch (Exception ex)
        {
            throw new Exceptions.CryptographicException("Failed to decode multibase string", ex);
        }
    }
}
