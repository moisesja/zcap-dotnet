namespace ZcapLd.Core.Serialization;

/// <summary>
/// Service for encoding and decoding data using multibase format.
/// Multibase is a self-describing base encoding format used for cryptographic signatures.
/// </summary>
public interface IMultibaseService
{
    /// <summary>
    /// Encodes binary data to a multibase string.
    /// Default encoding is base58-btc (Bitcoin base58).
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <param name="encoding">The multibase encoding to use (default: base58-btc).</param>
    /// <returns>The multibase-encoded string.</returns>
    string Encode(byte[] data, MultibaseEncoding encoding = MultibaseEncoding.Base58Btc);

    /// <summary>
    /// Encodes binary data to a multibase string asynchronously.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <param name="encoding">The multibase encoding to use (default: base58-btc).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The multibase-encoded string.</returns>
    Task<string> EncodeAsync(
        byte[] data,
        MultibaseEncoding encoding = MultibaseEncoding.Base58Btc,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decodes a multibase string to binary data.
    /// Automatically detects the encoding from the prefix.
    /// </summary>
    /// <param name="encoded">The multibase-encoded string.</param>
    /// <returns>The decoded binary data.</returns>
    byte[] Decode(string encoded);

    /// <summary>
    /// Decodes a multibase string to binary data asynchronously.
    /// </summary>
    /// <param name="encoded">The multibase-encoded string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decoded binary data.</returns>
    Task<byte[]> DecodeAsync(string encoded, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to decode a multibase string.
    /// </summary>
    /// <param name="encoded">The multibase-encoded string.</param>
    /// <param name="data">The decoded binary data if successful.</param>
    /// <returns>True if decoding succeeded; otherwise, false.</returns>
    bool TryDecode(string encoded, out byte[] data);
}

/// <summary>
/// Supported multibase encoding formats.
/// </summary>
public enum MultibaseEncoding
{
    /// <summary>
    /// Base58 Bitcoin encoding (prefix: 'z')
    /// Most commonly used in W3C specs.
    /// </summary>
    Base58Btc,

    /// <summary>
    /// Base64 URL-safe encoding (prefix: 'u')
    /// </summary>
    Base64Url,

    /// <summary>
    /// Base64 standard encoding (prefix: 'm')
    /// </summary>
    Base64,

    /// <summary>
    /// Base32 encoding (prefix: 'b')
    /// </summary>
    Base32
}
