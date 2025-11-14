using Microsoft.Extensions.Logging;
using Multiformats.Base;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Serialization;

/// <summary>
/// Default implementation of <see cref="IMultibaseService"/> using Multiformats.Base library.
/// Provides encoding and decoding of binary data using multibase format.
/// Thread-safe.
/// </summary>
public class MultibaseService : IMultibaseService
{
    private readonly ILogger<MultibaseService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="MultibaseService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    public MultibaseService(ILogger<MultibaseService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public string Encode(byte[] data, MultibaseEncoding encoding = MultibaseEncoding.Base58Btc)
    {
        if (data == null || data.Length == 0)
        {
            throw new ArgumentNullException(nameof(data), "Data to encode cannot be null or empty.");
        }

        try
        {
            var multibaseEncoding = GetMultibaseEncoding(encoding);
            var result = Multibase.Encode(multibaseEncoding, data);

            _logger.LogDebug(
                "Encoded {ByteCount} bytes using {Encoding} to multibase string (length: {Length})",
                data.Length,
                encoding,
                result.Length);

            return result;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to encode data using {Encoding}", encoding);
            throw new SerializationException($"Failed to encode data using {encoding}.", "multibase", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<string> EncodeAsync(
        byte[] data,
        MultibaseEncoding encoding = MultibaseEncoding.Base58Btc,
        CancellationToken cancellationToken = default)
    {
        // Encoding is CPU-bound, so run on thread pool
        return await Task.Run(() => Encode(data, encoding), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public byte[] Decode(string encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
        {
            throw new ArgumentNullException(nameof(encoded), "Encoded string cannot be null or empty.");
        }

        try
        {
            var result = Multibase.Decode(encoded);

            _logger.LogDebug(
                "Decoded multibase string (length: {Length}) to {ByteCount} bytes",
                encoded.Length,
                result.Length);

            return result;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to decode multibase string: {Encoded}", encoded);
            throw new SerializationException($"Failed to decode multibase string.", "multibase", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> DecodeAsync(string encoded, CancellationToken cancellationToken = default)
    {
        // Decoding is CPU-bound, so run on thread pool
        return await Task.Run(() => Decode(encoded), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public bool TryDecode(string encoded, out byte[] data)
    {
        data = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(encoded))
        {
            return false;
        }

        try
        {
            data = Multibase.Decode(encoded);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to decode multibase string: {Encoded}", encoded);
            return false;
        }
    }

    /// <summary>
    /// Maps our encoding enum to the Multiformats.Base encoding.
    /// </summary>
    private static MultibaseEncoding GetMultibaseEncoding(MultibaseEncoding encoding)
    {
        return encoding switch
        {
            MultibaseEncoding.Base58Btc => Multiformats.Base.MultibaseEncoding.Base58Btc,
            MultibaseEncoding.Base64Url => Multiformats.Base.MultibaseEncoding.Base64Url,
            MultibaseEncoding.Base64 => Multiformats.Base.MultibaseEncoding.Base64,
            MultibaseEncoding.Base32 => Multiformats.Base.MultibaseEncoding.Base32,
            _ => throw new ArgumentException($"Unsupported encoding: {encoding}", nameof(encoding))
        };
    }
}
