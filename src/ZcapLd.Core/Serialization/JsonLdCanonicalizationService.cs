using System.Text;
using System.Text.Json;
using JsonLD.Core;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Serialization;

/// <summary>
/// Default implementation of <see cref="IJsonLdCanonicalizationService"/>.
/// Uses the JsonLD.Core library for RDF Dataset Canonicalization (RDFC-1.0).
/// Thread-safe.
/// </summary>
public class JsonLdCanonicalizationService : IJsonLdCanonicalizationService
{
    private readonly ILogger<JsonLdCanonicalizationService> _logger;
    private readonly IZcapSerializationService _serializationService;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonLdCanonicalizationService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="serializationService">The serialization service for object conversion.</param>
    public JsonLdCanonicalizationService(
        ILogger<JsonLdCanonicalizationService> logger,
        IZcapSerializationService serializationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _serializationService = serializationService ?? throw new ArgumentNullException(nameof(serializationService));
    }

    /// <inheritdoc/>
    public async Task<string> CanonicalizeAsync(string jsonLd, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(jsonLd))
        {
            throw new ArgumentNullException(nameof(jsonLd), "JSON-LD document cannot be null or empty.");
        }

        try
        {
            _logger.LogDebug("Canonicalizing JSON-LD document (length: {Length})", jsonLd.Length);

            // Parse the JSON-LD using Newtonsoft.Json (required by JsonLD.Core)
            var jsonObject = JToken.Parse(jsonLd);

            // Perform RDF Dataset Canonicalization
            var options = new JsonLdOptions();
            var normalized = await Task.Run(
                () => JsonLdProcessor.Normalize(jsonObject, options),
                cancellationToken).ConfigureAwait(false);

            _logger.LogDebug("Canonicalization completed. Output length: {Length}", normalized.Length);

            return normalized;
        }
        catch (Exception ex) when (ex is not CanonicalizationException)
        {
            _logger.LogError(ex, "Failed to canonicalize JSON-LD document");
            throw new CanonicalizationException("Failed to canonicalize JSON-LD document.", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> CanonicalizeToBytesAsync(string jsonLd, CancellationToken cancellationToken = default)
    {
        var canonical = await CanonicalizeAsync(jsonLd, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetBytes(canonical);
    }

    /// <inheritdoc/>
    public async Task<string> CanonicalizeObjectAsync<T>(T obj, CancellationToken cancellationToken = default)
    {
        if (obj == null)
        {
            throw new ArgumentNullException(nameof(obj), "Object to canonicalize cannot be null.");
        }

        try
        {
            _logger.LogDebug("Canonicalizing object of type {Type}", typeof(T).Name);

            // Serialize object to JSON-LD
            var jsonLd = _serializationService.Serialize(obj);

            // Canonicalize the JSON-LD
            return await CanonicalizeAsync(jsonLd, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not CanonicalizationException)
        {
            _logger.LogError(ex, "Failed to canonicalize object of type {Type}", typeof(T).Name);
            throw new CanonicalizationException($"Failed to canonicalize object of type {typeof(T).Name}.", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> CanonicalizeObjectToBytesAsync<T>(T obj, CancellationToken cancellationToken = default)
    {
        var canonical = await CanonicalizeObjectAsync(obj, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetBytes(canonical);
    }
}
