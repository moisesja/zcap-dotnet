using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Serialization.Converters;

namespace ZcapLd.Core.Serialization;

/// <summary>
/// Default implementation of <see cref="IZcapSerializationService"/>.
/// Provides JSON-LD serialization and deserialization for ZCAP-LD objects.
/// Thread-safe.
/// </summary>
public class ZcapSerializationService : IZcapSerializationService
{
    private readonly ILogger<ZcapSerializationService> _logger;
    private readonly JsonSerializerOptions _defaultOptions;
    private readonly JsonSerializerOptions _indentedOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="ZcapSerializationService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    public ZcapSerializationService(ILogger<ZcapSerializationService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Configure default JSON options for ZCAP-LD
        _defaultOptions = CreateJsonOptions(indented: false);
        _indentedOptions = CreateJsonOptions(indented: true);
    }

    /// <inheritdoc/>
    public string Serialize<T>(T obj, bool indented = false)
    {
        if (obj == null)
        {
            throw new ArgumentNullException(nameof(obj), "Object to serialize cannot be null.");
        }

        try
        {
            var options = indented ? _indentedOptions : _defaultOptions;
            var json = JsonSerializer.Serialize(obj, options);

            _logger.LogDebug(
                "Serialized object of type {Type} to JSON (length: {Length}, indented: {Indented})",
                typeof(T).Name,
                json.Length,
                indented);

            return json;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to serialize object of type {Type}", typeof(T).Name);
            throw new SerializationException($"Failed to serialize object of type {typeof(T).Name}.", typeof(T).Name, ex);
        }
    }

    /// <inheritdoc/>
    public async Task<string> SerializeAsync<T>(T obj, bool indented = false, CancellationToken cancellationToken = default)
    {
        if (obj == null)
        {
            throw new ArgumentNullException(nameof(obj), "Object to serialize cannot be null.");
        }

        try
        {
            var options = indented ? _indentedOptions : _defaultOptions;

            using var stream = new MemoryStream();
            await JsonSerializer.SerializeAsync(stream, obj, options, cancellationToken).ConfigureAwait(false);

            var json = Encoding.UTF8.GetString(stream.ToArray());

            _logger.LogDebug(
                "Serialized object of type {Type} to JSON asynchronously (length: {Length}, indented: {Indented})",
                typeof(T).Name,
                json.Length,
                indented);

            return json;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to serialize object of type {Type} asynchronously", typeof(T).Name);
            throw new SerializationException($"Failed to serialize object of type {typeof(T).Name}.", typeof(T).Name, ex);
        }
    }

    /// <inheritdoc/>
    public T Deserialize<T>(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ArgumentNullException(nameof(json), "JSON string cannot be null or empty.");
        }

        try
        {
            var obj = JsonSerializer.Deserialize<T>(json, _defaultOptions);

            if (obj == null)
            {
                throw new SerializationException(
                    $"Deserialization resulted in null for type {typeof(T).Name}.",
                    typeof(T).Name);
            }

            _logger.LogDebug(
                "Deserialized JSON (length: {Length}) to object of type {Type}",
                json.Length,
                typeof(T).Name);

            return obj;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to deserialize JSON to type {Type}", typeof(T).Name);
            throw new SerializationException($"Failed to deserialize JSON to type {typeof(T).Name}.", typeof(T).Name, ex);
        }
    }

    /// <inheritdoc/>
    public async Task<T> DeserializeAsync<T>(string json, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ArgumentNullException(nameof(json), "JSON string cannot be null or empty.");
        }

        try
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
            var obj = await JsonSerializer.DeserializeAsync<T>(stream, _defaultOptions, cancellationToken)
                .ConfigureAwait(false);

            if (obj == null)
            {
                throw new SerializationException(
                    $"Deserialization resulted in null for type {typeof(T).Name}.",
                    typeof(T).Name);
            }

            _logger.LogDebug(
                "Deserialized JSON (length: {Length}) to object of type {Type} asynchronously",
                json.Length,
                typeof(T).Name);

            return obj;
        }
        catch (Exception ex) when (ex is not SerializationException)
        {
            _logger.LogError(ex, "Failed to deserialize JSON to type {Type} asynchronously", typeof(T).Name);
            throw new SerializationException($"Failed to deserialize JSON to type {typeof(T).Name}.", typeof(T).Name, ex);
        }
    }

    /// <inheritdoc/>
    public bool TryDeserialize<T>(string json, out T? result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            result = JsonSerializer.Deserialize<T>(json, _defaultOptions);
            return result != null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deserialize JSON to type {Type}", typeof(T).Name);
            return false;
        }
    }

    /// <inheritdoc/>
    public string SerializeRootCapability(RootCapability capability, bool indented = false)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        return Serialize(capability, indented);
    }

    /// <inheritdoc/>
    public string SerializeDelegatedCapability(DelegatedCapability capability, bool indented = false)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        return Serialize(capability, indented);
    }

    /// <inheritdoc/>
    public string SerializeInvocation(Invocation invocation, bool indented = false)
    {
        if (invocation == null)
        {
            throw new ArgumentNullException(nameof(invocation));
        }

        return Serialize(invocation, indented);
    }

    /// <inheritdoc/>
    public RootCapability DeserializeRootCapability(string json)
    {
        return Deserialize<RootCapability>(json);
    }

    /// <inheritdoc/>
    public DelegatedCapability DeserializeDelegatedCapability(string json)
    {
        return Deserialize<DelegatedCapability>(json);
    }

    /// <inheritdoc/>
    public Invocation DeserializeInvocation(string json)
    {
        return Deserialize<Invocation>(json);
    }

    /// <summary>
    /// Creates JSON serializer options with ZCAP-LD custom converters.
    /// </summary>
    private static JsonSerializerOptions CreateJsonOptions(bool indented)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        // Add custom converters for ZCAP-LD
        options.Converters.Add(new CaveatJsonConverter());
        options.Converters.Add(new ControllerJsonConverter());
        options.Converters.Add(new ContextJsonConverter());
        options.Converters.Add(new AllowedActionJsonConverter());
        options.Converters.Add(new Iso8601DateTimeConverter());

        // Use JsonStringEnumConverter for enums
        options.Converters.Add(new JsonStringEnumConverter());

        return options;
    }
}
