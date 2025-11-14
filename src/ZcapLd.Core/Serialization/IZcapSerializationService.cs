using ZcapLd.Core.Models;

namespace ZcapLd.Core.Serialization;

/// <summary>
/// Service for serializing and deserializing ZCAP-LD objects.
/// Handles custom converters for polymorphic types and ensures W3C spec compliance.
/// </summary>
public interface IZcapSerializationService
{
    /// <summary>
    /// Serializes an object to JSON-LD format.
    /// </summary>
    /// <typeparam name="T">The type of object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <param name="indented">Whether to format the output with indentation (default: false).</param>
    /// <returns>The JSON-LD string.</returns>
    /// <exception cref="SerializationException">Thrown when serialization fails.</exception>
    string Serialize<T>(T obj, bool indented = false);

    /// <summary>
    /// Serializes an object to JSON-LD format asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <param name="indented">Whether to format the output with indentation (default: false).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JSON-LD string.</returns>
    /// <exception cref="SerializationException">Thrown when serialization fails.</exception>
    Task<string> SerializeAsync<T>(T obj, bool indented = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deserializes a JSON-LD string to an object.
    /// </summary>
    /// <typeparam name="T">The type of object to deserialize to.</typeparam>
    /// <param name="json">The JSON-LD string.</param>
    /// <returns>The deserialized object.</returns>
    /// <exception cref="SerializationException">Thrown when deserialization fails.</exception>
    T Deserialize<T>(string json);

    /// <summary>
    /// Deserializes a JSON-LD string to an object asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of object to deserialize to.</typeparam>
    /// <param name="json">The JSON-LD string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The deserialized object.</returns>
    /// <exception cref="SerializationException">Thrown when deserialization fails.</exception>
    Task<T> DeserializeAsync<T>(string json, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to deserialize a JSON-LD string to an object.
    /// </summary>
    /// <typeparam name="T">The type of object to deserialize to.</typeparam>
    /// <param name="json">The JSON-LD string.</param>
    /// <param name="result">The deserialized object if successful.</param>
    /// <returns>True if deserialization succeeded; otherwise, false.</returns>
    bool TryDeserialize<T>(string json, out T? result);

    /// <summary>
    /// Serializes a root capability to JSON-LD.
    /// </summary>
    /// <param name="capability">The root capability.</param>
    /// <param name="indented">Whether to format the output with indentation.</param>
    /// <returns>The JSON-LD string.</returns>
    string SerializeRootCapability(RootCapability capability, bool indented = false);

    /// <summary>
    /// Serializes a delegated capability to JSON-LD.
    /// </summary>
    /// <param name="capability">The delegated capability.</param>
    /// <param name="indented">Whether to format the output with indentation.</param>
    /// <returns>The JSON-LD string.</returns>
    string SerializeDelegatedCapability(DelegatedCapability capability, bool indented = false);

    /// <summary>
    /// Serializes an invocation to JSON-LD.
    /// </summary>
    /// <param name="invocation">The invocation.</param>
    /// <param name="indented">Whether to format the output with indentation.</param>
    /// <returns>The JSON-LD string.</returns>
    string SerializeInvocation(Invocation invocation, bool indented = false);

    /// <summary>
    /// Deserializes a root capability from JSON-LD.
    /// </summary>
    /// <param name="json">The JSON-LD string.</param>
    /// <returns>The root capability.</returns>
    RootCapability DeserializeRootCapability(string json);

    /// <summary>
    /// Deserializes a delegated capability from JSON-LD.
    /// </summary>
    /// <param name="json">The JSON-LD string.</param>
    /// <returns>The delegated capability.</returns>
    DelegatedCapability DeserializeDelegatedCapability(string json);

    /// <summary>
    /// Deserializes an invocation from JSON-LD.
    /// </summary>
    /// <param name="json">The JSON-LD string.</param>
    /// <returns>The invocation.</returns>
    Invocation DeserializeInvocation(string json);
}
