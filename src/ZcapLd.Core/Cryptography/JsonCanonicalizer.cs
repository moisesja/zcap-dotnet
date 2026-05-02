using System.Text;
using System.Text.Json;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON canonicalization for ZCAP-LD documents
/// Implements a simplified JSON canonicalization that works for ZCAP-LD use cases
/// Based on RFC 8785 (JSON Canonicalization Scheme - JCS)
/// </summary>
public static class JsonCanonicalizer
{
    /// <summary>
    /// Canonicalizes a JSON object to bytes for signing
    /// Uses deterministic serialization with sorted keys
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonicalized UTF-8 bytes</returns>
    public static byte[] Canonicalize(object document)
    {
        // Serialize to JSON first
        var json = JsonSerializer.Serialize(document, CanonicalJsonOptions);
        // Then canonicalize the JSON string (which sorts properties)
        return CanonicalizeString(json);
    }

    /// <summary>
    /// Canonicalizes a JSON string to bytes
    /// Properties are sorted alphabetically for deterministic output
    /// </summary>
    /// <param name="jsonString">The JSON string to canonicalize</param>
    /// <returns>Canonicalized UTF-8 bytes</returns>
    public static byte[] CanonicalizeString(string jsonString)
    {
        // Parse and re-serialize with sorted properties
        using var doc = JsonDocument.Parse(jsonString);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, CanonicalWriterOptions))
        {
            WriteElementSorted(writer, doc.RootElement);
        }
        return stream.ToArray();
    }

    /// <summary>
    /// Per RFC 8785 §3.2.2.2, JSON strings escape only control chars (&lt;0x20),
    /// the reverse solidus, and the double quote — not characters like `+`, `&lt;`, `&gt;`,
    /// or `&amp;`. Utf8JsonWriter's default encoder escapes those for HTML safety,
    /// which would diverge our canonical bytes from any RFC 8785-conformant peer
    /// (e.g. timestamps written as `2026-04-29T00:00:00+00:00` would canonicalize
    /// differently in zcap-dotnet vs. zcap-py).
    /// </summary>
    private static readonly JsonWriterOptions CanonicalWriterOptions = new()
    {
        Indented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// JSON serialization options for canonical form
    /// - No indentation (compact)
    /// - Preserve original property names (no camelCase conversion)
    /// - Proper escaping
    /// - No default values
    /// </summary>
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null, // Preserve original names
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Removes the proof field from a capability or invocation object for verification
    /// </summary>
    /// <param name="jsonString">The JSON string with proof</param>
    /// <returns>JSON string without proof field</returns>
    public static string RemoveProofField(string jsonString)
    {
        using var doc = JsonDocument.Parse(jsonString);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, CanonicalWriterOptions))
        {
            WriteElementWithoutProof(writer, doc.RootElement);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteElementSorted(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name))
                {
                    // Skip null-valued properties so that JsonElement objects
                    // (from JSON round-trips) produce the same canonical form
                    // as native C# objects serialized with WhenWritingNull.
                    if (property.Value.ValueKind == JsonValueKind.Null)
                        continue;

                    writer.WritePropertyName(property.Name);
                    WriteElementSorted(writer, property.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteElementSorted(writer, item);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                if (element.TryGetInt32(out var intValue))
                    writer.WriteNumberValue(intValue);
                else if (element.TryGetInt64(out var longValue))
                    writer.WriteNumberValue(longValue);
                else if (element.TryGetDouble(out var doubleValue))
                    writer.WriteNumberValue(doubleValue);
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
        }
    }

    private static void WriteElementWithoutProof(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name))
                {
                    // Skip the proof field
                    if (property.Name == "proof")
                        continue;

                    writer.WritePropertyName(property.Name);
                    WriteElementWithoutProof(writer, property.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteElementWithoutProof(writer, item);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                if (element.TryGetInt32(out var intValue))
                    writer.WriteNumberValue(intValue);
                else if (element.TryGetInt64(out var longValue))
                    writer.WriteNumberValue(longValue);
                else if (element.TryGetDouble(out var doubleValue))
                    writer.WriteNumberValue(doubleValue);
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
        }
    }

    /// <summary>
    /// Creates a canonical JSON string from an object, excluding the proof field
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonical JSON string without proof</returns>
    public static string CanonicalizeWithoutProof(object document)
    {
        var json = JsonSerializer.Serialize(document, CanonicalJsonOptions);
        return RemoveProofField(json);
    }
}
