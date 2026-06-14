using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetCidJcs = NetCid.JcsCanonicalizer;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON canonicalization for ZCAP-LD documents (RFC 8785, JSON Canonicalization Scheme).
/// The canonicalization itself is delegated to NetCid's <see cref="NetCid.JcsCanonicalizer"/>
/// — the stack's single RFC 8785 implementation — preceded by a null-object-member strip so a
/// JsonElement round-tripped from the wire produces the same canonical form as a native model
/// serialized with <see cref="System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull"/>.
/// </summary>
/// <remarks>
/// Delegating to NetCid also makes key ordering RFC 8785-conformant (UTF-16 code-unit order,
/// culture-invariant). The previous hand-rolled writer sorted with the current culture, which is
/// locale-dependent and non-conformant for mixed-case / non-ASCII keys; spec ZCAP field names are
/// all lowercase ASCII, so the canonical bytes are unchanged for every conformant capability.
/// </remarks>
public static class JsonCanonicalizer
{
    /// <summary>
    /// Canonicalizes a JSON object to bytes for signing.
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonicalized UTF-8 bytes</returns>
    public static byte[] Canonicalize(object document)
    {
        var json = JsonSerializer.Serialize(document, CanonicalJsonOptions);
        return CanonicalizeString(json);
    }

    /// <summary>
    /// Canonicalizes a JSON string to bytes (RFC 8785), dropping null object members.
    /// </summary>
    /// <param name="jsonString">The JSON string to canonicalize</param>
    /// <returns>Canonicalized UTF-8 bytes</returns>
    public static byte[] CanonicalizeString(string jsonString)
    {
        using var doc = JsonDocument.Parse(jsonString);
        var stripped = StripNullMembers(doc.RootElement);
        var element = JsonSerializer.SerializeToElement(stripped);
        return NetCidJcs.Canonicalize(element);
    }

    /// <summary>
    /// Rebuilds <paramref name="element"/> dropping every null-valued <em>object member</em> at any
    /// depth, preserving null <em>array elements</em> (RFC 8785 keeps those). Mirrors the historical
    /// canonicalizer behavior so present-but-null wire fields and <c>WhenWritingNull</c>-serialized
    /// models canonicalize identically.
    /// </summary>
    private static JsonNode? StripNullMembers(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var obj = new JsonObject();
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                        continue;
                    obj[property.Name] = StripNullMembers(property.Value);
                }
                return obj;

            case JsonValueKind.Array:
                var arr = new JsonArray();
                foreach (var item in element.EnumerateArray())
                    arr.Add(item.ValueKind == JsonValueKind.Null ? null : StripNullMembers(item));
                return arr;

            default:
                return JsonNode.Parse(element.GetRawText());
        }
    }

    /// <summary>
    /// Per RFC 8785 §3.2.2.2, JSON strings escape only control chars (&lt;0x20), the reverse
    /// solidus, and the double quote. Used by the proof-removal helpers below, which preserve the
    /// historical relaxed-escaping writer output.
    /// </summary>
    private static readonly JsonWriterOptions CanonicalWriterOptions = new()
    {
        Indented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// JSON serialization options for canonical form: compact, original property names, relaxed
    /// escaping, and null model properties omitted.
    /// </summary>
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Removes the proof field from a capability or invocation object for verification.
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

    private static void WriteElementWithoutProof(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
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
    /// Creates a canonical JSON string from an object, excluding the proof field.
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonical JSON string without proof</returns>
    public static string CanonicalizeWithoutProof(object document)
    {
        var json = JsonSerializer.Serialize(document, CanonicalJsonOptions);
        return RemoveProofField(json);
    }
}
