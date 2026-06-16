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
}
