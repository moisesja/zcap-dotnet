using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON converter for <see cref="Capability.Context"/>: a JSON-LD <c>@context</c> is a string or an
/// array (or, in content the profile rejects, an object), so the member stays <c>object</c>-typed and
/// this converter replaces the reflection object converter (#154). Read yields a
/// <see cref="JsonElement"/>; write follows <see cref="UnionJsonValue"/>. JSON <c>null</c> and a null
/// member are handled by the serializer as before (read to null, omitted under <c>WhenWritingNull</c>).
/// </summary>
internal sealed class ContextJsonConverter : JsonConverter<object>
{
    public override object? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => UnionJsonValue.Read(ref reader, options);

    public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
        => UnionJsonValue.Write(writer, value, options, "Capability.Context");
}
