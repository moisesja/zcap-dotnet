using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON converter for <see cref="Proof.CapabilityChain"/>: entries are ancestor id strings or, for the
/// immediate parent, an embedded capability object, so the member stays <c>object[]</c>-typed and this
/// converter replaces the reflection array-of-object converter (#154). Each entry reads to a
/// <see cref="JsonElement"/> (a JSON <c>null</c> entry reads to null) and writes through
/// <see cref="UnionJsonValue"/>. JSON <c>null</c> and a null member are handled by the serializer as
/// before (read to null, omitted under <c>WhenWritingNull</c>).
/// </summary>
internal sealed class CapabilityChainJsonConverter : JsonConverter<object[]>
{
    public override object[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
            throw new JsonException($"capabilityChain MUST be an array, got {reader.TokenType}.");

        var entries = new List<object?>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            entries.Add(UnionJsonValue.Read(ref reader, options));
        return entries.ToArray()!;
    }

    public override void Write(Utf8JsonWriter writer, object[] value, JsonSerializerOptions options)
        => UnionJsonValue.Write(writer, value, options, "Proof.CapabilityChain");
}
