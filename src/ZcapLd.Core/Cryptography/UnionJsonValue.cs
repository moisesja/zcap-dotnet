using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Reads and writes the <c>object</c>-typed union members, <see cref="Capability.Context"/> and the
/// entries of <see cref="Proof.CapabilityChain"/>, exactly as the reflection object converter did before
/// #154, without needing reflection for the shapes zcap itself produces.
///
/// Read always yields a <see cref="JsonElement"/> (or null for JSON <c>null</c>), which is what the
/// services pattern-match on. Write handles a string, a <see cref="JsonElement"/>, a
/// <see cref="JsonNode"/>, an embedded <see cref="Capability"/> and any enumerable of those (so
/// <c>object[]</c>, <c>string[]</c> and <c>List&lt;object&gt;</c> contexts); nested nulls are written
/// as <c>null</c>, as the reflection array converter wrote them. Every other CLR type is serialized
/// through the metadata the options resolve for its runtime type: in a JIT application that is the
/// reflection resolver <see cref="ZcapJsonOptions.Default"/> keeps, so today's behaviour is unchanged;
/// where reflection is disabled the failure names the member and the type instead of surfacing as a
/// bare "metadata was not provided".
/// </summary>
internal static class UnionJsonValue
{
    private const string SupportedShapes =
        "Without reflection-based serialization only a string, a JsonElement, a JsonNode, an embedded " +
        "Capability and arrays or lists of those are supported.";

    // Through the options' JsonElement metadata rather than JsonElement.ParseValue, so the duplicate-key
    // rejection of the options applies inside the value exactly as it did under the reflection converter.
    public static object? Read(ref Utf8JsonReader reader, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.Null
            ? null
            : JsonSerializer.Deserialize(ref reader, (JsonTypeInfo<JsonElement>)options.GetTypeInfo(typeof(JsonElement)));

    public static void Write(Utf8JsonWriter writer, object? value, JsonSerializerOptions options, string member)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case string text:
                writer.WriteStringValue(text);
                break;
            case JsonElement element:
                element.WriteTo(writer);
                break;
            case JsonNode node:
                node.WriteTo(writer, options);
                break;
            case Capability capability:
                JsonSerializer.Serialize(writer, capability, (JsonTypeInfo<Capability>)options.GetTypeInfo(typeof(Capability)));
                break;
            // Reference-type element sequences only: a dictionary enumerates value-type pairs and so
            // still serializes as an object through the metadata path below.
            case IEnumerable<object?> items:
                // This recursion bypasses the serializer's own depth check, which is what caught a
                // self-referencing array (and any other cycle) before #154; apply the same bound.
                if (writer.CurrentDepth >= EffectiveMaxDepth(options))
                    throw new JsonException(
                        $"A possible object cycle was detected in {member}: the value nests deeper than the maximum " +
                        $"allowed depth of {EffectiveMaxDepth(options)}.");
                writer.WriteStartArray();
                foreach (var item in items)
                    Write(writer, item, options, member);
                writer.WriteEndArray();
                break;
            default:
                JsonSerializer.Serialize(writer, value, GetRuntimeTypeInfo(value.GetType(), options, member));
                break;
        }
    }

    // JsonSerializerOptions.MaxDepth reports 0 for the default, which the serializer treats as 64.
    private static int EffectiveMaxDepth(JsonSerializerOptions options)
        => options.MaxDepth > 0 ? options.MaxDepth : 64;

    private static JsonTypeInfo GetRuntimeTypeInfo(Type runtimeType, JsonSerializerOptions options, string member)
    {
        try
        {
            return options.GetTypeInfo(runtimeType);
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException)
        {
            throw new NotSupportedException(
                $"{member} holds a {runtimeType} and the serializer options have no metadata for that type. {SupportedShapes}",
                ex);
        }
    }
}
