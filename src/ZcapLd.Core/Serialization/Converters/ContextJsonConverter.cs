using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Serialization.Converters;

/// <summary>
/// JSON converter for the @context field, which can be either a string or an array of strings.
/// Per W3C ZCAP-LD spec:
/// - Root capabilities: @context is a string "https://w3id.org/zcap/v1"
/// - Delegated capabilities: @context is an array starting with "https://w3id.org/zcap/v1"
/// </summary>
public class ContextJsonConverter : JsonConverter<object>
{
    /// <inheritdoc/>
    public override object? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;

            case JsonTokenType.String:
                return reader.GetString() ?? string.Empty;

            case JsonTokenType.StartArray:
                var contexts = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var value = reader.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            contexts.Add(value);
                        }
                    }
                    else
                    {
                        throw new SerializationException(
                            $"@context array must contain only strings. Found: {reader.TokenType}",
                            "@context");
                    }
                }
                return contexts.ToArray();

            default:
                throw new SerializationException(
                    $"@context must be a string or array of strings. Found: {reader.TokenType}",
                    "@context");
        }
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        switch (value)
        {
            case string str:
                writer.WriteStringValue(str);
                break;

            case string[] arr:
                writer.WriteStartArray();
                foreach (var item in arr)
                {
                    writer.WriteStringValue(item);
                }
                writer.WriteEndArray();
                break;

            default:
                throw new SerializationException(
                    $"@context must be a string or string array. Got: {value.GetType().Name}",
                    "@context");
        }
    }
}
