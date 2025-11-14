using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Serialization.Converters;

/// <summary>
/// JSON converter for the allowedAction field, which can be either a string or an array of strings.
/// Per W3C ZCAP-LD spec, allowedAction can be a single action (string) or multiple actions (array).
/// </summary>
public class AllowedActionJsonConverter : JsonConverter<object>
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
                var actions = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var value = reader.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            actions.Add(value);
                        }
                    }
                    else
                    {
                        throw new SerializationException(
                            $"allowedAction array must contain only strings. Found: {reader.TokenType}",
                            "allowedAction");
                    }
                }
                return actions.ToArray();

            default:
                throw new SerializationException(
                    $"allowedAction must be a string or array of strings. Found: {reader.TokenType}",
                    "allowedAction");
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
                    $"allowedAction must be a string or string array. Got: {value.GetType().Name}",
                    "allowedAction");
        }
    }
}
