using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Serialization.Converters;

/// <summary>
/// JSON converter for the controller field, which can be either a string or an array of strings.
/// Per W3C ZCAP-LD spec, controller can be a single DID (string) or multiple DIDs (array).
/// </summary>
public class ControllerJsonConverter : JsonConverter<object>
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
                var controllers = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var value = reader.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            controllers.Add(value);
                        }
                    }
                    else
                    {
                        throw new SerializationException(
                            $"Controller array must contain only strings. Found: {reader.TokenType}",
                            "controller");
                    }
                }
                return controllers.ToArray();

            default:
                throw new SerializationException(
                    $"Controller must be a string or array of strings. Found: {reader.TokenType}",
                    "controller");
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
                    $"Controller must be a string or string array. Got: {value.GetType().Name}",
                    "controller");
        }
    }
}
