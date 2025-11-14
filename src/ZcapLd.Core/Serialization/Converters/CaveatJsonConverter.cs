using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Serialization.Converters;

/// <summary>
/// JSON converter for polymorphic Caveat types.
/// Deserializes based on the "type" discriminator field.
/// </summary>
public class CaveatJsonConverter : JsonConverter<Caveat>
{
    /// <inheritdoc/>
    public override Caveat? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new SerializationException(
                $"Expected StartObject token, got {reader.TokenType}",
                nameof(Caveat));
        }

        // Read the entire object into a JsonDocument to inspect the "type" field
        using var doc = JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;

        // Get the "type" property
        if (!root.TryGetProperty("type", out var typeElement))
        {
            throw new SerializationException(
                "Caveat JSON must contain a 'type' property.",
                nameof(Caveat));
        }

        var caveatType = typeElement.GetString();
        if (string.IsNullOrWhiteSpace(caveatType))
        {
            throw new SerializationException(
                "Caveat 'type' property cannot be null or empty.",
                nameof(Caveat));
        }

        // Deserialize to the appropriate concrete type based on "type" value
        var rawJson = root.GetRawText();

        return caveatType switch
        {
            ExpirationCaveat.CaveatType => JsonSerializer.Deserialize<ExpirationCaveat>(rawJson, options),
            UsageCountCaveat.CaveatType => JsonSerializer.Deserialize<UsageCountCaveat>(rawJson, options),
            TimeWindowCaveat.CaveatType => JsonSerializer.Deserialize<TimeWindowCaveat>(rawJson, options),
            ActionCaveat.CaveatType => JsonSerializer.Deserialize<ActionCaveat>(rawJson, options),
            IpAddressCaveat.CaveatType => JsonSerializer.Deserialize<IpAddressCaveat>(rawJson, options),
            _ => throw new SerializationException(
                $"Unknown caveat type: {caveatType}. Supported types: {string.Join(", ", GetSupportedTypes())}",
                nameof(Caveat))
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, Caveat value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        // Serialize the concrete type polymorphically
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }

    /// <summary>
    /// Gets the list of supported caveat type identifiers.
    /// </summary>
    /// <returns>An array of supported type strings.</returns>
    public static string[] GetSupportedTypes()
    {
        return new[]
        {
            ExpirationCaveat.CaveatType,
            UsageCountCaveat.CaveatType,
            TimeWindowCaveat.CaveatType,
            ActionCaveat.CaveatType,
            IpAddressCaveat.CaveatType
        };
    }
}
