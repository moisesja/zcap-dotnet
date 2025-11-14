using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZcapLd.Core.Serialization.Converters;

/// <summary>
/// JSON converter for DateTime that serializes in ISO 8601 / XSD dateTime format.
/// Per W3C ZCAP-LD spec, timestamps must be in ISO 8601 format with timezone.
/// Format: "2024-01-15T10:30:00Z" (always UTC, always with 'Z' suffix)
/// </summary>
public class Iso8601DateTimeConverter : JsonConverter<DateTime>
{
    private const string Format = "yyyy-MM-ddTHH:mm:ssZ";

    /// <inheritdoc/>
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var str = reader.GetString();
        if (string.IsNullOrWhiteSpace(str))
        {
            return default;
        }

        // Try ISO 8601 formats
        if (DateTime.TryParse(str, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var result))
        {
            // Convert to UTC if not already
            return result.Kind == DateTimeKind.Utc ? result : result.ToUniversalTime();
        }

        throw new JsonException($"Unable to parse '{str}' as ISO 8601 DateTime.");
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        // Ensure UTC
        var utcValue = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();

        // Write in ISO 8601 format with 'Z' suffix
        writer.WriteStringValue(utcValue.ToString(Format, CultureInfo.InvariantCulture));
    }
}
