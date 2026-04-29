using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Serializes DateTime / DateTime? as ISO-8601 UTC with 6-digit (microsecond)
/// fractional seconds: "yyyy-MM-ddTHH:mm:ss.ffffffZ".
///
/// JCS canonicalization is byte-sensitive, so cross-stack interop requires every
/// implementation to produce the same string for the same instant. .NET's default
/// emits 7-digit (100-ns tick) precision, while Python / JS / Rust emit 6-digit.
/// Standardizing on 6 digits aligns with the broader Data Integrity ecosystem.
/// </summary>
internal sealed class IsoUtcMicrosecondDateTimeConverter : JsonConverterFactory
{
    private const string Format = "yyyy-MM-ddTHH:mm:ss.ffffffZ";

    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert == typeof(DateTime) || typeToConvert == typeof(DateTime?);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        typeToConvert == typeof(DateTime)
            ? new DateTimeConverter()
            : new NullableDateTimeConverter();

    private sealed class DateTimeConverter : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.GetDateTime();

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        {
            var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
            writer.WriteStringValue(utc.ToString(Format, CultureInfo.InvariantCulture));
        }
    }

    private sealed class NullableDateTimeConverter : JsonConverter<DateTime?>
    {
        public override DateTime? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.TokenType == JsonTokenType.Null ? null : reader.GetDateTime();

        public override void Write(Utf8JsonWriter writer, DateTime? value, JsonSerializerOptions options)
        {
            if (!value.HasValue)
            {
                writer.WriteNullValue();
                return;
            }

            var utc = value.Value.Kind == DateTimeKind.Utc
                ? value.Value
                : value.Value.ToUniversalTime();
            writer.WriteStringValue(utc.ToString(Format, CultureInfo.InvariantCulture));
        }
    }
}
