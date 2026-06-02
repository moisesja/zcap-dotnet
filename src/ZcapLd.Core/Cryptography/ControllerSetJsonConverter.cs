using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON converter for <see cref="ControllerSet"/> that reads and writes the two
/// spec-allowed wire shapes for <c>controller</c> — a bare string or an array of
/// strings — and preserves whichever shape it saw.
///
/// Write dispatches on <see cref="ControllerSet.IsArrayForm"/>: array form emits a
/// JSON array, scalar form emits a bare string. Preserving the shape keeps JCS
/// canonical bytes byte-stable across a round-trip, which is what cross-language
/// Data Integrity verifiers re-canonicalize against (Issue #47).
///
/// Read rejects malformed controller values per the spec: a non-string array entry,
/// an empty array, or an empty/whitespace string all throw <see cref="JsonException"/>
/// rather than silently producing a valid-looking capability.
/// </summary>
internal sealed class ControllerSetJsonConverter : JsonConverter<ControllerSet>
{
    public override ControllerSet Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
            {
                var value = reader.GetString();
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new JsonException("controller string MUST be a non-empty URI.");
                }
                return ControllerSet.FromSingle(value);
            }

            case JsonTokenType.StartArray:
            {
                var values = new List<string>();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    if (reader.TokenType != JsonTokenType.String)
                    {
                        throw new JsonException(
                            $"controller array entries MUST be strings, got {reader.TokenType}.");
                    }

                    var value = reader.GetString();
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        throw new JsonException("controller array entries MUST be non-empty URIs.");
                    }

                    values.Add(value);
                }

                if (values.Count == 0)
                {
                    throw new JsonException("controller array MUST contain at least one URI.");
                }

                return ControllerSet.FromValues(values, asArray: true);
            }

            case JsonTokenType.Null:
                return ControllerSet.Empty;

            default:
                throw new JsonException(
                    $"controller MUST be a string or an array of strings, got {reader.TokenType}.");
        }
    }

    public override void Write(Utf8JsonWriter writer, ControllerSet value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.IsArrayForm)
        {
            writer.WriteStartArray();
            foreach (var controller in value.Values)
            {
                writer.WriteStringValue(controller);
            }
            writer.WriteEndArray();
        }
        else
        {
            // Scalar form (single controller, or empty degenerate case) → bare string.
            writer.WriteStringValue(value.Primary);
        }
    }
}
