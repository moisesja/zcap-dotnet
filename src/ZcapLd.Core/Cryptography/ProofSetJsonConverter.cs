using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON converter for <see cref="ProofSet"/> that reads and writes the two spec-allowed wire
/// shapes for a delegated zcap's <c>proof</c> — a single DI proof object or an array of proof
/// objects — and preserves whichever shape it saw.
///
/// Write dispatches on <see cref="ProofSet.IsArrayForm"/>: array form emits a JSON array,
/// object form emits a single bare proof object. Each <see cref="Proof"/> is (de)serialized
/// through normal STJ machinery, so <c>[JsonExtensionData]</c> and <c>WhenWritingNull</c> on
/// <see cref="Proof"/> are honored — unmodeled proof fields round-trip verbatim (Issue #48).
///
/// Read rejects an empty array and non-object array entries with <see cref="JsonException"/>:
/// a delegated zcap with an empty proof set is invalid and must not deserialize into a
/// valid-looking capability.
/// </summary>
internal sealed class ProofSetJsonConverter : JsonConverter<ProofSet>
{
    public override ProofSet Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.StartObject:
            {
                var proof = JsonSerializer.Deserialize<Proof>(ref reader, options)
                    ?? throw new JsonException("proof object deserialized to null.");
                return ProofSet.FromSingle(proof);
            }

            case JsonTokenType.StartArray:
            {
                var proofs = new List<Proof>();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        throw new JsonException(
                            $"proof array entries MUST be objects, got {reader.TokenType}.");
                    }

                    var proof = JsonSerializer.Deserialize<Proof>(ref reader, options)
                        ?? throw new JsonException("proof array entry deserialized to null.");
                    proofs.Add(proof);
                }

                if (proofs.Count == 0)
                {
                    throw new JsonException("proof array MUST contain at least one proof.");
                }

                return ProofSet.FromValues(proofs, asArray: true);
            }

            default:
                throw new JsonException(
                    $"proof MUST be an object or an array of objects, got {reader.TokenType}.");
        }
    }

    public override void Write(Utf8JsonWriter writer, ProofSet value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.IsArrayForm)
        {
            writer.WriteStartArray();
            foreach (var proof in value.Values)
            {
                JsonSerializer.Serialize(writer, proof, options);
            }
            writer.WriteEndArray();
        }
        else
        {
            // Object form (single proof) → bare proof object, identical to the pre-#48 wire shape.
            JsonSerializer.Serialize(writer, value.Primary, options);
        }
    }
}
