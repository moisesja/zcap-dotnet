using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JSON converter for <see cref="InvocationCapability"/> that reads and writes the two spec-allowed
/// wire shapes for an invocation's <c>capability</c> — a bare root-id <b>string</b> (root invocation)
/// or the <b>full embedded delegated zcap object</b> (delegated DI invocation, Issue #51) — and
/// preserves whichever shape it saw.
///
/// The embedded <see cref="Capability"/> is (de)serialized through the supplied serializer options
/// — <see cref="ZcapJsonOptions.Default"/> on the signing/verification paths — so its caveats, proof
/// set, and <c>capabilityChain</c> round-trip exactly and the delegated object's bytes match between
/// the signer and any other Data Integrity verifier (the same contract <see cref="ProofSetJsonConverter"/>
/// upholds for a delegated zcap's <c>proof</c>).
///
/// Read rejects any token that is neither a string nor an object: a malformed <c>capability</c> value
/// must not deserialize into a valid-looking invocation.
/// </summary>
internal sealed class InvocationCapabilityJsonConverter : JsonConverter<InvocationCapability>
{
    public override InvocationCapability? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;

            case JsonTokenType.String:
                return InvocationCapability.FromId(reader.GetString()!);

            case JsonTokenType.StartObject:
            {
                var capability = JsonSerializer.Deserialize<Capability>(ref reader, options)
                    ?? throw new JsonException("Invocation capability object deserialized to null.");
                if (string.IsNullOrEmpty(capability.Id))
                {
                    throw new JsonException("Embedded invocation capability object MUST have an id.");
                }

                return InvocationCapability.FromCapability(capability);
            }

            default:
                throw new JsonException(
                    $"Invocation capability MUST be a root id string or an embedded capability object, got {reader.TokenType}.");
        }
    }

    public override void Write(Utf8JsonWriter writer, InvocationCapability value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.EmbeddedCapability is { } embedded)
        {
            // Delegated invocation: emit the full delegated zcap object so it participates in the
            // signed canonical payload (Issue #51). Serialized through the shared options so the
            // embedded object's caveats/proof/chain round-trip identically.
            JsonSerializer.Serialize(writer, embedded, options);
        }
        else
        {
            // Root invocation (and revocation requests): emit the bare root-id string.
            writer.WriteStringValue(value.Id ?? string.Empty);
        }
    }
}
