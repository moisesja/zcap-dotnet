using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Polymorphic JSON converter for <see cref="Caveat"/> that dispatches by the
/// `type` discriminator at read time and by the runtime CLR type at write time.
///
/// Without this converter, STJ uses the static array element type (<see cref="Caveat"/>,
/// abstract) when serializing a <c>Caveat[]</c>, silently dropping derived-class
/// fields (Issue #39). The result: sign-time JCS sees `[{"type":"Expiration"}]`
/// while the wire body any orchestrator emits via <c>value.GetType()</c> carries
/// the full `[{"type":"Expiration","expires":"..."}]`. zcap-py and other
/// cross-language verifiers re-canonicalize the wire body, hashes diverge, and
/// signature verification fails at the chain link with the caveat.
///
/// <see cref="CanConvert"/> matches only the abstract base type so concrete-type
/// recursion bottoms out at default reflection — no infinite loop, derived
/// classes serialize through normal STJ machinery.
/// </summary>
internal sealed class CaveatJsonConverter : JsonConverter<Caveat>
{
    private readonly CaveatTypeRegistry _registry;

    public CaveatJsonConverter(CaveatTypeRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public override bool CanConvert(Type typeToConvert) => typeToConvert == typeof(Caveat);

    public override Caveat? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
            throw new JsonException($"Expected JSON object for Caveat, got {root.ValueKind}.");

        if (!root.TryGetProperty("type", out var typeProp) || typeProp.ValueKind != JsonValueKind.String)
            throw new JsonException("Caveat JSON object is missing required 'type' discriminator.");

        var discriminator = typeProp.GetString()!;
        var concreteType = _registry.Resolve(discriminator)
            ?? throw new JsonException(
                $"No Caveat type registered for discriminator '{discriminator}'. " +
                $"Register it via CaveatTypeRegistry.Default.Register<T>(\"{discriminator}\") " +
                $"before signing or verifying capabilities that carry this caveat.");

        return (Caveat?)JsonSerializer.Deserialize(root.GetRawText(), concreteType, options);
    }

    public override void Write(Utf8JsonWriter writer, Caveat value, JsonSerializerOptions options)
    {
        // Dispatch to the runtime concrete type so STJ writes derived fields.
        // CanConvert returns false for concrete types, so this recursion bottoms
        // out at default reflection serialization.
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}
