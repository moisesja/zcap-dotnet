using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Source-generated serializer metadata for every type zcap puts on the wire or hands to a
/// canonicalizer (#154). <see cref="ZcapJsonOptions.Default"/> resolves through this context first, so
/// a native AOT, trimmed or file-based (<c>dotnet run app.cs</c>) application, where reflection-based
/// serialization is disabled, serializes the same bytes a JIT application does.
///
/// The attribute mirrors the settings of <see cref="ZcapJsonOptions.Default"/> that the generator can
/// express (indentation, null omission, duplicate-key rejection); the encoder cannot be declared here
/// and lives on the options. Generation is metadata-only on purpose: the metadata path drives the same
/// converters reflection does, so the output is byte-identical by construction, while the fast-path
/// (<c>Serialization</c>) mode would write a second implementation of the models that the golden
/// vectors would have to re-prove.
///
/// Model types list the converters and models that the ZcapLd services serialize; the collection and
/// JSON DOM types cover the field dictionaries, context arrays, caveat entries and probe documents that
/// <c>ProofSigningPayloadBuilder</c>, <c>LegacyProofCrypto</c>, <c>CanonicalIri</c>, <c>CaveatCodec</c>,
/// <c>SigningService</c>, <c>CapabilityService</c>, <c>VerificationService</c> and
/// <c>CapabilityProfile</c> pass to the serializer.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    AllowDuplicateProperties = false,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
// Wire models.
[JsonSerializable(typeof(Capability))]
[JsonSerializable(typeof(Proof))]
[JsonSerializable(typeof(ProofSet))]
[JsonSerializable(typeof(ControllerSet))]
[JsonSerializable(typeof(Invocation))]
[JsonSerializable(typeof(InvocationCapability))]
[JsonSerializable(typeof(RevocationRequest))]
[JsonSerializable(typeof(RevocationRecord))]
[JsonSerializable(typeof(RevocationScope))]
// JSON DOM: extension data, chain entries, caveat entries, context arrays and application documents.
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(JsonElement[]))]
[JsonSerializable(typeof(IEnumerable<JsonElement>))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonArray))]
// Field dictionaries, the CanonicalIri probe document and signed revocation metadata.
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(IDictionary<string, string>))]
[JsonSerializable(typeof(IReadOnlyDictionary<string, string>))]
// Context values and chain entries in their native shapes.
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(IReadOnlyList<string>))]
[JsonSerializable(typeof(IEnumerable<string>))]
[JsonSerializable(typeof(object))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(List<object>))]
internal sealed partial class ZcapJsonContext : JsonSerializerContext
{
}
