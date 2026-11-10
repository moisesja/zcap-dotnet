using System.Buffers;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// RFC 8785 canonicalization through NetCid's <see cref="JsonElement"/> overload, the one path that is
/// reflection-free (#154). NetCid's <see cref="JsonNode"/> overloads reach the element walker through
/// <c>JsonSerializer.SerializeToDocument(node)</c>, which is the reflection-based serializer and throws
/// under native AOT, trimming and .NET 10 file-based apps. Converting here with
/// <see cref="JsonNode.WriteTo"/> and <see cref="JsonDocument.Parse(ReadOnlyMemory{byte}, JsonDocumentOptions)"/>
/// yields the same element, so the bytes are the ones 6.0.0 produced; the pinned revocation-key, grant-key
/// and caveat-context tests hold that fixed. This is the only ZcapLd type that calls
/// <c>NetCid.JcsCanonicalizer</c>.
/// </summary>
internal static class Jcs
{
    // NetCid serializes a node with MaxDepth = 65 so its own depth guard (64) is what rejects deep input,
    // as JcsFormatException rather than the serializer's JsonException. Parsing with the same headroom
    // keeps that behaviour.
    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 65 };

    /// <summary>Canonical UTF-8 bytes of <paramref name="node"/> (<see langword="null"/> is the literal <c>null</c>).</summary>
    internal static byte[] Canonicalize(JsonNode? node)
        => NetCid.JcsCanonicalizer.Canonicalize(ToElement(node));

    /// <summary>Canonical UTF-8 bytes of <paramref name="element"/>.</summary>
    internal static byte[] Canonicalize(JsonElement element)
        => NetCid.JcsCanonicalizer.Canonicalize(element);

    /// <summary>Canonical UTF-8 bytes of <paramref name="element"/>, allowing up to <paramref name="maxOutputBytes"/>.</summary>
    internal static byte[] Canonicalize(JsonElement element, int maxOutputBytes)
        => NetCid.JcsCanonicalizer.Canonicalize(element, maxOutputBytes);

    /// <summary>The <see cref="JsonElement"/> holding the JSON <paramref name="node"/> represents.</summary>
    internal static JsonElement ToElement(JsonNode? node)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            if (node is null)
                writer.WriteNullValue();
            else
                node.WriteTo(writer);
        }

        try
        {
            using var document = JsonDocument.Parse(buffer.WrittenMemory, ParseOptions);
            return document.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            // The node overload reports its depth guard as JcsFormatException; keep that for callers.
            throw new NetCid.JcsFormatException("JSON nests deeper than the supported limit of 64 levels.", ex);
        }
    }
}
