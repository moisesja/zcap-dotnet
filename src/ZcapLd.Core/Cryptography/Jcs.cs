using System.Buffers;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetCid;

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
/// <para>
/// The node overload also validates the node before it serializes it, and that check is replicated here
/// with NetCid's messages: an unpaired UTF-16 surrogate in a string value, an object key or a
/// <see cref="char"/> value has no UTF-8 form and <see cref="Utf8JsonWriter"/> would substitute U+FFFD, so
/// two distinct inputs (and two distinct revocation keys) would canonicalize alike; NaN and ±infinity
/// have no RFC 8785 form. Both are refused as <see cref="JcsFormatException"/>, as 6.0.0 refused them.
/// </para>
/// </summary>
internal static class Jcs
{
    // NetCid's node overload rejects nesting past this depth as JcsFormatException, before serializing.
    private const int MaxDepth = 64;

    // NetCid serializes a node with MaxDepth = 65 so its own depth guard (64) is what rejects deep input,
    // as JcsFormatException rather than the serializer's JsonException. Parsing with the same headroom
    // keeps that behaviour.
    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = MaxDepth + 1 };

    private const string UnpairedSurrogateMessage =
        "JSON string contains invalid UTF-16 (unpaired surrogate); cannot canonicalize.";

    /// <summary>Canonical UTF-8 bytes of <paramref name="node"/> (<see langword="null"/> is the literal <c>null</c>).</summary>
    internal static byte[] Canonicalize(JsonNode? node)
        => JcsCanonicalizer.Canonicalize(ToElement(node));

    /// <summary>Canonical UTF-8 bytes of <paramref name="element"/>.</summary>
    internal static byte[] Canonicalize(JsonElement element)
        => JcsCanonicalizer.Canonicalize(element);

    /// <summary>Canonical UTF-8 bytes of <paramref name="element"/>, allowing up to <paramref name="maxOutputBytes"/>.</summary>
    internal static byte[] Canonicalize(JsonElement element, int maxOutputBytes)
        => JcsCanonicalizer.Canonicalize(element, maxOutputBytes);

    /// <summary>
    /// The <see cref="JsonElement"/> holding the JSON <paramref name="node"/> represents, after the checks
    /// NetCid's node overload applies.
    /// </summary>
    /// <exception cref="JcsFormatException">The node holds an unpaired surrogate, NaN, ±infinity or nests deeper than 64 levels.</exception>
    internal static JsonElement ToElement(JsonNode? node)
    {
        if (node is not null)
            Validate(node);

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            try
            {
                if (node is null)
                    writer.WriteNullValue();
                else
                    node.WriteTo(writer);
            }
            catch (ArgumentException ex)
            {
                // The writer's signal for NaN/±infinity hidden inside a JsonValue wrapping a CLR object the
                // walk cannot see into; NetCid reports the same case with this message.
                throw new JcsFormatException("JSON value contains NaN or infinity, which cannot be canonicalized.", ex);
            }
        }

        try
        {
            using var document = JsonDocument.Parse(buffer.WrittenMemory, ParseOptions);
            return document.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            // The node overload reports its depth guard as JcsFormatException; keep that for callers.
            throw new JcsFormatException("JSON nests deeper than the supported limit of 64 levels.", ex);
        }
    }

    // Mirrors NetCid.JcsCanonicalizer.ValidateNode, including how it maps the exceptions the JsonNode
    // accessors throw.
    private static void Validate(JsonNode node)
    {
        try
        {
            ValidateNode(node, 0);
        }
        catch (InvalidOperationException ex)
        {
            // A parsed node holding an element-backed unpaired surrogate makes the value/key accessors
            // throw InvalidOperationException ("incomplete UTF-16"); report it as the raw-string check does.
            throw new JcsFormatException(UnpairedSurrogateMessage, ex);
        }
        catch (ArgumentException)
        {
            // A parsed JsonObject builds its dictionary on first enumeration and rejects a duplicate
            // member name with ArgumentException (JcsFormatException is not one, so the checks above
            // propagate untouched). Fall through: WriteTo preserves the duplicate and NetCid's element
            // walker reports it with its key-naming message, the single source of truth for both overloads.
        }
    }

    private static void ValidateNode(JsonNode node, int depth)
    {
        if (depth > MaxDepth)
            throw new JcsFormatException($"JSON nesting exceeds the canonicalization depth limit of {MaxDepth}.");

        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, child) in obj)
                {
                    ThrowIfUnpairedSurrogate(key);
                    if (child is not null)
                        ValidateNode(child, depth + 1);
                }
                break;

            case JsonArray arr:
                foreach (var item in arr)
                {
                    if (item is not null)
                        ValidateNode(item, depth + 1);
                }
                break;

            case JsonValue val:
                if (val.TryGetValue<double>(out var d))
                    ThrowIfNotFinite(double.IsNaN(d), double.IsPositiveInfinity(d), double.IsNegativeInfinity(d));
                else if (val.TryGetValue<float>(out var f))
                    ThrowIfNotFinite(float.IsNaN(f), float.IsPositiveInfinity(f), float.IsNegativeInfinity(f));
                else if (val.TryGetValue<string>(out var s) && s is not null)
                    ThrowIfUnpairedSurrogate(s);
                else if (val.TryGetValue<char>(out var ch) && char.IsSurrogate(ch))
                    // A single code unit can never form a pair, so any surrogate char is unpaired.
                    throw new JcsFormatException(UnpairedSurrogateMessage);
                break;
        }
    }

    private static void ThrowIfNotFinite(bool isNaN, bool isPositiveInfinity, bool isNegativeInfinity)
    {
        if (isNaN)
            throw new JcsFormatException("JCS cannot represent NaN (RFC 8785 §3.2.2.3).");
        if (isPositiveInfinity)
            throw new JcsFormatException("JCS cannot represent +infinity (RFC 8785 §3.2.2.3).");
        if (isNegativeInfinity)
            throw new JcsFormatException("JCS cannot represent -infinity (RFC 8785 §3.2.2.3).");
    }

    private static void ThrowIfUnpairedSurrogate(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                    throw new JcsFormatException(UnpairedSurrogateMessage);
                i++; // a valid pair; skip the low surrogate
            }
            else if (char.IsLowSurrogate(value[i]))
            {
                throw new JcsFormatException(UnpairedSurrogateMessage);
            }
        }
    }
}
