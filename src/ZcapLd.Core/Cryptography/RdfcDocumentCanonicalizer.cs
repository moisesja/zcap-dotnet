using System.Text.Json;
using InnerCanonicalizer = DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// RDFC-1.0 (W3C RDF Dataset Canonicalization) document canonicalizer.
/// Delegates JSON-LD 1.1 expansion and RDFC-1.0 canonicalization to DataProofs.Rdfc — the
/// stack's single dotNetRDF home — serving ZCAP-LD's JSON-LD contexts offline via
/// <see cref="RdfcContextDocumentLoader"/> so the canonical N-Quads stay byte-identical.
/// </summary>
public class RdfcDocumentCanonicalizer : IDocumentCanonicalizer
{
    // The document is serialized with these options before JSON-LD expansion. Kept identical to
    // the pre-delegation serializer so the canonical N-Quads do not drift.
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly InnerCanonicalizer Inner = new(RdfcContextDocumentLoader.Instance);

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        ArgumentNullException.ThrowIfNull(document);

        using var parsed = document is string s
            ? JsonDocument.Parse(s)
            : JsonSerializer.SerializeToDocument(document, SerializerOptions);

        return Inner.CanonicalizeJsonLd(parsed.RootElement);
    }
}
