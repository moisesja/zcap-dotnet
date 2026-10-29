using System.Text.Json;
using ZcapLd.Core.Models;
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
    // Use the same serialization options as the production proof engine.
    private static readonly JsonSerializerOptions SerializerOptions = ZcapJsonOptions.Default;

    private static readonly InnerCanonicalizer Shared = new(RdfcContextDocumentLoader.Instance);

    private readonly InnerCanonicalizer _inner;

    /// <summary>A canonicalizer over the ZCAP and supported suite contexts.</summary>
    public RdfcDocumentCanonicalizer() => _inner = Shared;

    /// <summary>A canonicalizer that also resolves the generated contexts of registered caveat types (#157).</summary>
    public RdfcDocumentCanonicalizer(CaveatTypeRegistry caveats)
        => _inner = new InnerCanonicalizer(new RdfcContextDocumentLoader(caveats ?? throw new ArgumentNullException(nameof(caveats))));

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        ArgumentNullException.ThrowIfNull(document);

        using var parsed = document is string s
            ? JsonDocument.Parse(s)
            : JsonSerializer.SerializeToDocument(document, SerializerOptions);

        return _inner.CanonicalizeJsonLd(parsed.RootElement);
    }
}
