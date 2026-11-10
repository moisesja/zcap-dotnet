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

        // The same metadata as the production proof engine: zcap's models and the JSON DOM resolve
        // without reflection, a consumer's own type needs the options' reflection resolver (#154).
        using var parsed = document is string s
            ? JsonDocument.Parse(s)
            : JsonSerializer.SerializeToDocument(document, ZcapJsonOptions.TypeInfo<object>());

        return _inner.CanonicalizeJsonLd(parsed.RootElement);
    }
}
