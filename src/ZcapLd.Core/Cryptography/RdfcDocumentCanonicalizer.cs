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
    // The document is serialized with these options before JSON-LD expansion. Reuse the single
    // ZcapJsonOptions.Default so caveats serialize through CaveatJsonConverter — identical to what
    // production sign/verify (LegacyProofCrypto.BuildDocumentElement) feeds the canonicalizer.
    // A bespoke copy here omitted the converter, so a caveat-bearing capability's restriction fields
    // were dropped from the N-Quads, diverging from production and from any direct RDFC consumer.
    private static readonly JsonSerializerOptions SerializerOptions = ZcapJsonOptions.Default;

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
