namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Produces a deterministic byte representation of a JSON/JSON-LD document. The implementation is
/// RDFC-1.0 (W3C RDF Dataset Canonicalization) — the only canonicalization ZCAP-LD supports.
/// </summary>
public interface IDocumentCanonicalizer
{
    /// <summary>
    /// Identifier for the canonicalization method (currently always <c>"RDFC-1.0"</c>).
    /// </summary>
    string Method { get; }

    /// <summary>
    /// Canonicalizes a document to a deterministic byte representation.
    /// </summary>
    /// <param name="document">The document to canonicalize (C# object or JSON string)</param>
    /// <returns>Canonical UTF-8 bytes</returns>
    byte[] Canonicalize(object document);
}
