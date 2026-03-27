using System.Text;
using System.Text.Json;
using VDS.RDF;
using VDS.RDF.Parsing;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// RDFC-1.0 (W3C RDF Dataset Canonicalization) document canonicalizer.
/// Parses JSON-LD, canonicalizes to N-Quads via dotNetRdf's <see cref="RdfCanonicalizer"/>.
/// </summary>
public class RdfcDocumentCanonicalizer : IDocumentCanonicalizer
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var jsonString = document is string s
            ? s
            : JsonSerializer.Serialize(document, SerializerOptions);

        var store = new TripleStore();
        var parser = new JsonLdParser();
        parser.Load(store, new StringReader(jsonString));

        var canonicalizer = new RdfCanonicalizer();
        var result = canonicalizer.Canonicalize(store);

        return Encoding.UTF8.GetBytes(result.SerializedNQuads);
    }
}
