using System.Text;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// RDFC-1.0 as DataProofs 1.4.0 and other lenient JSON-LD processors produce it: dotNetRDF without
/// DataProofs 1.5.0's data-loss checks. Terms no context defines and IRIs it cannot parse are silently
/// dropped, and respelled IRIs are signed in their rewritten form. Adversarial tests sign with it to
/// model an attacker on such a stack: the signature is valid for the reduced graph, and the verifier
/// must still reject the document that carries the extra data.
/// </summary>
internal sealed class LenientRdfcCanonicalizer : IDocumentCanonicalizer
{
    public static LenientRdfcCanonicalizer Instance { get; } = new();

    private readonly RdfcContextDocumentLoader _loader;

    public LenientRdfcCanonicalizer(CaveatTypeRegistry? caveats = null) => _loader = new RdfcContextDocumentLoader(caveats);

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        var json = document as string ?? JsonSerializer.Serialize(document, ZcapJsonOptions.Default);
        var store = new TripleStore();
        new JsonLdParser(new JsonLdProcessorOptions { DocumentLoader = Load }).Load(store, new StringReader(json));
        return Encoding.UTF8.GetBytes(new RdfCanonicalizer("SHA256").Canonicalize(store).SerializedNQuads);
    }

    private RemoteDocument Load(Uri uri, JsonLdLoaderOptions options)
    {
        var loaded = _loader.Load(uri);
        return new RemoteDocument { Document = JToken.Parse(loaded.Content), DocumentUrl = loaded.DocumentUrl };
    }
}
