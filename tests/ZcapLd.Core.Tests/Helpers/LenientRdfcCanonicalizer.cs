using System.Text;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;
using VDS.RDF.Writing;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using DataProofsRdfc = DataProofsDotnet.Rdfc;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// RDFC-1.0 over a lenient JSON-LD expansion: dotNetRDF's parser without DataProofs' data-loss checks, so
/// terms no context defines and IRIs it cannot parse are silently dropped, and respelled IRIs are signed in
/// their rewritten form. Adversarial tests sign with it to model an attacker on such a stack: the signature
/// is valid for the reduced graph, and the verifier must still reject the document that carries the extra
/// data. The expanded dataset is then canonicalized by the production canonicalizer (DataProofs), so the only
/// difference from production is the data loss. dotNetRDF 3.5.1's own <c>RdfCanonicalizer</c> labels tied
/// blank nodes in the wrong order (dotnetrdf#917), which DataProofs 2.0.0 corrects; a signer using it
/// disagrees with the verifier on documents such as an embedded parent carrying two proofs.
/// </summary>
internal sealed class LenientRdfcCanonicalizer : IDocumentCanonicalizer
{
    public static LenientRdfcCanonicalizer Instance { get; } = new();

    private readonly RdfcContextDocumentLoader _loader;
    private readonly DataProofsRdfc.RdfcDocumentCanonicalizer _production;

    public LenientRdfcCanonicalizer(CaveatTypeRegistry? caveats = null)
    {
        _loader = new RdfcContextDocumentLoader(caveats);
        _production = new DataProofsRdfc.RdfcDocumentCanonicalizer(_loader);
    }

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        var json = document as string ?? JsonSerializer.Serialize(document, ZcapJsonOptions.Default);
        var store = new TripleStore();
        new JsonLdParser(new JsonLdProcessorOptions { DocumentLoader = Load }).Load(store, new StringReader(json));

        // Lenient expansion above, production canonicalization below.
        var nquads = new System.IO.StringWriter();
        new NQuadsWriter(NQuadsSyntax.Rdf11).Save(store, nquads);
        return Encoding.UTF8.GetBytes(_production.CanonicalizeNQuads(nquads.ToString()));
    }

    private RemoteDocument Load(Uri uri, JsonLdLoaderOptions options)
    {
        var loaded = _loader.Load(uri);
        return new RemoteDocument { Document = JToken.Parse(loaded.Content), DocumentUrl = loaded.DocumentUrl };
    }
}
