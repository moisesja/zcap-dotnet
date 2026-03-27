using System.Text;
using FluentAssertions;
using VDS.RDF;
using VDS.RDF.Parsing;
using Xunit;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Smoke tests using official W3C RDFC-1.0 test vectors to verify that
/// dotNetRdf's RdfCanonicalizer produces correct output.
/// Source: https://w3c.github.io/rdf-canon/tests/
/// </summary>
public class RdfcComplianceTests
{
    /// <summary>
    /// Runs the RDFC-1.0 canonicalization algorithm on N-Quads input
    /// and returns the canonical N-Quads output.
    /// </summary>
    private static string Canonicalize(string inputNQuads)
    {
        var store = new TripleStore();
        var parser = new NQuadsParser();
        parser.Load(store, new StringReader(inputNQuads));

        var canonicalizer = new RdfCanonicalizer();
        var result = canonicalizer.Canonicalize(store);
        return result.SerializedNQuads;
    }

    [Fact]
    public void W3C_Test002_DuplicatePropertyIriValues()
    {
        // https://w3c.github.io/rdf-canon/tests/#test002
        // No blank nodes — output should match input (already canonical)
        const string input =
            """<http://example.org/test#example1> <http://example.org/vocab#p> <http://example.org/test#example2> .""" + "\n";

        const string expected =
            """<http://example.org/test#example1> <http://example.org/vocab#p> <http://example.org/test#example2> .""" + "\n";

        Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void W3C_Test003_BlankNode()
    {
        // https://w3c.github.io/rdf-canon/tests/#test003
        // Single blank node — should be renamed to _:c14n0
        const string input =
            """_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Foo> .""" + "\n";

        const string expected =
            """_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Foo> .""" + "\n";

        Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void W3C_Test006_MultipleRdfTypes()
    {
        // https://w3c.github.io/rdf-canon/tests/#test006
        // Two type triples — canonical output sorts lexicographically
        const string input =
            """<http://example.org/test#example> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Foo> .""" + "\n" +
            """<http://example.org/test#example> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Bar> .""" + "\n";

        const string expected =
            """<http://example.org/test#example> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Bar> .""" + "\n" +
            """<http://example.org/test#example> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Foo> .""" + "\n";

        Canonicalize(input).Should().Be(expected);
    }

    [Fact]
    public void W3C_EmptyInput_ProducesEmptyOutput()
    {
        // Empty dataset should produce empty canonical output
        Canonicalize("").Should().BeEmpty();
    }
}
