using System.Text;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class RdfcDocumentCanonicalizerTests
{
    private readonly RdfcDocumentCanonicalizer _canonicalizer = new();

    [Fact]
    public void Method_ShouldReturnRdfc10()
    {
        _canonicalizer.Method.Should().Be("RDFC-1.0");
    }

    [Fact]
    public void Canonicalize_WithJsonLdDocument_ShouldProduceNQuads()
    {
        // A minimal JSON-LD document with a known context
        var jsonLd = new Dictionary<string, object>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["id"] = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            ["controller"] = "did:key:example",
            ["invocationTarget"] = "https://example.com/foo"
        };

        var result = _canonicalizer.Canonicalize(jsonLd);

        result.Should().NotBeNull();
        result.Length.Should().BeGreaterThan(0);

        // N-Quads output should be UTF-8 text
        var nquads = Encoding.UTF8.GetString(result);
        nquads.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Canonicalize_ShouldProduceDeterministicOutput()
    {
        var jsonLd = new Dictionary<string, object>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["id"] = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            ["controller"] = "did:key:example",
            ["invocationTarget"] = "https://example.com/foo"
        };

        var result1 = _canonicalizer.Canonicalize(jsonLd);
        var result2 = _canonicalizer.Canonicalize(jsonLd);

        result1.Should().Equal(result2);
    }

    [Fact]
    public void Canonicalize_WithDifferentPropertyOrder_ShouldProduceSameOutput()
    {
        var json1 = """{"@context":"https://w3id.org/zcap/v1","id":"urn:test","controller":"did:key:ex"}""";
        var json2 = """{"controller":"did:key:ex","@context":"https://w3id.org/zcap/v1","id":"urn:test"}""";

        var result1 = _canonicalizer.Canonicalize(json1);
        var result2 = _canonicalizer.Canonicalize(json2);

        result1.Should().Equal(result2);
    }

    [Fact]
    public void Canonicalize_WithNullDocument_ShouldThrow()
    {
        var act = () => _canonicalizer.Canonicalize(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Canonicalize_WithStringInput_ShouldWork()
    {
        var jsonLd = """{"@context":"https://w3id.org/zcap/v1","id":"urn:test","controller":"did:key:ex"}""";

        var result = _canonicalizer.Canonicalize(jsonLd);

        result.Should().NotBeNull();
        result.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Canonicalize_DiffersFromJcs()
    {
        // Same document should produce different canonical forms for JCS vs RDFC-1.0
        var jsonLd = new Dictionary<string, object>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["id"] = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            ["controller"] = "did:key:example",
            ["invocationTarget"] = "https://example.com/foo"
        };

        var rdfcResult = _canonicalizer.Canonicalize(jsonLd);
        var jcsResult = new JcsDocumentCanonicalizer().Canonicalize(jsonLd);

        // RDFC-1.0 produces N-Quads, JCS produces compact JSON — they should differ
        rdfcResult.Should().NotEqual(jcsResult);
    }
}
