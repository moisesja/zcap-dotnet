using System.Text;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class JcsDocumentCanonicalizerTests
{
    private readonly JcsDocumentCanonicalizer _canonicalizer = new();

    [Fact]
    public void Method_ShouldReturnJCS()
    {
        _canonicalizer.Method.Should().Be("JCS");
    }

    [Fact]
    public void Canonicalize_ShouldProduceDeterministicOutput()
    {
        var document = new
        {
            id = "urn:uuid:test",
            controller = "did:key:example",
            invocationTarget = "https://example.com/foo"
        };

        var result1 = _canonicalizer.Canonicalize(document);
        var result2 = _canonicalizer.Canonicalize(document);

        result1.Should().Equal(result2);
    }

    [Fact]
    public void Canonicalize_ShouldSortPropertiesAlphabetically()
    {
        var document = new
        {
            zzz = "last",
            aaa = "first",
            mmm = "middle"
        };

        var result = Encoding.UTF8.GetString(_canonicalizer.Canonicalize(document));

        var indexA = result.IndexOf("\"aaa\"");
        var indexM = result.IndexOf("\"mmm\"");
        var indexZ = result.IndexOf("\"zzz\"");

        indexA.Should().BeLessThan(indexM);
        indexM.Should().BeLessThan(indexZ);
    }

    [Fact]
    public void Canonicalize_ShouldDelegateToJsonCanonicalizer()
    {
        var document = new { test = "value" };

        var fromCanonicalizer = _canonicalizer.Canonicalize(document);
        var fromStatic = JsonCanonicalizer.Canonicalize(document);

        fromCanonicalizer.Should().Equal(fromStatic);
    }

    [Fact]
    public void Canonicalize_WithNullDocument_ShouldThrow()
    {
        var act = () => _canonicalizer.Canonicalize(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
