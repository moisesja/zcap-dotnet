using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class DocumentCanonicalizerProviderTests
{
    [Fact]
    public void GetByMethod_WithRegisteredJcs_ShouldReturnCanonicalizer()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new JcsDocumentCanonicalizer());

        var result = provider.GetByMethod("JCS");

        result.Should().NotBeNull();
        result!.Method.Should().Be("JCS");
    }

    [Fact]
    public void GetByMethod_WithRegisteredRdfc_ShouldReturnCanonicalizer()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new RdfcDocumentCanonicalizer());

        var result = provider.GetByMethod("RDFC-1.0");

        result.Should().NotBeNull();
        result!.Method.Should().Be("RDFC-1.0");
    }

    [Fact]
    public void GetByMethod_WithUnknownMethod_ShouldReturnNull()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new JcsDocumentCanonicalizer());

        var result = provider.GetByMethod("UNKNOWN");

        result.Should().BeNull();
    }

    [Fact]
    public void GetByMethod_WithNullOrEmpty_ShouldReturnNull()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new JcsDocumentCanonicalizer());

        provider.GetByMethod(null!).Should().BeNull();
        provider.GetByMethod("").Should().BeNull();
    }

    [Fact]
    public void Register_WithNull_ShouldThrow()
    {
        var provider = new DocumentCanonicalizerProvider();

        var act = () => provider.Register(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Register_ShouldReplaceDuplicateMethod()
    {
        var provider = new DocumentCanonicalizerProvider();
        var first = new JcsDocumentCanonicalizer();
        var second = new JcsDocumentCanonicalizer();

        provider.Register(first);
        provider.Register(second);

        // Should not throw, second replaces first
        provider.GetByMethod("JCS").Should().BeSameAs(second);
    }

    [Fact]
    public void MultipleCanonicalizers_ShouldBeRegisteredIndependently()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new JcsDocumentCanonicalizer());
        provider.Register(new RdfcDocumentCanonicalizer());

        provider.GetByMethod("JCS").Should().NotBeNull();
        provider.GetByMethod("RDFC-1.0").Should().NotBeNull();
    }
}
