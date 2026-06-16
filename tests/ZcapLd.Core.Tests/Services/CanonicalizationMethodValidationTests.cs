using FluentAssertions;
using Xunit;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// The constructors validate <c>canonicalizationMethod</c> (review feedback on PR #109). Without
/// this, a typo like <c>"rdfc-1.0"</c> silently falls through to JCS in the legacy-suite resolver
/// and the consumer signs/verifies with the wrong algorithm. The constructors must fail fast.
/// </summary>
public class CanonicalizationMethodValidationTests
{
    private readonly InMemoryDidProvider _did = new();
    private readonly CaveatProcessor _caveat = new();

    [Theory]
    [InlineData("JCS")]
    [InlineData("RDFC-1.0")]
    public void Constructors_AcceptSupportedMethods(string method)
    {
        var signing = () => new SigningService(_did, _did, method);
        var verifying = () => new VerificationService(
            _did, _caveat, new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), canonicalizationMethod: method);

        signing.Should().NotThrow();
        verifying.Should().NotThrow();
    }

    [Theory]
    [InlineData("rdfc-1.0")]  // wrong case — the bug the reviewer flagged
    [InlineData("jcs")]
    [InlineData("RDFC")]
    [InlineData("URDNA2015")]
    [InlineData("")]
    public void Constructors_RejectUnsupportedMethods(string method)
    {
        var signing = () => new SigningService(_did, _did, method);
        var verifying = () => new VerificationService(
            _did, _caveat, new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), canonicalizationMethod: method);

        signing.Should().Throw<ArgumentException>().WithParameterName("canonicalizationMethod");
        verifying.Should().Throw<ArgumentException>().WithParameterName("canonicalizationMethod");
    }

    [Fact]
    public void SigningService_RejectsNullMethod()
    {
        var act = () => new SigningService(_did, _did, null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("canonicalizationMethod");
    }

    [Fact]
    public void VerificationService_NullMethodDefaultsToJcs()
    {
        // The full ctor's canonicalizationMethod is optional; null means "use the JCS default".
        var act = () => new VerificationService(
            _did, _caveat, new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), canonicalizationMethod: null);
        act.Should().NotThrow();
    }
}
