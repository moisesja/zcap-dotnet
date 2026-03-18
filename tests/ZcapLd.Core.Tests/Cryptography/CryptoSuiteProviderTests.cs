using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class CryptoSuiteProviderTests
{
    private readonly CryptoSuiteProvider _provider = new();

    [Fact]
    public void GetByProofType_WhenRegistered_ShouldReturnSuite()
    {
        // Arrange
        var suite = CryptoSuite.Ed25519();
        _provider.Register(suite);

        // Act
        var result = _provider.GetByProofType("Ed25519Signature2020");

        // Assert
        result.Should().NotBeNull();
        result.Should().BeSameAs(suite);
    }

    [Fact]
    public void GetByProofType_WhenNotRegistered_ShouldReturnNull()
    {
        // Act
        var result = _provider.GetByProofType("UnknownProofType");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetByProofType_WithNullOrEmpty_ShouldReturnNull()
    {
        _provider.GetByProofType(null!).Should().BeNull();
        _provider.GetByProofType("").Should().BeNull();
    }

    [Fact]
    public void Register_ShouldReplaceDuplicateProofType()
    {
        // Arrange
        var suite1 = CryptoSuite.Ed25519();
        var suite2 = CryptoSuite.Ed25519();
        _provider.Register(suite1);

        // Act
        _provider.Register(suite2);

        // Assert — second registration wins
        var result = _provider.GetByProofType("Ed25519Signature2020");
        result.Should().BeSameAs(suite2);
    }

    [Fact]
    public void Register_WithNull_ShouldThrow()
    {
        var act = () => _provider.Register(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
