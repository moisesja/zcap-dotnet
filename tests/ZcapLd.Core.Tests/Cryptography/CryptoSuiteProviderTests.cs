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
        var suite = new Ed25519CryptoSuite();
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
    public void GetByMulticodecPrefix_WhenRegistered_ShouldReturnSuite()
    {
        // Arrange
        var suite = new Ed25519CryptoSuite();
        _provider.Register(suite);
        byte[] data = [0xed, 0x01, 0x00, 0x00]; // Ed25519 prefix + extra bytes

        // Act
        var result = _provider.GetByMulticodecPrefix(data);

        // Assert
        result.Should().NotBeNull();
        result.Should().BeSameAs(suite);
    }

    [Fact]
    public void GetByMulticodecPrefix_WhenNotRegistered_ShouldReturnNull()
    {
        // Arrange
        _provider.Register(new Ed25519CryptoSuite());
        byte[] unknownPrefix = [0x80, 0x24, 0x00]; // P-256 prefix, not registered

        // Act
        var result = _provider.GetByMulticodecPrefix(unknownPrefix);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetByMulticodecPrefix_WithShortData_ShouldReturnNull()
    {
        // Arrange
        _provider.Register(new Ed25519CryptoSuite());
        byte[] tooShort = [0xed]; // Only one byte, prefix is 2 bytes

        // Act
        var result = _provider.GetByMulticodecPrefix(tooShort);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Register_ShouldReplaceDuplicateProofType()
    {
        // Arrange
        var suite1 = new Ed25519CryptoSuite();
        var suite2 = new Ed25519CryptoSuite();
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
