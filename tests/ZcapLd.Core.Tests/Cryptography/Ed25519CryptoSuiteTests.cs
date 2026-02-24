using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class Ed25519CryptoSuiteTests
{
    private readonly Ed25519CryptoSuite _suite = new();

    [Fact]
    public void ProofType_ShouldBeEd25519Signature2020()
    {
        _suite.ProofType.Should().Be("Ed25519Signature2020");
    }

    [Fact]
    public void KeyType_ShouldBeEd25519VerificationKey2020()
    {
        _suite.KeyType.Should().Be("Ed25519VerificationKey2020");
    }

    [Fact]
    public void MulticodecPrefix_ShouldBeEd25519Prefix()
    {
        _suite.MulticodecPrefix.Should().Equal([0xed, 0x01]);
    }

    [Fact]
    public void PublicKeyLength_ShouldBe32()
    {
        _suite.PublicKeyLength.Should().Be(32);
    }

    [Fact]
    public void Sign_ShouldDelegateToEd25519Signer()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = "test data"u8.ToArray();

        // Act
        var signature = _suite.Sign(data, privateKey);

        // Assert
        signature.Should().HaveCount(64);
        _suite.Verify(data, signature, publicKey).Should().BeTrue();
    }

    [Fact]
    public void Verify_WithValidSignature_ShouldReturnTrue()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = "test data"u8.ToArray();
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Act & Assert
        _suite.Verify(data, signature, publicKey).Should().BeTrue();
    }

    [Fact]
    public void Verify_WithInvalidSignature_ShouldReturnFalse()
    {
        // Arrange
        var (_, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = "test data"u8.ToArray();
        var badSignature = new byte[64]; // All zeros

        // Act & Assert
        _suite.Verify(data, badSignature, publicKey).Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongKey_ShouldReturnFalse()
    {
        // Arrange
        var (privateKey1, _) = Ed25519Signer.GenerateKeyPair();
        var (_, publicKey2) = Ed25519Signer.GenerateKeyPair();
        var data = "test data"u8.ToArray();
        var signature = Ed25519Signer.Sign(data, privateKey1);

        // Act & Assert
        _suite.Verify(data, signature, publicKey2).Should().BeFalse();
    }
}
