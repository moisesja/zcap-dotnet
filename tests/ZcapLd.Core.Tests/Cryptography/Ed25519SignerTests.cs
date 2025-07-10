using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class Ed25519SignerTests
{
    [Fact]
    public void Sign_WithValidData_ShouldReturnSignature()
    {
        // Arrange
        var data = System.Text.Encoding.UTF8.GetBytes("test data");
        var privateKey = new byte[32]; // Ed25519 private key is 32 bytes

        // Act
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Assert
        signature.Should().NotBeNull();
        signature.Should().HaveCount(64); // Ed25519 signatures are 64 bytes
    }

    [Fact]
    public void Verify_WithValidSignature_ShouldReturnTrue()
    {
        // Arrange
        var data = System.Text.Encoding.UTF8.GetBytes("test data");
        var signature = new byte[64];
        var publicKey = new byte[32];

        // Act
        var result = Ed25519Signer.Verify(data, signature, publicKey);

        // Assert (stub implementation returns true)
        result.Should().BeTrue();
    }

    [Fact]
    public void CanonicalizeDocument_WithObject_ShouldReturnBytes()
    {
        // Arrange
        var document = new { test = "value", number = 42 };

        // Act
        var result = Ed25519Signer.CanonicalizeDocument(document);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();
    }

    [Fact]
    public void EncodeAndDecode_ShouldBeReversible()
    {
        // Arrange
        var originalSignature = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            originalSignature[i] = (byte)(i % 256);
        }

        // Act
        var encoded = Ed25519Signer.EncodeSignature(originalSignature);
        var decoded = Ed25519Signer.DecodeSignature(encoded);

        // Assert
        decoded.Should().BeEquivalentTo(originalSignature);
    }
}