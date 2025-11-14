using System;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Tests.Cryptography;

public class Ed25519CryptographicServiceTests
{
    private readonly Ed25519CryptographicService _service;

    public Ed25519CryptographicServiceTests()
    {
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<Ed25519CryptographicService>();
        _service = new Ed25519CryptographicService(logger);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act
        var act = () => new Ed25519CryptographicService(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void SignatureAlgorithm_ShouldReturnEd25519Signature2020()
    {
        // Act
        var algorithm = _service.SignatureAlgorithm;

        // Assert
        algorithm.Should().Be("Ed25519Signature2020");
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldGenerateValidKeyPair()
    {
        // Act
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();

        // Assert
        publicKey.Should().NotBeNull();
        publicKey.Should().HaveCount(32);
        privateKey.Should().NotBeNull();
        privateKey.Should().HaveCount(32);
    }

    [Fact]
    public async Task SignAsync_ShouldGenerateValidSignature()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data to sign");

        // Act
        var signature = await _service.SignAsync(data, privateKey);

        // Assert
        signature.Should().NotBeNull();
        signature.Should().HaveCount(64); // Ed25519 signatures are 64 bytes
    }

    [Fact]
    public async Task SignAsync_ShouldThrowArgumentNullException_WhenDataIsNull()
    {
        // Arrange
        var (_, privateKey) = await _service.GenerateKeyPairAsync();

        // Act
        var act = async () => await _service.SignAsync(null!, privateKey);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("data");
    }

    [Fact]
    public async Task SignAsync_ShouldThrowArgumentNullException_WhenPrivateKeyIsNull()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");

        // Act
        var act = async () => await _service.SignAsync(data, null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("privateKey");
    }

    [Fact]
    public async Task SignAsync_ShouldThrowArgumentException_WhenPrivateKeyHasInvalidLength()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        var invalidPrivateKey = new byte[16]; // Wrong length

        // Act
        var act = async () => await _service.SignAsync(data, invalidPrivateKey);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("privateKey")
            .WithMessage("*32 bytes*");
    }

    [Fact]
    public async Task SignAsync_WithKeyPair_ShouldGenerateValidSignature()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "test-key", "did:example:123#key-1");
        var data = Encoding.UTF8.GetBytes("Test data to sign");

        // Act
        var signature = await _service.SignAsync(data, keyPair);

        // Assert
        signature.Should().NotBeNull();
        signature.Should().HaveCount(64);
    }

    [Fact]
    public async Task SignAsync_WithKeyPair_ShouldThrowArgumentNullException_WhenKeyPairIsNull()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");

        // Act
        var act = async () => await _service.SignAsync(data, (KeyPair)null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyPair");
    }

    [Fact]
    public async Task VerifyAsync_ShouldReturnTrue_WhenSignatureIsValid()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data to sign");
        var signature = await _service.SignAsync(data, privateKey);

        // Act
        var isValid = await _service.VerifyAsync(data, signature, publicKey);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAsync_ShouldReturnFalse_WhenSignatureIsInvalid()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data to sign");
        var signature = await _service.SignAsync(data, privateKey);

        // Tamper with the signature
        signature[0] ^= 0xFF;

        // Act
        var isValid = await _service.VerifyAsync(data, signature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_ShouldReturnFalse_WhenDataIsDifferent()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var originalData = Encoding.UTF8.GetBytes("Original data");
        var signature = await _service.SignAsync(originalData, privateKey);
        var differentData = Encoding.UTF8.GetBytes("Different data");

        // Act
        var isValid = await _service.VerifyAsync(differentData, signature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_ShouldReturnFalse_WhenSignatureHasWrongLength()
    {
        // Arrange
        var (publicKey, _) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data");
        var invalidSignature = new byte[32]; // Wrong length

        // Act
        var isValid = await _service.VerifyAsync(data, invalidSignature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_ShouldThrowArgumentNullException_WhenDataIsNull()
    {
        // Arrange
        var (publicKey, _) = await _service.GenerateKeyPairAsync();
        var signature = new byte[64];

        // Act
        var act = async () => await _service.VerifyAsync(null!, signature, publicKey);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("data");
    }

    [Fact]
    public async Task VerifyAsync_ShouldThrowArgumentNullException_WhenSignatureIsNull()
    {
        // Arrange
        var (publicKey, _) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data");

        // Act
        var act = async () => await _service.VerifyAsync(data, null!, publicKey);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("signature");
    }

    [Fact]
    public async Task VerifyAsync_ShouldThrowArgumentNullException_WhenPublicKeyIsNull()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        var signature = new byte[64];

        // Act
        var act = async () => await _service.VerifyAsync(data, signature, (byte[])null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public async Task VerifyAsync_ShouldThrowArgumentException_WhenPublicKeyHasInvalidLength()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        var signature = new byte[64];
        var invalidPublicKey = new byte[16]; // Wrong length

        // Act
        var act = async () => await _service.VerifyAsync(data, signature, invalidPublicKey);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("publicKey")
            .WithMessage("*32 bytes*");
    }

    [Fact]
    public async Task VerifyAsync_WithPublicKey_ShouldReturnTrue_WhenSignatureIsValid()
    {
        // Arrange
        var (publicKeyBytes, privateKey) = await _service.GenerateKeyPairAsync();
        var publicKey = new PublicKey(publicKeyBytes, "test-key", "did:example:123#key-1");
        var data = Encoding.UTF8.GetBytes("Test data to sign");
        var signature = await _service.SignAsync(data, privateKey);

        // Act
        var isValid = await _service.VerifyAsync(data, signature, publicKey);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAsync_WithPublicKey_ShouldThrowArgumentNullException_WhenPublicKeyIsNull()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        var signature = new byte[64];

        // Act
        var act = async () => await _service.VerifyAsync(data, signature, (PublicKey)null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public async Task SignAndVerify_ShouldWorkEndToEnd()
    {
        // Arrange
        var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet");

        // Act - Sign
        var signature = await _service.SignAsync(data, privateKey);

        // Act - Verify
        var isValid = await _service.VerifyAsync(data, signature, publicKey);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldGenerateUniqueKeys()
    {
        // Act
        var (publicKey1, privateKey1) = await _service.GenerateKeyPairAsync();
        var (publicKey2, privateKey2) = await _service.GenerateKeyPairAsync();

        // Assert
        publicKey1.Should().NotBeEquivalentTo(publicKey2);
        privateKey1.Should().NotBeEquivalentTo(privateKey2);
    }

    [Fact]
    public async Task SignAsync_WithDifferentPrivateKeys_ShouldProduceDifferentSignatures()
    {
        // Arrange
        var (_, privateKey1) = await _service.GenerateKeyPairAsync();
        var (_, privateKey2) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Same data");

        // Act
        var signature1 = await _service.SignAsync(data, privateKey1);
        var signature2 = await _service.SignAsync(data, privateKey2);

        // Assert
        signature1.Should().NotBeEquivalentTo(signature2);
    }

    [Fact]
    public async Task SignAsync_WithSameKey_ShouldProduceSameSignature()
    {
        // Arrange
        var (_, privateKey) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Same data");

        // Act
        var signature1 = await _service.SignAsync(data, privateKey);
        var signature2 = await _service.SignAsync(data, privateKey);

        // Assert
        signature1.Should().BeEquivalentTo(signature2);
    }

    [Fact]
    public async Task VerifyAsync_WithWrongPublicKey_ShouldReturnFalse()
    {
        // Arrange
        var (publicKey1, privateKey1) = await _service.GenerateKeyPairAsync();
        var (publicKey2, _) = await _service.GenerateKeyPairAsync();
        var data = Encoding.UTF8.GetBytes("Test data");
        var signature = await _service.SignAsync(data, privateKey1);

        // Act - Verify with wrong public key
        var isValid = await _service.VerifyAsync(data, signature, publicKey2);

        // Assert
        isValid.Should().BeFalse();
    }
}
