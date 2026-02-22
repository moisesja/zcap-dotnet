using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class Ed25519SignerTests
{
    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        // Act
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();

        // Assert
        privateKey.Should().NotBeNull();
        publicKey.Should().NotBeNull();
        privateKey.Length.Should().Be(32); // Ed25519 private key is 32 bytes
        publicKey.Length.Should().Be(32);  // Ed25519 public key is 32 bytes
    }

    [Fact]
    public void GetPublicKey_ShouldExtractCorrectPublicKey()
    {
        // Arrange
        var (privateKey, expectedPublicKey) = Ed25519Signer.GenerateKeyPair();

        // Act
        var actualPublicKey = Ed25519Signer.GetPublicKey(privateKey);

        // Assert
        actualPublicKey.Should().Equal(expectedPublicKey);
    }

    [Fact]
    public void Sign_ShouldCreateValidSignature()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message for signing");

        // Act
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Assert
        signature.Should().NotBeNull();
        signature.Length.Should().Be(64); // Ed25519 signature is 64 bytes

        // Verify the signature is valid
        var isValid = Ed25519Signer.Verify(data, signature, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WithValidSignature_ShouldReturnTrue()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message");
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Act
        var isValid = Ed25519Signer.Verify(data, signature, publicKey);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WithInvalidSignature_ShouldReturnFalse()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message");
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Corrupt the signature
        signature[0] ^= 0xFF;

        // Act
        var isValid = Ed25519Signer.Verify(data, signature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongData_ShouldReturnFalse()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Original message");
        var signature = Ed25519Signer.Sign(data, privateKey);
        var wrongData = System.Text.Encoding.UTF8.GetBytes("Different message");

        // Act
        var isValid = Ed25519Signer.Verify(wrongData, signature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongPublicKey_ShouldReturnFalse()
    {
        // Arrange
        var (privateKey1, _) = Ed25519Signer.GenerateKeyPair();
        var (_, publicKey2) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message");
        var signature = Ed25519Signer.Sign(data, privateKey1);

        // Act
        var isValid = Ed25519Signer.Verify(data, signature, publicKey2);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public void EncodeSignature_ShouldReturnMultibaseString()
    {
        // Arrange
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message");
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Act
        var encoded = MultibaseCodec.Encode(signature);

        // Assert
        encoded.Should().NotBeNullOrEmpty();
        encoded.Should().StartWith("z"); // multibase base58-btc prefix
        encoded.Length.Should().BeGreaterThan(64); // base58 encoding increases length
    }

    [Fact]
    public void DecodeSignature_ShouldReturnOriginalBytes()
    {
        // Arrange
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message");
        var originalSignature = Ed25519Signer.Sign(data, privateKey);
        var encoded = MultibaseCodec.Encode(originalSignature);

        // Act
        var decoded = MultibaseCodec.Decode(encoded);

        // Assert
        decoded.Should().Equal(originalSignature);
    }

    [Fact]
    public void EncodeAndDecodeSignature_ShouldRoundTrip()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("Test message for round trip");
        var signature = Ed25519Signer.Sign(data, privateKey);

        // Act
        var encoded = MultibaseCodec.Encode(signature);
        var decoded = MultibaseCodec.Decode(encoded);

        // Assert
        decoded.Should().Equal(signature);

        // Verify decoded signature still works
        var isValid = Ed25519Signer.Verify(data, decoded, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void DecodeSignature_WithInvalidPrefix_ShouldThrowException()
    {
        // Arrange
        var invalidEncoded = "a1234567890"; // Wrong prefix (should be 'z')

        // Act & Assert
        var act = () => MultibaseCodec.Decode(invalidEncoded);
        act.Should().Throw<ZcapLd.Core.Exceptions.CryptographicException>();
    }

    [Fact]
    public void CanonicalizeDocument_ShouldProduceDeterministicOutput()
    {
        // Arrange
        var document = new
        {
            id = "urn:uuid:test",
            controller = "did:key:example",
            invocationTarget = "https://example.com/foo"
        };

        // Act
        var canonical1 = MultibaseCodec.CanonicalizeDocument(document);
        var canonical2 = MultibaseCodec.CanonicalizeDocument(document);

        // Assert
        canonical1.Should().Equal(canonical2);
    }

    [Fact]
    public void CanonicalizeDocument_WithDifferentPropertyOrder_ShouldProduceSameOutput()
    {
        // Note: This test validates that property order doesn't matter
        // However, C# anonymous objects maintain declaration order
        // So we test by serializing and deserializing with different orders

        var json1 = """{"id":"urn:uuid:test","controller":"did:key:example","invocationTarget":"https://example.com/foo"}""";
        var json2 = """{"controller":"did:key:example","invocationTarget":"https://example.com/foo","id":"urn:uuid:test"}""";

        // Act
        var canonical1 = JsonCanonicalizer.CanonicalizeString(json1);
        var canonical2 = JsonCanonicalizer.CanonicalizeString(json2);

        // Assert - should be equal after canonicalization (sorted keys)
        canonical1.Should().Equal(canonical2);
    }

    [Fact]
    public void SignJson_ShouldCreateValidSignature()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var document = new
        {
            id = "urn:uuid:test",
            controller = "did:key:example",
            invocationTarget = "https://example.com/foo"
        };

        // Act
        var signature = Ed25519Signer.SignJson(document, privateKey);

        // Assert
        signature.Should().NotBeNullOrEmpty();
        signature.Should().StartWith("z");

        // Verify the signature
        var isValid = Ed25519Signer.VerifyJson(document, signature, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyJson_WithValidSignature_ShouldReturnTrue()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var document = new
        {
            type = "TestDocument",
            value = 123,
            nested = new { property = "value" }
        };
        var signature = Ed25519Signer.SignJson(document, privateKey);

        // Act
        var isValid = Ed25519Signer.VerifyJson(document, signature, publicKey);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyJson_WithModifiedDocument_ShouldReturnFalse()
    {
        // Arrange
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var originalDocument = new
        {
            id = "urn:uuid:original",
            controller = "did:key:example"
        };
        var signature = Ed25519Signer.SignJson(originalDocument, privateKey);

        var modifiedDocument = new
        {
            id = "urn:uuid:modified",
            controller = "did:key:example"
        };

        // Act
        var isValid = Ed25519Signer.VerifyJson(modifiedDocument, signature, publicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Sign_WithNullData_ShouldThrowException()
    {
        // Arrange
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();

        // Act & Assert
        var act = () => Ed25519Signer.Sign(null!, privateKey);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Sign_WithEmptyData_ShouldThrowException()
    {
        // Arrange
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();

        // Act & Assert
        var act = () => Ed25519Signer.Sign(Array.Empty<byte>(), privateKey);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Sign_WithInvalidKeyLength_ShouldThrowException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Wrong size
        var data = System.Text.Encoding.UTF8.GetBytes("test");

        // Act & Assert
        var act = () => Ed25519Signer.Sign(data, invalidKey);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Verify_WithInvalidPublicKeyLength_ShouldThrowException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Wrong size
        var data = System.Text.Encoding.UTF8.GetBytes("test");
        var signature = new byte[64];

        // Act & Assert
        var act = () => Ed25519Signer.Verify(data, signature, invalidKey);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Verify_WithInvalidSignatureLength_ShouldThrowException()
    {
        // Arrange
        var (_, publicKey) = Ed25519Signer.GenerateKeyPair();
        var data = System.Text.Encoding.UTF8.GetBytes("test");
        var invalidSignature = new byte[32]; // Wrong size

        // Act & Assert
        var act = () => Ed25519Signer.Verify(data, invalidSignature, publicKey);
        act.Should().Throw<ArgumentException>();
    }
}
