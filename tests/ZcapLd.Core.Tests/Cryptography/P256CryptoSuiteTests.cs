using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class P256CryptoSuiteTests
{
    private readonly P256CryptoSuite _suite = new();

    [Fact]
    public void ProofType_ShouldBeEcdsaSecp256r1Signature2019()
    {
        _suite.ProofType.Should().Be("EcdsaSecp256r1Signature2019");
    }

    [Fact]
    public void KeyType_ShouldBeEcdsaSecp256r1VerificationKey2019()
    {
        _suite.KeyType.Should().Be("EcdsaSecp256r1VerificationKey2019");
    }

    [Fact]
    public void ContextUrl_ShouldBeEcdsa2019()
    {
        _suite.ContextUrl.Should().Be("https://w3id.org/security/suites/ecdsa-2019/v1");
    }

    [Fact]
    public void Sign_ShouldProduceValidSignature()
    {
        var (privateKey, publicKey) = P256CryptoSuite.GenerateKeyPair();
        var data = "test data for P-256"u8.ToArray();

        var signature = _suite.Sign(data, privateKey);

        signature.Should().HaveCount(64); // IEEE P1363: 32-byte r + 32-byte s
        _suite.Verify(data, signature, publicKey).Should().BeTrue();
    }

    [Fact]
    public void Verify_WithValidSignature_ShouldReturnTrue()
    {
        var (privateKey, publicKey) = P256CryptoSuite.GenerateKeyPair();
        var data = "verify this"u8.ToArray();
        var signature = _suite.Sign(data, privateKey);

        _suite.Verify(data, signature, publicKey).Should().BeTrue();
    }

    [Fact]
    public void Verify_WithInvalidSignature_ShouldReturnFalse()
    {
        var (_, publicKey) = P256CryptoSuite.GenerateKeyPair();
        var data = "test data"u8.ToArray();
        var badSignature = new byte[64];

        _suite.Verify(data, badSignature, publicKey).Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongKey_ShouldReturnFalse()
    {
        var (privateKey1, _) = P256CryptoSuite.GenerateKeyPair();
        var (_, publicKey2) = P256CryptoSuite.GenerateKeyPair();
        var data = "test data"u8.ToArray();
        var signature = _suite.Sign(data, privateKey1);

        _suite.Verify(data, signature, publicKey2).Should().BeFalse();
    }

    [Fact]
    public void GenerateKeyPair_ShouldProduceValidKeys()
    {
        var (privateKey, publicKey) = P256CryptoSuite.GenerateKeyPair();

        privateKey.Should().HaveCount(32);
        publicKey.Should().HaveCount(33);
        publicKey[0].Should().BeOneOf((byte)0x02, (byte)0x03); // compressed prefix
    }

    [Fact]
    public void Sign_WithInvalidPrivateKeyLength_ShouldThrow()
    {
        var data = "test"u8.ToArray();
        var badKey = new byte[16];

        var act = () => _suite.Sign(data, badKey);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Verify_WithInvalidPublicKeyLength_ShouldThrow()
    {
        var data = "test"u8.ToArray();
        var signature = new byte[64];
        var badKey = new byte[32]; // should be 33

        var act = () => _suite.Verify(data, signature, badKey);

        act.Should().Throw<ArgumentException>();
    }
}
