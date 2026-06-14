using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class CryptoSuiteTests
{
    private static readonly DefaultKeyGenerator KeyGen = new();

    #region Ed25519 Suite

    [Fact]
    public void Ed25519_ProofType_ShouldBeEd25519Signature2020()
    {
        CryptoSuite.Ed25519().ProofType.Should().Be("Ed25519Signature2020");
    }

    [Fact]
    public void Ed25519_KeyType_ShouldBeEd25519VerificationKey2020()
    {
        CryptoSuite.Ed25519().KeyType.Should().Be("Ed25519VerificationKey2020");
    }

    [Fact]
    public void Ed25519_ContextUrl_ShouldBeCorrect()
    {
        CryptoSuite.Ed25519().ContextUrl.Should().Be("https://w3id.org/security/suites/ed25519-2020/v1");
    }

    [Fact]
    public void Ed25519_Sign_ShouldProduceValidSignature()
    {
        var suite = CryptoSuite.Ed25519();
        var kp = KeyGen.Generate(KeyType.Ed25519);
        var data = "test data"u8.ToArray();

        var signature = suite.Sign(data, kp.PrivateKey);

        signature.Should().HaveCount(64);
        suite.Verify(data, signature, kp.PublicKey).Should().BeTrue();
    }

    [Fact]
    public void Ed25519_Verify_WithValidSignature_ShouldReturnTrue()
    {
        var suite = CryptoSuite.Ed25519();
        var kp = KeyGen.Generate(KeyType.Ed25519);
        var data = "test data"u8.ToArray();
        var signature = suite.Sign(data, kp.PrivateKey);

        suite.Verify(data, signature, kp.PublicKey).Should().BeTrue();
    }

    [Fact]
    public void Ed25519_Verify_WithInvalidSignature_ShouldReturnFalse()
    {
        var suite = CryptoSuite.Ed25519();
        var kp = KeyGen.Generate(KeyType.Ed25519);
        var data = "test data"u8.ToArray();
        var badSignature = new byte[64];

        suite.Verify(data, badSignature, kp.PublicKey).Should().BeFalse();
    }

    [Fact]
    public void Ed25519_Verify_WithWrongKey_ShouldReturnFalse()
    {
        var suite = CryptoSuite.Ed25519();
        var kp1 = KeyGen.Generate(KeyType.Ed25519);
        var kp2 = KeyGen.Generate(KeyType.Ed25519);
        var data = "test data"u8.ToArray();
        var signature = suite.Sign(data, kp1.PrivateKey);

        suite.Verify(data, signature, kp2.PublicKey).Should().BeFalse();
    }

    #endregion

    #region P-256 Suite

    [Fact]
    public void P256_ProofType_ShouldBeEcdsaSecp256r1Signature2019()
    {
        CryptoSuite.P256().ProofType.Should().Be("EcdsaSecp256r1Signature2019");
    }

    [Fact]
    public void P256_KeyType_ShouldBeEcdsaSecp256r1VerificationKey2019()
    {
        CryptoSuite.P256().KeyType.Should().Be("EcdsaSecp256r1VerificationKey2019");
    }

    [Fact]
    public void P256_ContextUrl_ShouldBeEcdsa2019()
    {
        CryptoSuite.P256().ContextUrl.Should().Be("https://w3id.org/security/suites/ecdsa-2019/v1");
    }

    [Fact]
    public void P256_Sign_ShouldProduceValidSignature()
    {
        var suite = CryptoSuite.P256();
        var kp = KeyGen.Generate(KeyType.P256);
        var data = "test data for P-256"u8.ToArray();

        var signature = suite.Sign(data, kp.PrivateKey);

        signature.Should().HaveCount(64); // IEEE P1363: 32-byte r + 32-byte s
        suite.Verify(data, signature, kp.PublicKey).Should().BeTrue();
    }

    [Fact]
    public void P256_Sign_ProducesIeeeP1363WireFormat_NotDer()
    {
        // Regression guard for the NetDid 1.3.0 trap: NetDid's *legacy* Sign overload defaults
        // P-256 to ASN.1 DER (~70-72 bytes, starts 0x30). The W3C ecdsa-2019 /
        // EcdsaSecp256r1Signature2019 wire format (and JOSE ES256) require IEEE P1363 fixed-width
        // r‖s = exactly 64 bytes for P-256. CryptoSuite must call NetDid's format-aware overload
        // with EcdsaSignatureFormat.IeeeP1363; if a future change reverts to the 3-arg overload,
        // signatures become DER and silently break cross-language verification — caught here by
        // the deterministic 64-byte length (DER is never 64 bytes for P-256).
        var suite = CryptoSuite.P256();
        var kp = KeyGen.Generate(KeyType.P256);
        var data = "ecdsa-2019 wire format compatibility"u8.ToArray();

        var signature = suite.Sign(data, kp.PrivateKey);

        signature.Length.Should().Be(64,
            "P-256 proofValue must be IEEE P1363 (32-byte r + 32-byte s), not ASN.1 DER");
        suite.Verify(data, signature, kp.PublicKey).Should().BeTrue();
    }

    [Fact]
    public void P256_Verify_WithValidSignature_ShouldReturnTrue()
    {
        var suite = CryptoSuite.P256();
        var kp = KeyGen.Generate(KeyType.P256);
        var data = "verify this"u8.ToArray();
        var signature = suite.Sign(data, kp.PrivateKey);

        suite.Verify(data, signature, kp.PublicKey).Should().BeTrue();
    }

    [Fact]
    public void P256_Verify_WithInvalidSignature_ShouldReturnFalse()
    {
        var suite = CryptoSuite.P256();
        var kp = KeyGen.Generate(KeyType.P256);
        var data = "test data"u8.ToArray();
        var badSignature = new byte[64];

        suite.Verify(data, badSignature, kp.PublicKey).Should().BeFalse();
    }

    [Fact]
    public void P256_Verify_WithWrongKey_ShouldReturnFalse()
    {
        var suite = CryptoSuite.P256();
        var kp1 = KeyGen.Generate(KeyType.P256);
        var kp2 = KeyGen.Generate(KeyType.P256);
        var data = "test data"u8.ToArray();
        var signature = suite.Sign(data, kp1.PrivateKey);

        suite.Verify(data, signature, kp2.PublicKey).Should().BeFalse();
    }

    [Fact]
    public void P256_GenerateKeyPair_ViaKeyGenerator_ShouldProduceValidKeys()
    {
        var kp = KeyGen.Generate(KeyType.P256);

        kp.PrivateKey.Should().HaveCount(32);
        kp.PublicKey.Should().HaveCount(33);
        kp.PublicKey[0].Should().BeOneOf((byte)0x02, (byte)0x03); // compressed prefix
    }

    #endregion

    #region Custom Suite Construction

    [Fact]
    public void Constructor_WithNullProofType_ShouldThrow()
    {
        var act = () => new CryptoSuite(null!, "key", "url", KeyType.Ed25519);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullKeyType_ShouldThrow()
    {
        var act = () => new CryptoSuite("proof", null!, "url", KeyType.Ed25519);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullContextUrl_ShouldThrow()
    {
        var act = () => new CryptoSuite("proof", "key", null!, KeyType.Ed25519);
        act.Should().Throw<ArgumentNullException>();
    }

    #endregion
}
