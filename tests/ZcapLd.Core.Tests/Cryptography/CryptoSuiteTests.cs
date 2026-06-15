using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// As of Stage C (#108) <see cref="ICryptoSuite"/> is a metadata record (proof type, key type,
/// context URL, canonicalization method); the actual sign/verify crypto is delegated to DataProofs'
/// legacy cryptosuites and exercised end-to-end by the Compliance golden vectors + integration
/// round-trips. These tests therefore cover only the suite metadata and construction guards.
/// </summary>
public class CryptoSuiteTests
{
    #region Ed25519 Suite metadata

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
    public void Ed25519_CanonicalizationMethod_DefaultsToJcs()
    {
        // CanonicalizationMethod is a default interface member — access via the interface.
        ((ICryptoSuite)CryptoSuite.Ed25519()).CanonicalizationMethod.Should().Be("JCS");
    }

    #endregion

    #region P-256 Suite metadata

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
    public void P256_GenerateKeyPair_ViaKeyGenerator_ShouldProduceValidKeys()
    {
        var kp = new DefaultKeyGenerator().Generate(KeyType.P256);

        kp.PrivateKey.Should().HaveCount(32);
        kp.PublicKey.Should().HaveCount(33);
        kp.PublicKey[0].Should().BeOneOf((byte)0x02, (byte)0x03); // compressed prefix
    }

    #endregion

    #region Custom Suite Construction

    [Fact]
    public void Constructor_WithNullProofType_ShouldThrow()
    {
        var act = () => new CryptoSuite(null!, "key", "url");
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullKeyType_ShouldThrow()
    {
        var act = () => new CryptoSuite("proof", null!, "url");
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullContextUrl_ShouldThrow()
    {
        var act = () => new CryptoSuite("proof", "key", null!);
        act.Should().Throw<ArgumentNullException>();
    }

    #endregion
}
