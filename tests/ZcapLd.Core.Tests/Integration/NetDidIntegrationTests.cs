using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Method.Key;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Services;
using Xunit;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// Integration tests verifying the DidKeyResolver adapter correctly
/// delegates to NetDid's DidKeyMethod for did:key resolution.
/// </summary>
public class NetDidIntegrationTests
{
    private readonly DidKeyResolver _resolver = new();
    private readonly DefaultKeyGenerator _keyGen = new();

    #region Ed25519 Resolution

    [Fact]
    public async Task ResolvePublicKeyAsync_Ed25519_ShouldReturnCorrectKeyTypeAndBytes()
    {
        // Arrange
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        // Act
        var resolved = await _resolver.ResolvePublicKeyAsync(did);

        // Assert
        resolved.KeyType.Should().Be("Ed25519VerificationKey2020");
        resolved.PublicKeyBytes.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_Ed25519_WithVerificationMethodFragment_ShouldResolve()
    {
        // Arrange
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        var verificationMethod = $"{did}#{keyPair.MultibasePublicKey}";

        // Act
        var resolved = await _resolver.ResolvePublicKeyAsync(verificationMethod);

        // Assert
        resolved.KeyType.Should().Be("Ed25519VerificationKey2020");
        resolved.PublicKeyBytes.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_X25519KeyAgreementFragment_ReturnsX25519KeyNotEd25519()
    {
        // Issue #67: an Ed25519 did:key resolves to two verification methods — the Ed25519
        // signing key and a derived X25519 key-agreement key. Resolving a specific method by
        // #fragment must return THAT method's key, not always the first one.
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        var didKeyMethod = new DidKeyMethod(new DefaultKeyGenerator());
        var doc = await didKeyMethod.ResolveAsync(did);
        var vms = doc.DidDocument!.VerificationMethod!;
        vms.Count.Should().BeGreaterThanOrEqualTo(2,
            "an Ed25519 did:key derives an X25519 key-agreement verification method");

        var first = await _resolver.ResolvePublicKeyAsync(vms[0].Id);
        var second = await _resolver.ResolvePublicKeyAsync(vms[1].Id);

        first.KeyType.Should().Be("Ed25519VerificationKey2020");
        second.KeyType.Should().Be("X25519KeyAgreementKey2020",
            "the X25519 fragment must resolve to the X25519 key, not the first (Ed25519) method");
        second.PublicKeyBytes.Should().NotEqual(first.PublicKeyBytes);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_UnknownFragment_Throws()
    {
        // Issue #67: a fragment that matches no verification method must throw, not silently
        // substitute the first method.
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        var bogus = $"{did}#zNotARealFragment";

        var act = async () => await _resolver.ResolvePublicKeyAsync(bogus);
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    #endregion

    #region P-256 Resolution

    [Fact]
    public async Task ResolvePublicKeyAsync_P256_ShouldReturnCorrectKeyTypeAndBytes()
    {
        // Arrange
        var keyPair = _keyGen.Generate(KeyType.P256);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        // Act
        var resolved = await _resolver.ResolvePublicKeyAsync(did);

        // Assert
        resolved.KeyType.Should().Be("EcdsaSecp256r1VerificationKey2019");
        resolved.PublicKeyBytes.Should().Equal(keyPair.PublicKey);
    }

    #endregion

    #region Round-trip: Generate → Resolve → Sign → Verify

    [Fact]
    public async Task RoundTrip_GenerateDidKey_ResolveAndVerifySignature()
    {
        // Arrange — generate an Ed25519 key pair and build a did:key
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        var data = "Hello, ZCAP-LD!"u8.ToArray();

        // Act — resolve the DID and sign data with the private key
        var resolved = await _resolver.ResolvePublicKeyAsync(did);
        var crypto = new DefaultCryptoProvider();
        var signature = crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);

        // Assert — verify the signature with the resolved public key
        var isValid = crypto.Verify(KeyType.Ed25519, resolved.PublicKeyBytes, data, signature);
        isValid.Should().BeTrue();
    }

    #endregion

    #region GetVerificationMethodAsync

    [Fact]
    public async Task GetVerificationMethodAsync_ShouldReturnDidWithFragment()
    {
        // Arrange
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        // Act
        var vm = await _resolver.GetVerificationMethodAsync(did);

        // Assert
        vm.Should().Be($"{did}#{keyPair.MultibasePublicKey}");
    }

    #endregion

    #region Error Handling

    [Fact]
    public async Task ResolvePublicKeyAsync_NonDidKeyDid_ShouldThrowCapabilityValidationException()
    {
        // Act & Assert
        var act = async () => await _resolver.ResolvePublicKeyAsync("did:web:example.com");
        await act.Should().ThrowAsync<CapabilityValidationException>()
            .WithMessage("*only handles did:key*");
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_InvalidDidKey_ShouldThrowCapabilityValidationException()
    {
        // Arrange — valid did:key prefix but invalid multibase content
        var invalidDid = "did:key:abc123";

        // Act & Assert
        var act = async () => await _resolver.ResolvePublicKeyAsync(invalidDid);
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_EmptyString_ShouldThrowArgumentException()
    {
        // Act & Assert
        var act = async () => await _resolver.ResolvePublicKeyAsync("");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_NullString_ShouldThrowArgumentException()
    {
        // Act & Assert
        var act = async () => await _resolver.ResolvePublicKeyAsync(null!);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public void GetVerificationMethodAsync_NonDidKeyDid_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _resolver.GetVerificationMethodAsync("did:web:example.com");
        act.Should().ThrowAsync<CapabilityValidationException>();
    }

    #endregion

    #region KeyType Mapping

    [Theory]
    [InlineData(KeyType.Ed25519, "Ed25519VerificationKey2020")]
    [InlineData(KeyType.P256, "EcdsaSecp256r1VerificationKey2019")]
    public async Task ResolvePublicKeyAsync_ShouldMapKeyTypeCorrectly(KeyType keyType, string expectedKeyTypeString)
    {
        // Arrange
        var keyPair = _keyGen.Generate(keyType);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        // Act
        var resolved = await _resolver.ResolvePublicKeyAsync(did);

        // Assert
        resolved.KeyType.Should().Be(expectedKeyTypeString);
    }

    #endregion
}
