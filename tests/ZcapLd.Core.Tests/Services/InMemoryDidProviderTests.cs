using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

public class InMemoryDidProviderTests
{
    private readonly InMemoryDidProvider _provider;

    public InMemoryDidProviderTests()
    {
        _provider = new InMemoryDidProvider();
    }

    #region SignAsync Tests

    [Fact]
    public async Task SignAsync_WithRegisteredKey_ShouldReturnValidSignature()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        _provider.GenerateAndRegisterKeyPair(did);
        var data = "hello world"u8.ToArray();

        // Act
        var result = await _provider.SignAsync(did, data);

        // Assert
        result.Should().NotBeNull();
        result.Signature.Should().HaveCount(64); // Ed25519 signatures are 64 bytes
        result.SignatureType.Should().Be("Ed25519Signature2020");
    }

    [Fact]
    public async Task SignAsync_WithUnregisteredKey_ShouldThrow()
    {
        // Arrange
        var did = "did:key:z6MkUnknown";
        var data = "hello"u8.ToArray();

        // Act & Assert
        var act = async () => await _provider.SignAsync(did, data);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*No private key registered*");
    }

    [Fact]
    public async Task SignAsync_WithEmptyDid_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _provider.SignAsync("", "data"u8.ToArray());
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task SignAsync_WithNullData_ShouldThrow()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        _provider.GenerateAndRegisterKeyPair(did);

        // Act & Assert
        var act = async () => await _provider.SignAsync(did, null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task SignAsync_SignatureIsVerifiable()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (_, publicKey) = _provider.GenerateAndRegisterKeyPair(did);
        var data = "test data to sign"u8.ToArray();

        // Act
        var result = await _provider.SignAsync(did, data);

        // Assert - verify signature with public key
        Ed25519Signer.Verify(data, result.Signature, publicKey).Should().BeTrue();
    }

    #endregion

    #region ResolvePublicKeyAsync Tests

    [Fact]
    public async Task ResolvePublicKeyAsync_WithRegisteredKey_ShouldReturnPublicKey()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (_, expectedPublicKey) = _provider.GenerateAndRegisterKeyPair(did);

        // Act
        var resolvedKey = await _provider.ResolvePublicKeyAsync(did);

        // Assert
        resolvedKey.PublicKeyBytes.Should().Equal(expectedPublicKey);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_WithVerificationMethodUri_ShouldResolve()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (_, expectedPublicKey) = _provider.GenerateAndRegisterKeyPair(did);

        // Act - pass full verification method URI with fragment
        var resolvedKey = await _provider.ResolvePublicKeyAsync($"{did}#z6MkTest");

        // Assert
        resolvedKey.PublicKeyBytes.Should().Equal(expectedPublicKey);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_WithDidKeyFormat_ShouldDecodeMultibase()
    {
        // Arrange - generate a proper did:key using GenerateDidKey
        var did = _provider.GenerateDidKey();

        // Act
        var resolvedKey = await _provider.ResolvePublicKeyAsync(did);

        // Assert
        resolvedKey.Should().NotBeNull();
        resolvedKey.PublicKeyBytes.Should().HaveCount(32); // Ed25519 public keys are 32 bytes
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_WithInvalidDid_ShouldThrow()
    {
        // Arrange
        var invalidDid = "did:invalid:xyz";

        // Act & Assert
        var act = async () => await _provider.ResolvePublicKeyAsync(invalidDid);
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_WithEmptyDid_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _provider.ResolvePublicKeyAsync("");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_WithInvalidDidKeyFormat_ShouldThrow()
    {
        // Arrange - did:key without the required 'z' multibase prefix
        var invalidDidKey = "did:key:abc123";

        // Act & Assert
        var act = async () => await _provider.ResolvePublicKeyAsync(invalidDidKey);
        await act.Should().ThrowAsync<CapabilityValidationException>()
            .WithMessage("*must start with 'z'*");
    }

    #endregion

    #region GetVerificationMethodAsync Tests

    [Fact]
    public async Task GetVerificationMethodAsync_WithDidKey_ShouldReturnDidFragment()
    {
        // Arrange
        var did = "did:key:z6MkExample1234";

        // Act
        var verificationMethod = await _provider.GetVerificationMethodAsync(did);

        // Assert
        verificationMethod.Should().Be("did:key:z6MkExample1234#z6MkExample1234");
    }

    [Fact]
    public async Task GetVerificationMethodAsync_WithNonKeyDid_ShouldReturnDefaultFragment()
    {
        // Arrange
        var did = "did:web:example.com";

        // Act
        var verificationMethod = await _provider.GetVerificationMethodAsync(did);

        // Assert
        verificationMethod.Should().Be("did:web:example.com#key-1");
    }

    [Fact]
    public async Task GetVerificationMethodAsync_WithEmptyDid_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _provider.GetVerificationMethodAsync("");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region RegisterKey Tests

    [Fact]
    public void RegisterKey_WithValidKey_ShouldSucceed()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();

        // Act
        _provider.RegisterKey(did, privateKey);

        // Assert - should not throw, and key should be usable
        var act = async () => await _provider.SignAsync(did, "test"u8.ToArray());
        act.Should().NotThrowAsync();
    }

    [Fact]
    public void RegisterKey_WithInvalidKeyLength_ShouldThrow()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var invalidKey = new byte[16]; // Wrong length

        // Act & Assert
        var act = () => _provider.RegisterKey(did, invalidKey);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*32 bytes*");
    }

    [Fact]
    public void RegisterKey_WithEmptyDid_ShouldThrow()
    {
        // Arrange
        var (privateKey, _) = Ed25519Signer.GenerateKeyPair();

        // Act & Assert
        var act = () => _provider.RegisterKey("", privateKey);
        act.Should().Throw<ArgumentException>();
    }

    #endregion

    #region GenerateAndRegisterKeyPair Tests

    [Fact]
    public void GenerateAndRegisterKeyPair_ShouldReturnValidKeyPair()
    {
        // Arrange
        var did = "did:key:z6MkTest";

        // Act
        var (privateKey, publicKey) = _provider.GenerateAndRegisterKeyPair(did);

        // Assert
        privateKey.Should().HaveCount(32);
        publicKey.Should().HaveCount(32);
    }

    [Fact]
    public async Task GenerateAndRegisterKeyPair_ShouldMakeKeyUsable()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        _provider.GenerateAndRegisterKeyPair(did);

        // Act & Assert - should be able to sign
        var result = await _provider.SignAsync(did, "test"u8.ToArray());
        result.Should().NotBeNull();
        result.Signature.Should().HaveCount(64);
    }

    #endregion

    #region GenerateDidKey Tests

    [Fact]
    public void GenerateDidKey_ShouldReturnValidDidKeyFormat()
    {
        // Act
        var did = _provider.GenerateDidKey();

        // Assert
        did.Should().StartWith("did:key:z");
    }

    [Fact]
    public async Task GenerateDidKey_ShouldRegisterKeyForSigning()
    {
        // Arrange
        var did = _provider.GenerateDidKey();

        // Act & Assert - should be able to sign with the generated DID
        var result = await _provider.SignAsync(did, "test data"u8.ToArray());
        result.Should().NotBeNull();
        result.SignatureType.Should().Be("Ed25519Signature2020");
    }

    [Fact]
    public async Task GenerateDidKey_ShouldBeResolvable()
    {
        // Arrange
        var did = _provider.GenerateDidKey();

        // Act
        var publicKey = await _provider.ResolvePublicKeyAsync(did);

        // Assert
        publicKey.Should().NotBeNull();
        publicKey.PublicKeyBytes.Should().HaveCount(32);
    }

    [Fact]
    public void GenerateDidKey_ShouldGenerateUniqueKeys()
    {
        // Act
        var did1 = _provider.GenerateDidKey();
        var did2 = _provider.GenerateDidKey();

        // Assert
        did1.Should().NotBe(did2);
    }

    #endregion

    #region Thread Safety Tests

    [Fact]
    public void ConcurrentKeyRegistration_ShouldBeThreadSafe()
    {
        // Arrange & Act
        var tasks = Enumerable.Range(0, 100)
            .Select(i =>
            {
                var did = $"did:key:z6MkConcurrent{i}";
                return Task.Run(() => _provider.GenerateAndRegisterKeyPair(did));
            })
            .ToArray();

        // Assert - should not throw
        var act = () => Task.WaitAll(tasks);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task ConcurrentSigning_ShouldBeThreadSafe()
    {
        // Arrange
        var dids = Enumerable.Range(0, 50)
            .Select(i =>
            {
                var did = $"did:key:z6MkConcurrentSign{i}";
                _provider.GenerateAndRegisterKeyPair(did);
                return did;
            })
            .ToArray();

        var data = "concurrent test data"u8.ToArray();

        // Act
        var results = await Task.WhenAll(
            dids.Select(did => _provider.SignAsync(did, data)));

        // Assert
        results.Should().HaveCount(50);
        results.Should().OnlyContain(r => r.Signature.Length == 64);
        results.Should().OnlyContain(r => r.SignatureType == "Ed25519Signature2020");
    }

    #endregion
}
