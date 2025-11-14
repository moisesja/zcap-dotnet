using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Tests.Cryptography;

public class InMemoryKeyProviderTests
{
    private readonly InMemoryKeyProvider _provider;
    private readonly ICryptographicService _cryptoService;

    public InMemoryKeyProviderTests()
    {
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<InMemoryKeyProvider>();
        var cryptoLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<Ed25519CryptographicService>();

        _cryptoService = new Ed25519CryptographicService(cryptoLogger);
        _provider = new InMemoryKeyProvider(_cryptoService, logger);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenCryptoServiceIsNull()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<InMemoryKeyProvider>();

        // Act
        var act = () => new InMemoryKeyProvider(null!, logger);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("cryptoService");
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act
        var act = () => new InMemoryKeyProvider(_cryptoService, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void KeyCount_ShouldReturnZero_WhenEmpty()
    {
        // Assert
        _provider.KeyCount.Should().Be(0);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldGenerateAndStoreKeyPair()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";

        // Act
        var keyPair = await _provider.GenerateKeyPairAsync(keyId);

        // Assert
        keyPair.Should().NotBeNull();
        keyPair.KeyId.Should().Be(keyId);
        keyPair.PublicKey.Should().HaveCount(32);
        keyPair.PrivateKey.Should().HaveCount(32);
        _provider.KeyCount.Should().Be(1);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldUseCustomVerificationMethod()
    {
        // Arrange
        var keyId = "alice-key-1";
        var verificationMethod = "did:example:alice#key-1";

        // Act
        var keyPair = await _provider.GenerateKeyPairAsync(keyId, verificationMethod);

        // Assert
        keyPair.KeyId.Should().Be(keyId);
        keyPair.VerificationMethod.Should().Be(verificationMethod);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldDefaultVerificationMethodToKeyId_WhenNotProvided()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";

        // Act
        var keyPair = await _provider.GenerateKeyPairAsync(keyId);

        // Assert
        keyPair.VerificationMethod.Should().Be(keyId);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldThrowArgumentNullException_WhenKeyIdIsNull()
    {
        // Act
        var act = async () => await _provider.GenerateKeyPairAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyId");
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldThrowArgumentNullException_WhenKeyIdIsEmpty()
    {
        // Act
        var act = async () => await _provider.GenerateKeyPairAsync("");

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyId");
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ShouldThrowCryptographicException_WhenKeyIdAlreadyExists()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";
        await _provider.GenerateKeyPairAsync(keyId);

        // Act
        var act = async () => await _provider.GenerateKeyPairAsync(keyId);

        // Assert
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*already exists*");
    }

    [Fact]
    public async Task GetKeyPairAsync_ShouldReturnKeyPair_WhenExists()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";
        var generated = await _provider.GenerateKeyPairAsync(keyId);

        // Act
        var retrieved = await _provider.GetKeyPairAsync(keyId);

        // Assert
        retrieved.Should().NotBeNull();
        retrieved!.KeyId.Should().Be(generated.KeyId);
        retrieved.PublicKey.Should().BeEquivalentTo(generated.PublicKey);
        retrieved.PrivateKey.Should().BeEquivalentTo(generated.PrivateKey);
    }

    [Fact]
    public async Task GetKeyPairAsync_ShouldReturnNull_WhenNotExists()
    {
        // Act
        var keyPair = await _provider.GetKeyPairAsync("non-existent-key");

        // Assert
        keyPair.Should().BeNull();
    }

    [Fact]
    public async Task GetKeyPairAsync_ShouldThrowArgumentNullException_WhenKeyIdIsNull()
    {
        // Act
        var act = async () => await _provider.GetKeyPairAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyId");
    }

    [Fact]
    public async Task GetPublicKeyAsync_ShouldReturnPublicKey_WhenExists()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";
        var generated = await _provider.GenerateKeyPairAsync(keyId);

        // Act
        var publicKey = await _provider.GetPublicKeyAsync(keyId);

        // Assert
        publicKey.Should().NotBeNull();
        publicKey!.KeyId.Should().Be(keyId);
        publicKey.KeyBytes.Should().BeEquivalentTo(generated.PublicKey);
        publicKey.VerificationMethod.Should().Be(generated.VerificationMethod);
    }

    [Fact]
    public async Task GetPublicKeyAsync_ShouldReturnNull_WhenNotExists()
    {
        // Act
        var publicKey = await _provider.GetPublicKeyAsync("non-existent-key");

        // Assert
        publicKey.Should().BeNull();
    }

    [Fact]
    public async Task GetPublicKeyAsync_ShouldThrowArgumentNullException_WhenKeyIdIsNull()
    {
        // Act
        var act = async () => await _provider.GetPublicKeyAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyId");
    }

    [Fact]
    public async Task StoreKeyPairAsync_ShouldStoreKeyPair()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "test-key", "did:example:test#key-1");

        // Act
        await _provider.StoreKeyPairAsync(keyPair);

        // Assert
        var retrieved = await _provider.GetKeyPairAsync("test-key");
        retrieved.Should().NotBeNull();
        retrieved!.KeyId.Should().Be(keyPair.KeyId);
    }

    [Fact]
    public async Task StoreKeyPairAsync_ShouldOverwriteExisting()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";
        await _provider.GenerateKeyPairAsync(keyId);

        var (newPublicKey, newPrivateKey) = await _cryptoService.GenerateKeyPairAsync();
        var newKeyPair = new KeyPair(newPublicKey, newPrivateKey, keyId, "did:example:alice#key-2");

        // Act
        await _provider.StoreKeyPairAsync(newKeyPair);

        // Assert
        var retrieved = await _provider.GetKeyPairAsync(keyId);
        retrieved.Should().NotBeNull();
        retrieved!.VerificationMethod.Should().Be("did:example:alice#key-2");
        _provider.KeyCount.Should().Be(1);
    }

    [Fact]
    public async Task StoreKeyPairAsync_ShouldThrowArgumentNullException_WhenKeyPairIsNull()
    {
        // Act
        var act = async () => await _provider.StoreKeyPairAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyPair");
    }

    [Fact]
    public async Task DeleteKeyPairAsync_ShouldDeleteKeyPair_WhenExists()
    {
        // Arrange
        var keyId = "did:example:alice#key-1";
        await _provider.GenerateKeyPairAsync(keyId);

        // Act
        var deleted = await _provider.DeleteKeyPairAsync(keyId);

        // Assert
        deleted.Should().BeTrue();
        _provider.KeyCount.Should().Be(0);
        var retrieved = await _provider.GetKeyPairAsync(keyId);
        retrieved.Should().BeNull();
    }

    [Fact]
    public async Task DeleteKeyPairAsync_ShouldReturnFalse_WhenNotExists()
    {
        // Act
        var deleted = await _provider.DeleteKeyPairAsync("non-existent-key");

        // Assert
        deleted.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteKeyPairAsync_ShouldThrowArgumentNullException_WhenKeyIdIsNull()
    {
        // Act
        var act = async () => await _provider.DeleteKeyPairAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyId");
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_ShouldResolveByVerificationMethod()
    {
        // Arrange
        var keyId = "alice-key-1";
        var verificationMethod = "did:example:alice#key-1";
        await _provider.GenerateKeyPairAsync(keyId, verificationMethod);

        // Act
        var publicKey = await _provider.ResolvePublicKeyAsync(verificationMethod);

        // Assert
        publicKey.Should().NotBeNull();
        publicKey!.VerificationMethod.Should().Be(verificationMethod);
        publicKey.KeyId.Should().Be(keyId);
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_ShouldReturnNull_WhenNotFound()
    {
        // Act
        var publicKey = await _provider.ResolvePublicKeyAsync("did:example:unknown#key-1");

        // Assert
        publicKey.Should().BeNull();
    }

    [Fact]
    public async Task ResolvePublicKeyAsync_ShouldThrowArgumentNullException_WhenVerificationMethodIsNull()
    {
        // Act
        var act = async () => await _provider.ResolvePublicKeyAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("verificationMethod");
    }

    [Fact]
    public async Task ClearAll_ShouldRemoveAllKeys()
    {
        // Arrange
        await _provider.GenerateKeyPairAsync("key1");
        await _provider.GenerateKeyPairAsync("key2");
        await _provider.GenerateKeyPairAsync("key3");

        // Act
        _provider.ClearAll();

        // Assert
        _provider.KeyCount.Should().Be(0);
        var key1 = await _provider.GetKeyPairAsync("key1");
        var key2 = await _provider.GetKeyPairAsync("key2");
        var key3 = await _provider.GetKeyPairAsync("key3");
        key1.Should().BeNull();
        key2.Should().BeNull();
        key3.Should().BeNull();
    }

    [Fact]
    public async Task MultipleKeys_ShouldCoexist()
    {
        // Arrange & Act
        var key1 = await _provider.GenerateKeyPairAsync("did:example:alice#key-1");
        var key2 = await _provider.GenerateKeyPairAsync("did:example:bob#key-1");
        var key3 = await _provider.GenerateKeyPairAsync("did:example:charlie#key-1");

        // Assert
        _provider.KeyCount.Should().Be(3);

        var retrieved1 = await _provider.GetKeyPairAsync(key1.KeyId);
        var retrieved2 = await _provider.GetKeyPairAsync(key2.KeyId);
        var retrieved3 = await _provider.GetKeyPairAsync(key3.KeyId);

        retrieved1.Should().NotBeNull();
        retrieved2.Should().NotBeNull();
        retrieved3.Should().NotBeNull();

        retrieved1!.KeyId.Should().Be(key1.KeyId);
        retrieved2!.KeyId.Should().Be(key2.KeyId);
        retrieved3!.KeyId.Should().Be(key3.KeyId);
    }

    [Fact]
    public async Task ThreadSafety_ConcurrentOperations_ShouldNotThrow()
    {
        // Arrange
        var tasks = new Task[10];

        // Act - Concurrent key generation
        for (int i = 0; i < 10; i++)
        {
            var keyId = $"concurrent-key-{i}";
            tasks[i] = Task.Run(async () =>
            {
                await _provider.GenerateKeyPairAsync(keyId);
                var retrieved = await _provider.GetKeyPairAsync(keyId);
                retrieved.Should().NotBeNull();
            });
        }

        // Assert
        await Task.WhenAll(tasks);
        _provider.KeyCount.Should().Be(10);
    }
}
