using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Serialization;

namespace ZcapLd.Core.Tests.Cryptography;

public class ProofServiceTests
{
    private readonly ProofService _proofService;
    private readonly ICryptographicService _cryptoService;
    private readonly IMultibaseService _multibaseService;
    private readonly IJsonLdCanonicalizationService _canonicalizationService;
    private readonly IZcapSerializationService _serializationService;

    public ProofServiceTests()
    {
        var cryptoLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<Ed25519CryptographicService>();
        var multibaseLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<MultibaseService>();
        var canonicalizationLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<JsonLdCanonicalizationService>();
        var serializationLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<ZcapSerializationService>();
        var proofLogger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<ProofService>();

        _cryptoService = new Ed25519CryptographicService(cryptoLogger);
        _multibaseService = new MultibaseService(multibaseLogger);
        _canonicalizationService = new JsonLdCanonicalizationService(canonicalizationLogger);
        _serializationService = new ZcapSerializationService(serializationLogger);

        _proofService = new ProofService(
            _cryptoService,
            _canonicalizationService,
            _multibaseService,
            _serializationService,
            proofLogger);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenCryptoServiceIsNull()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<ProofService>();

        // Act
        var act = () => new ProofService(
            null!,
            _canonicalizationService,
            _multibaseService,
            _serializationService,
            logger);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("cryptoService");
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenCanonicalizationServiceIsNull()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole())
            .CreateLogger<ProofService>();

        // Act
        var act = () => new ProofService(
            _cryptoService,
            null!,
            _multibaseService,
            _serializationService,
            logger);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("canonicalizationService");
    }

    [Fact]
    public async Task CreateDelegationProofAsync_ShouldCreateValidProof()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");

        var parentCapability = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var capability = DelegatedCapability.Create(
            parentCapability.Id,
            "did:example:alice",
            "https://api.example.com/users/123",
            DateTime.UtcNow.AddDays(30));

        var capabilityChain = new object[] { parentCapability.Id, parentCapability };

        // Act
        var proof = await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            capabilityChain);

        // Assert
        proof.Should().NotBeNull();
        proof.Type.Should().Be("Ed25519Signature2020");
        proof.ProofPurpose.Should().Be("capabilityDelegation");
        proof.VerificationMethod.Should().Be("did:example:alice#key-1");
        proof.ProofValue.Should().NotBeNullOrEmpty();
        proof.ProofValue.Should().StartWith("z"); // Base58-BTC prefix
        proof.CapabilityChain.Should().NotBeNull();
        proof.CapabilityChain.Should().HaveCount(2);
    }

    [Fact]
    public async Task CreateDelegationProofAsync_ShouldThrowArgumentNullException_WhenCapabilityIsNull()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var capabilityChain = new object[] { "zcap-id" };

        // Act
        var act = async () => await _proofService.CreateDelegationProofAsync(
            null!,
            keyPair,
            capabilityChain);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("capability");
    }

    [Fact]
    public async Task CreateDelegationProofAsync_ShouldThrowArgumentNullException_WhenKeyPairIsNull()
    {
        // Arrange
        var capability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(1));
        var capabilityChain = new object[] { "zcap-id" };

        // Act
        var act = async () => await _proofService.CreateDelegationProofAsync(
            capability,
            null!,
            capabilityChain);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("keyPair");
    }

    [Fact]
    public async Task CreateDelegationProofAsync_ShouldThrowArgumentException_WhenCapabilityChainIsEmpty()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var capability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(1));

        // Act
        var act = async () => await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            Array.Empty<object>());

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("capabilityChain")
            .WithMessage("*cannot be null or empty*");
    }

    [Fact]
    public async Task CreateInvocationProofAsync_ShouldCreateValidProof()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");

        var invocation = Invocation.Create(
            "urn:zcap:root:https%3A%2F%2Fapi.example.com",
            "read",
            "https://api.example.com/users/123",
            "did:example:alice");

        // Act
        var proof = await _proofService.CreateInvocationProofAsync(
            invocation,
            keyPair,
            "urn:zcap:root:https%3A%2F%2Fapi.example.com");

        // Assert
        proof.Should().NotBeNull();
        proof.Type.Should().Be("Ed25519Signature2020");
        proof.ProofPurpose.Should().Be("capabilityInvocation");
        proof.VerificationMethod.Should().Be("did:example:alice#key-1");
        proof.ProofValue.Should().NotBeNullOrEmpty();
        proof.ProofValue.Should().StartWith("z");
        proof.Capability.Should().Be("urn:zcap:root:https%3A%2F%2Fapi.example.com");
    }

    [Fact]
    public async Task CreateInvocationProofAsync_ShouldThrowArgumentNullException_WhenInvocationIsNull()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");

        // Act
        var act = async () => await _proofService.CreateInvocationProofAsync(
            null!,
            keyPair,
            "capability-id");

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("invocation");
    }

    [Fact]
    public async Task CreateInvocationProofAsync_ShouldThrowArgumentNullException_WhenCapabilityIdIsNull()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var invocation = Invocation.Create("cap-id", "read", "https://api.example.com");

        // Act
        var act = async () => await _proofService.CreateInvocationProofAsync(
            invocation,
            keyPair,
            null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("capabilityId");
    }

    [Fact]
    public async Task VerifyDelegationProofAsync_ShouldReturnTrue_WhenProofIsValid()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var publicKeyObj = new PublicKey(publicKey, "key-1", "did:example:alice#key-1");

        var parentCapability = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var capability = DelegatedCapability.Create(
            parentCapability.Id,
            "did:example:alice",
            "https://api.example.com/users/123",
            DateTime.UtcNow.AddDays(30));

        var capabilityChain = new object[] { parentCapability.Id, parentCapability };

        var proof = await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            capabilityChain);

        capability.Proof = proof;

        // Act
        var isValid = await _proofService.VerifyDelegationProofAsync(
            capability,
            publicKeyObj);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyDelegationProofAsync_ShouldReturnFalse_WhenProofIsInvalid()
    {
        // Arrange
        var (publicKey1, privateKey1) = await _cryptoService.GenerateKeyPairAsync();
        var (publicKey2, _) = await _cryptoService.GenerateKeyPairAsync();

        var keyPair = new KeyPair(publicKey1, privateKey1, "key-1", "did:example:alice#key-1");
        var wrongPublicKey = new PublicKey(publicKey2, "key-2", "did:example:bob#key-1");

        var parentCapability = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var capability = DelegatedCapability.Create(
            parentCapability.Id,
            "did:example:alice",
            "https://api.example.com/users/123",
            DateTime.UtcNow.AddDays(30));

        var capabilityChain = new object[] { parentCapability.Id, parentCapability };

        var proof = await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            capabilityChain);

        capability.Proof = proof;

        // Act - Verify with wrong public key
        var isValid = await _proofService.VerifyDelegationProofAsync(
            capability,
            wrongPublicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyDelegationProofAsync_ShouldThrowArgumentException_WhenCapabilityHasNoProof()
    {
        // Arrange
        var (publicKey, _) = await _cryptoService.GenerateKeyPairAsync();
        var publicKeyObj = new PublicKey(publicKey, "key-1", "did:example:alice#key-1");

        var capability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com",
            DateTime.UtcNow.AddDays(1));
        // No proof attached

        // Act
        var act = async () => await _proofService.VerifyDelegationProofAsync(
            capability,
            publicKeyObj);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*must have a proof*");
    }

    [Fact]
    public async Task VerifyInvocationProofAsync_ShouldReturnTrue_WhenProofIsValid()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var publicKeyObj = new PublicKey(publicKey, "key-1", "did:example:alice#key-1");

        var invocation = Invocation.Create(
            "urn:zcap:root:https%3A%2F%2Fapi.example.com",
            "read",
            "https://api.example.com/users/123",
            "did:example:alice");

        var proof = await _proofService.CreateInvocationProofAsync(
            invocation,
            keyPair,
            "urn:zcap:root:https%3A%2F%2Fapi.example.com");

        invocation.Proof = proof;

        // Act
        var isValid = await _proofService.VerifyInvocationProofAsync(
            invocation,
            publicKeyObj);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocationProofAsync_ShouldReturnFalse_WhenProofIsInvalid()
    {
        // Arrange
        var (publicKey1, privateKey1) = await _cryptoService.GenerateKeyPairAsync();
        var (publicKey2, _) = await _cryptoService.GenerateKeyPairAsync();

        var keyPair = new KeyPair(publicKey1, privateKey1, "key-1", "did:example:alice#key-1");
        var wrongPublicKey = new PublicKey(publicKey2, "key-2", "did:example:bob#key-1");

        var invocation = Invocation.Create("cap-id", "read", "https://api.example.com");
        var proof = await _proofService.CreateInvocationProofAsync(invocation, keyPair, "cap-id");
        invocation.Proof = proof;

        // Act - Verify with wrong public key
        var isValid = await _proofService.VerifyInvocationProofAsync(invocation, wrongPublicKey);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CreateAndVerifyProof_EndToEnd_ShouldWork()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var publicKeyObj = new PublicKey(publicKey, "key-1", "did:example:alice#key-1");

        var parentCapability = RootCapability.Create("https://api.example.com", "did:example:issuer");
        var capability = DelegatedCapability.Create(
            parentCapability.Id,
            "did:example:alice",
            "https://api.example.com/users/123",
            DateTime.UtcNow.AddDays(30));

        var capabilityChain = new object[] { parentCapability.Id, parentCapability };

        // Act - Create proof
        var proof = await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            capabilityChain);

        capability.Proof = proof;

        // Act - Verify proof
        var isValid = await _proofService.VerifyDelegationProofAsync(
            capability,
            publicKeyObj);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyProofAsync_ShouldReturnFalse_WhenDocumentIsModified()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var publicKeyObj = new PublicKey(publicKey, "key-1", "did:example:alice#key-1");

        var capability = DelegatedCapability.Create(
            "parent-id",
            "did:example:alice",
            "https://api.example.com/users/123",
            DateTime.UtcNow.AddDays(30));

        var capabilityChain = new object[] { "parent-id", new { } };

        var proof = await _proofService.CreateDelegationProofAsync(
            capability,
            keyPair,
            capabilityChain);

        capability.Proof = proof;

        // Modify the capability after signing
        capability.AllowedAction = "write";

        // Act
        var isValid = await _proofService.VerifyDelegationProofAsync(
            capability,
            publicKeyObj);

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CreateProofAsync_WithUnsupportedProofPurpose_ShouldThrowArgumentException()
    {
        // Arrange
        var (publicKey, privateKey) = await _cryptoService.GenerateKeyPairAsync();
        var keyPair = new KeyPair(publicKey, privateKey, "key-1", "did:example:alice#key-1");
        var document = new { data = "test" };

        // Act
        var act = async () => await _proofService.CreateProofAsync(
            document,
            keyPair,
            "unsupportedPurpose");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Unsupported proof purpose*");
    }
}
