using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Cryptography;

public class SignatureVerifierTests
{
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly Ed25519CryptoSuite _suite = new();

    public SignatureVerifierTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
    }

    [Fact]
    public async Task VerifyInvocationSignature_WithSignedInvocation_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var invocation = new Invocation
        {
            Capability = "urn:uuid:test-capability",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        var resolved = await _didProvider.ResolvePublicKeyAsync(invocation.Proof.VerificationMethod);

        // Act
        var isValid = SignatureVerifier.VerifyInvocationSignature(
            invocation,
            resolved.PublicKeyBytes,
            _suite);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocationSignature_WithTamperedProofMetadata_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var invocation = new Invocation
        {
            Capability = "urn:uuid:test-capability",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        invocation.Proof.InvocationTarget = "https://example.com/other-resource";
        var resolved = await _didProvider.ResolvePublicKeyAsync(controllerDid);

        // Act
        var isValid = SignatureVerifier.VerifyInvocationSignature(
            invocation,
            resolved.PublicKeyBytes,
            _suite);

        // Assert
        isValid.Should().BeFalse();
    }
}
