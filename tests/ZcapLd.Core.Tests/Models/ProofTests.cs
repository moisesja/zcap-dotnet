using FluentAssertions;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>
/// Unit tests for <see cref="Proof"/> class.
/// </summary>
public class ProofTests
{
    private const string ValidVerificationMethod = "did:example:controller#key-1";
    private const string ValidProofValue = "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz";
    private const string ValidRootCapabilityId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi";
    private const string ValidDelegatedCapabilityId = "urn:uuid:12345678-1234-1234-1234-123456789abc";

    [Fact]
    public void CreateDelegationProof_WithValidParameters_ReturnsProof()
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId };

        // Act
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, chain);

        // Assert
        proof.Should().NotBeNull();
        proof.Type.Should().Be(Proof.Ed25519Signature2020);
        proof.ProofPurpose.Should().Be(Proof.CapabilityDelegationPurpose);
        proof.VerificationMethod.Should().Be(ValidVerificationMethod);
        proof.ProofValue.Should().Be(ValidProofValue);
        proof.CapabilityChain.Should().BeEquivalentTo(chain);
        proof.Created.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void CreateDelegationProof_WithCustomSignatureType_UsesSpecifiedType()
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId };

        // Act
        var proof = Proof.CreateDelegationProof(
            ValidVerificationMethod,
            ValidProofValue,
            chain,
            Proof.Ed25519Signature2018);

        // Assert
        proof.Type.Should().Be(Proof.Ed25519Signature2018);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateDelegationProof_WithInvalidVerificationMethod_ThrowsArgumentNullException(string? verificationMethod)
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId };

        // Act
        var act = () => Proof.CreateDelegationProof(verificationMethod!, ValidProofValue, chain);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("verificationMethod");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateDelegationProof_WithInvalidProofValue_ThrowsArgumentNullException(string? proofValue)
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId };

        // Act
        var act = () => Proof.CreateDelegationProof(ValidVerificationMethod, proofValue!, chain);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("proofValue");
    }

    [Fact]
    public void CreateDelegationProof_WithNullCapabilityChain_ThrowsArgumentNullException()
    {
        // Act
        var act = () => Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("capabilityChain");
    }

    [Fact]
    public void CreateDelegationProof_WithEmptyCapabilityChain_ThrowsArgumentNullException()
    {
        // Arrange
        var emptyChain = Array.Empty<object>();

        // Act
        var act = () => Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, emptyChain);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("capabilityChain");
    }

    [Fact]
    public void CreateInvocationProof_WithValidParameters_ReturnsProof()
    {
        // Act
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Assert
        proof.Should().NotBeNull();
        proof.Type.Should().Be(Proof.Ed25519Signature2020);
        proof.ProofPurpose.Should().Be(Proof.CapabilityInvocationPurpose);
        proof.VerificationMethod.Should().Be(ValidVerificationMethod);
        proof.ProofValue.Should().Be(ValidProofValue);
        proof.Capability.Should().Be(ValidDelegatedCapabilityId);
        proof.Created.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateInvocationProof_WithInvalidCapabilityId_ThrowsArgumentNullException(string? capabilityId)
    {
        // Act
        var act = () => Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, capabilityId!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("capabilityId");
    }

    [Fact]
    public void Validate_WithValidDelegationProof_DoesNotThrow()
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId };
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, chain);

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_WithValidInvocationProof_DoesNotThrow()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_WithEmptyType_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Type = string.Empty;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*type is required*")
            .Which.ErrorCode.Should().Be("MISSING_PROOF_TYPE");
    }

    [Fact]
    public void Validate_WithDefaultCreatedTimestamp_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Created = default;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*created timestamp is required*")
            .Which.ErrorCode.Should().Be("MISSING_PROOF_CREATED");
    }

    [Fact]
    public void Validate_WithFutureCreatedTimestamp_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Created = DateTime.UtcNow.AddHours(1);

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*created timestamp is in the future*")
            .Which.ErrorCode.Should().Be("INVALID_PROOF_CREATED");
    }

    [Fact]
    public void Validate_WithEmptyProofPurpose_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.ProofPurpose = string.Empty;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*purpose is required*")
            .Which.ErrorCode.Should().Be("MISSING_PROOF_PURPOSE");
    }

    [Fact]
    public void Validate_WithInvalidProofPurpose_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.ProofPurpose = "invalidPurpose";

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Invalid proofPurpose*")
            .Which.ErrorCode.Should().Be("INVALID_PROOF_PURPOSE");
    }

    [Fact]
    public void Validate_WithEmptyVerificationMethod_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.VerificationMethod = string.Empty;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Verification method is required*")
            .Which.ErrorCode.Should().Be("MISSING_VERIFICATION_METHOD");
    }

    [Fact]
    public void Validate_WithInvalidVerificationMethodUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.VerificationMethod = "not-a-valid-uri";

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Verification method must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_VERIFICATION_METHOD_URI");
    }

    [Fact]
    public void Validate_WithEmptyProofValue_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.ProofValue = string.Empty;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Proof value*is required*")
            .Which.ErrorCode.Should().Be("MISSING_PROOF_VALUE");
    }

    [Fact]
    public void Validate_DelegationProofWithoutCapabilityChain_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateDelegationProof(
            ValidVerificationMethod,
            ValidProofValue,
            new object[] { ValidRootCapabilityId });
        proof.CapabilityChain = null;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Capability chain is required*")
            .Which.ErrorCode.Should().Be("MISSING_CAPABILITY_CHAIN");
    }

    [Fact]
    public void Validate_DelegationProofWithNonStringRootId_ThrowsCapabilityValidationException()
    {
        // Arrange
        var chain = new object[] { 123 }; // Invalid: not a string
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, new object[] { ValidRootCapabilityId });
        proof.CapabilityChain = chain;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*first entry*must be the root capability ID*")
            .Which.ErrorCode.Should().Be("INVALID_CAPABILITY_CHAIN_ROOT");
    }

    [Fact]
    public void Validate_DelegationProofWithInvalidRootIdFormat_ThrowsCapabilityValidationException()
    {
        // Arrange
        var chain = new object[] { "urn:uuid:12345678-1234-1234-1234-123456789abc" }; // Not a root ID
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, new object[] { ValidRootCapabilityId });
        proof.CapabilityChain = chain;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*must start with 'urn:zcap:root:'*")
            .Which.ErrorCode.Should().Be("INVALID_ROOT_ID_IN_CHAIN");
    }

    [Fact]
    public void Validate_DelegationProofWithInvalidIntermediateEntry_ThrowsCapabilityValidationException()
    {
        // Arrange
        var chain = new object[]
        {
            ValidRootCapabilityId,
            123, // Invalid: intermediate must be string
            ValidDelegatedCapabilityId
        };
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, new object[] { ValidRootCapabilityId });
        proof.CapabilityChain = chain;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Intermediate*must be a capability ID*")
            .Which.ErrorCode.Should().Be("INVALID_CAPABILITY_CHAIN_INTERMEDIATE");
    }

    [Fact]
    public void Validate_DelegationProofWithValidChain_DoesNotThrow()
    {
        // Arrange
        var chain = new object[]
        {
            ValidRootCapabilityId,
            "urn:uuid:intermediate-1",
            "urn:uuid:intermediate-2",
            ValidDelegatedCapabilityId // Parent (can be object or string)
        };
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, new object[] { ValidRootCapabilityId });
        proof.CapabilityChain = chain;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_InvocationProofWithoutCapability_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Capability = null;

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Capability ID is required*")
            .Which.ErrorCode.Should().Be("MISSING_INVOCATION_CAPABILITY");
    }

    [Fact]
    public void Validate_InvocationProofWithInvalidCapabilityUri_ThrowsCapabilityValidationException()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Capability = "not-a-valid-uri";

        // Act
        var act = () => proof.Validate();

        // Assert
        act.Should().Throw<CapabilityValidationException>()
            .WithMessage("*Capability must be a valid URI*")
            .Which.ErrorCode.Should().Be("INVALID_INVOCATION_CAPABILITY_URI");
    }

    [Fact]
    public void IsDelegationProof_WithDelegationProof_ReturnsTrue()
    {
        // Arrange
        var proof = Proof.CreateDelegationProof(
            ValidVerificationMethod,
            ValidProofValue,
            new object[] { ValidRootCapabilityId });

        // Act
        var result = proof.IsDelegationProof();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsDelegationProof_WithInvocationProof_ReturnsFalse()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var result = proof.IsDelegationProof();

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsInvocationProof_WithInvocationProof_ReturnsTrue()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var result = proof.IsInvocationProof();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsInvocationProof_WithDelegationProof_ReturnsFalse()
    {
        // Arrange
        var proof = Proof.CreateDelegationProof(
            ValidVerificationMethod,
            ValidProofValue,
            new object[] { ValidRootCapabilityId });

        // Act
        var result = proof.IsInvocationProof();

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void GetCapabilityChain_WithSetChain_ReturnsChain()
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId, ValidDelegatedCapabilityId };
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, chain);

        // Act
        var result = proof.GetCapabilityChain();

        // Assert
        result.Should().BeEquivalentTo(chain);
    }

    [Fact]
    public void GetCapabilityChain_WithNullChain_ReturnsEmptyArray()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var result = proof.GetCapabilityChain();

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void GetRootCapabilityId_WithValidChain_ReturnsRootId()
    {
        // Arrange
        var chain = new object[] { ValidRootCapabilityId, ValidDelegatedCapabilityId };
        var proof = Proof.CreateDelegationProof(ValidVerificationMethod, ValidProofValue, chain);

        // Act
        var result = proof.GetRootCapabilityId();

        // Assert
        result.Should().Be(ValidRootCapabilityId);
    }

    [Fact]
    public void GetRootCapabilityId_WithNullChain_ReturnsNull()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var result = proof.GetRootCapabilityId();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetRootCapabilityId_WithEmptyChain_ReturnsNull()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.CapabilityChain = Array.Empty<object>();

        // Act
        var result = proof.GetRootCapabilityId();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void IsRecent_WithRecentProof_ReturnsTrue()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);

        // Act
        var result = proof.IsRecent();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsRecent_WithOldProof_ReturnsFalse()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Created = DateTime.UtcNow.AddMinutes(-10);

        // Act
        var result = proof.IsRecent(maxAgeMinutes: 5);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsRecent_WithCustomMaxAge_UsesSpecifiedValue()
    {
        // Arrange
        var proof = Proof.CreateInvocationProof(ValidVerificationMethod, ValidProofValue, ValidDelegatedCapabilityId);
        proof.Created = DateTime.UtcNow.AddMinutes(-8);

        // Act
        var result = proof.IsRecent(maxAgeMinutes: 10);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void Constants_HaveExpectedValues()
    {
        // Assert
        Proof.CapabilityDelegationPurpose.Should().Be("capabilityDelegation");
        Proof.CapabilityInvocationPurpose.Should().Be("capabilityInvocation");
        Proof.Ed25519Signature2020.Should().Be("Ed25519Signature2020");
        Proof.Ed25519Signature2018.Should().Be("Ed25519Signature2018");
    }
}
