using System.Reflection;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Compliance;

public class NormativeUnitComplianceTests
{
    [Fact(DisplayName = "MUST-01 Root @context MUST equal https://w3id.org/zcap/v1")]
    public async Task Must01_RootContext_MustBeExactValue()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resources",
            new[] { "read" });

        root.Context.Should().Be("https://w3id.org/zcap/v1");
    }

    [Fact(DisplayName = "MUST-02 Root MUST include id/controller/invocationTarget")]
    public async Task Must02_Root_MustContainRequiredFields()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resources",
            new[] { "read" });

        root.Id.Should().NotBeNullOrWhiteSpace();
        root.Controller.Primary.Should().Be(controllerDid);
        root.InvocationTarget.Should().Be("https://example.com/resources");
    }

    [Fact(DisplayName = "MUST-03 Root MUST NOT have any additional capability fields")]
    public async Task Must03_Root_MustNotHaveAdditionalFields()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resources",
            new[] { "read" });

        // Per #37: root capabilities omit optional fields entirely so cross-language
        // parsers see field absence rather than empty arrays / null values.
        root.AllowedAction.Should().BeNull();
        root.Caveat.Should().BeNull();
        root.Expires.Should().BeNull();
        root.ParentCapability.Should().BeNull();
        root.Proof.Should().BeNull();
    }

    [Fact(DisplayName = "MUST-04 Delegated @context MUST be array with zcap context first")]
    public async Task Must04_DelegatedContext_MustBeArrayWithZcapContextFirst()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Context.Should().BeOfType<object[]>();
        ((object[])delegated.Context)[0].Should().Be("https://w3id.org/zcap/v1");
    }

    [Fact(DisplayName = "MUST-05 Delegated capability MUST include required fields")]
    public async Task Must05_DelegatedCapability_MustContainRequiredFields()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Id.Should().NotBeNullOrWhiteSpace();
        delegated.ParentCapability.Should().Be(root.Id);
        delegated.Controller.Primary.Should().Be(childDid);
        delegated.InvocationTarget.Should().Be(root.InvocationTarget);
        delegated.Expires.Should().NotBeNull();
        delegated.Proof.Should().NotBeNull();
    }

    [Fact(DisplayName = "MUST-06 Delegated capability MUST have delegation proof")]
    public async Task Must06_DelegatedCapability_MustHaveDelegationProof()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Proof.Should().NotBeNull();
        delegated.Proof!.Primary.ProofPurpose.Should().Be("capabilityDelegation");
    }

    [Fact(DisplayName = "MUST-07 capabilityChain MUST be array with root capability ID first")]
    public async Task Must07_CapabilityChain_MustStartWithRootId()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Proof.Should().NotBeNull();
        delegated.Proof!.Primary.CapabilityChain.Should().NotBeEmpty();
        delegated.Proof.Primary.CapabilityChain![0].Should().Be(root.Id);
    }

    [Fact(DisplayName = "MUST-08 capabilityChain MUST embed immediate parent as last entry")]
    public async Task Must08_CapabilityChain_MustEmbedImmediateParent()
    {
        var fixture = new ComplianceTestFixture();
        var rootDid = fixture.RegisterControllerDid();
        var level1Did = fixture.RegisterControllerDid();
        var level2Did = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            rootDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var level1 = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            level1Did,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(20));

        var level2 = await fixture.CapabilityService.DelegateCapabilityAsync(
            level1,
            level2Did,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        var lastChainEntry = level2.Proof!.Primary.CapabilityChain![^1];

        if (lastChainEntry is Capability embeddedParent)
        {
            embeddedParent.Id.Should().Be(level1.Id);
            return;
        }

        if (lastChainEntry is System.Text.Json.JsonElement jsonElement &&
            jsonElement.ValueKind == System.Text.Json.JsonValueKind.Object &&
            jsonElement.TryGetProperty("id", out var idProperty))
        {
            idProperty.GetString().Should().Be(level1.Id);
            return;
        }

        throw new Xunit.Sdk.XunitException(
            "MUST-08 requires the immediate parent capability object as the last capabilityChain entry.");
    }

    [Fact(DisplayName = "MUST-15 Delegated capabilities MUST have expiration date-times")]
    public async Task Must15_DelegatedCapabilities_MustHaveExpiration()
    {
        var fixture = new ComplianceTestFixture();
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:test-capability",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresources",
            Controller = fixture.RegisterControllerDid(),
            InvocationTarget = "https://example.com/resources",
            AllowedAction = new[] { "read" },
            Proof = new Proof
            {
                Type = "Ed25519Signature2020",
                ProofPurpose = "capabilityDelegation",
                VerificationMethod = "did:key:placeholder#placeholder",
                ProofValue = "z123"
            },
            Expires = null
        };

        var isValid = await fixture.CapabilityService.ValidateCapabilityAsync(capability);
        isValid.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-16 Invocation proof purpose MUST be capabilityInvocation")]
    public async Task Must16_InvocationProofPurpose_MustBeCapabilityInvocation()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var invocation = new Invocation
        {
            Capability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresources",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resources"
        };

        var proof = await fixture.SigningService.SignInvocationAsync(invocation, controllerDid);
        proof.ProofPurpose.Should().Be("capabilityInvocation");
    }

    [Fact(DisplayName = "MUST-17 Delegation proof purpose MUST be capabilityDelegation")]
    public async Task Must17_DelegationProofPurpose_MustBeCapabilityDelegation()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Proof!.Primary.ProofPurpose.Should().Be("capabilityDelegation");
    }

    [Fact(DisplayName = "SHOULD-01 Root capability ID SHOULD use urn:zcap:root:<encoded-target> format")]
    public async Task Should01_RootId_ShouldUseRecommendedFormat()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resources",
            new[] { "read" });

        root.Id.Should().StartWith("urn:zcap:root:");
    }

    [Fact(DisplayName = "SHOULD-02 Delegated capability ID SHOULD use urn:uuid format")]
    public async Task Should02_DelegatedId_ShouldUseUrnUuidFormat()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.Id.Should().StartWith("urn:uuid:");
    }

    [Fact(DisplayName = "SHOULD-05 capabilityAction SHOULD be read/write")]
    public async Task Should05_CapabilityAction_ShouldBeReadOrWrite()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "admin" },
            DateTime.UtcNow.AddDays(5));

        var isValid = await fixture.CapabilityService.ValidateCapabilityAsync(delegated);
        isValid.Should().BeFalse("SHOULD-05 expects enforcement or explicit validation feedback for non-standard actions.");
    }

    [Fact(DisplayName = "SHOULD-06 Invocation SHOULD include an id field")]
    public void Should06_Invocation_ShouldExposeIdField()
    {
        var invocationIdProperty = typeof(Invocation).GetProperty("Id", BindingFlags.Public | BindingFlags.Instance);
        invocationIdProperty.Should().NotBeNull("SHOULD-06 recommends an invocation id (e.g., for nonce/replay resistance).");
    }

    [Fact(DisplayName = "SHOULD-07 Revocation endpoint support SHOULD be exposed by public API")]
    public void Should07_RevocationEndpoint_ShouldBeSupported()
    {
        var publicServiceMethods = new[]
        {
            typeof(ZcapLd.Core.Services.ICapabilityService),
            typeof(ZcapLd.Core.Services.IVerificationService)
        }
        .SelectMany(t => t.GetMethods())
        .Select(m => m.Name)
        .ToArray();

        publicServiceMethods.Any(m => m.Contains("Revoke", StringComparison.OrdinalIgnoreCase))
            .Should()
            .BeTrue("SHOULD-07 expects revocation endpoint/workflow support to be visible in the public API.");
    }
}
