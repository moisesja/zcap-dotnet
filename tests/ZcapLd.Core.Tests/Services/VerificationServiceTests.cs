using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

public class VerificationServiceTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor;
    private readonly VerificationService _verificationService;

    public VerificationServiceTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _caveatProcessor = new CaveatProcessor();
        _verificationService = new VerificationService(_didProvider, _caveatProcessor);
        _capabilityService = new CapabilityService(_signingService);
    }

    #region Capability Proof Verification Tests

    [Fact]
    public async Task VerifyCapabilityProof_RootCapability_ShouldReturnTrue()
    {
        // Arrange
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkRoot",
            "https://example.com/resource",
            new[] { "read" });

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(rootCapability);

        // Assert
        result.Should().BeTrue(); // Root capabilities have no proof, which is valid
    }

    [Fact]
    public async Task VerifyCapabilityProof_ValidDelegation_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WhenResolvedKeyTypeMismatchesSuite_ReturnsFalse()
    {
        // Issue #68: the suite is chosen from proof.Type; the resolved key's type must match it.
        // Here the key bytes are correct (signature would verify), but a resolver reports a
        // mismatched KeyType — the explicit binding guard must reject it before/independently of
        // the signature check.
        var controllerDid = "did:key:z6MkKeyTypeBinding";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid, "https://example.com/resource", new[] { "read" });

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Verifier whose resolver returns the correct key bytes but a mismatched key type.
        var mismatchVerifier = new VerificationService(
            new WrongKeyTypeResolver(_didProvider, "EcdsaSecp256r1VerificationKey2019"),
            _caveatProcessor);

        (await mismatchVerifier.VerifyInvocationAsync(invocation, root)).Should().BeFalse();

        // Sanity: the same invocation verifies under the honest resolver (so the only failing
        // factor above is the key-type/suite mismatch).
        var honestVerifier = new VerificationService(_didProvider, _caveatProcessor);
        (await honestVerifier.VerifyInvocationAsync(invocation, root)).Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_WhenItFailsClosed_LogsTheCause()
    {
        // Issue #64: failing closed is correct, but the cause must not be discarded silently.
        // A delegated capability whose chain cannot be reconstructed throws internally; the
        // top-level catch must return false AND emit a diagnostic via the injected logger.
        var logger = new CapturingLogger<VerificationService>();
        var verifier = new VerificationService(
            _didProvider,
            _caveatProcessor,
            VerificationService.CreateDefaultSuiteProvider(),
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(),
            SigningService.CreateDefaultCanonicalizerProvider(),
            nonceWindow: null,
            logger: logger);

        // Looks delegated (has parentCapability) but carries no proof/chain → BuildCapabilityChainAsync throws.
        var malformed = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:malformed",
            Controller = "did:key:z6MkLogChild",
            InvocationTarget = "https://example.com/resource",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource"
        };

        var result = await verifier.VerifyCapabilityChainAsync(malformed);

        result.Should().BeFalse("fail-closed is preserved");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Exception != null,
            "the swallowed cause must be logged, not discarded");
    }

    [Fact]
    public async Task VerifyCapabilityProof_WithRevokedImmediateParent_ShouldReturnFalse()
    {
        // Issue #63: VerifyCapabilityProofAsync previously checked only the leaf's revocation,
        // ignoring the immediate parent embedded in proof.capabilityChain. A capability whose
        // ancestor has been revoked must not pass the single-proof check either.
        var rootDid = "did:key:z6MkRevParentRoot";
        var midDid = "did:key:z6MkRevParentMid";
        var leafDid = "did:key:z6MkRevParentLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(midDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            mid, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(10));

        // Sanity: before revocation the leaf's proof verifies.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeTrue();

        // Revoke the immediate parent (mid).
        await _verificationService.RevokeCapabilityAsync(mid.Id, rootDid);

        // The single-proof check must now also reject the leaf, matching VerifyCapabilityChainAsync.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(leaf)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_AfterJsonRoundTrip_ShouldReturnTrue()
    {
        // Arrange — simulates HTTP POST: serialize capability → deserialize on server
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // JSON round-trip: object → JSON string → new object
        // This converts native C# types (string, object[], Capability) to JsonElement,
        // which is exactly what happens when ASP.NET Core deserializes a POST body.
        var json = JsonSerializer.Serialize(delegatedCapability);
        var deserialized = JsonSerializer.Deserialize<Capability>(json)!;

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(deserialized);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityProof_RootWithProof_ShouldReturnFalse()
    {
        // Arrange - Create a malformed root capability with a proof
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkRoot",
            "https://example.com/resource",
            new[] { "read" });

        rootCapability.Proof = new Proof
        {
            Type = "Ed25519Signature2020",
            ProofValue = "z123...",
            ProofPurpose = "capabilityDelegation"
        };

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(rootCapability);

        // Assert
        result.Should().BeFalse(); // Root capabilities MUST NOT have proofs
    }

    [Fact]
    public async Task VerifyCapabilityProof_DelegationWithoutProof_ShouldReturnFalse()
    {
        // Arrange - Create a malformed delegated capability without a proof
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:test",
            ParentCapability = "urn:zcap:root:something",
            Controller = "did:key:z6MkChild",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Proof = null // Missing required proof
        };

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(capability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_InvalidProofPurpose_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Corrupt the proof purpose
        delegatedCapability.Proof!.Primary.ProofPurpose = "capabilityInvocation"; // Wrong purpose

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_WithTamperedVerificationMethod_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        var attackerDid = "did:key:z6MkAttacker";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);
        _didProvider.GenerateAndRegisterKeyPair(attackerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        delegatedCapability.Proof!.Primary.VerificationMethod = await _didProvider.GetVerificationMethodAsync(attackerDid);

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_WithTamperedCapabilityChain_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        delegatedCapability.Proof!.Primary.CapabilityChain![0] = "urn:zcap:root:tampered";

        // Act
        var result = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Capability Chain Verification Tests

    [Fact]
    public async Task VerifyCapabilityChain_ValidSingleLevelChain_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_SelfSignedDelegationWithoutEmbeddedParent_ShouldReturnFalse()
    {
        // Arrange
        var rootDid = "did:key:z6MkRoot";
        var childDid = "did:key:z6MkChild";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(childDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var suiteContext = await _signingService.ResolveSuiteContextUrlAsync(childDid);
        var delegatedCapability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", suiteContext },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = rootCapability.Id,
            Controller = childDid,
            InvocationTarget = rootCapability.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(5))
        };

        // Malicious chain omits the embedded immediate parent object.
        delegatedCapability.Proof = await _signingService.SignCapabilityAsync(
            delegatedCapability,
            childDid,
            "capabilityDelegation",
            new object[] { rootCapability.Id });

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityChain_ValidMultiLevelChain_ShouldReturnTrue()
    {
        // Arrange
        var controller1 = "did:key:z6MkController1";
        var controller2 = "did:key:z6MkController2";
        var controller3 = "did:key:z6MkController3";

        _didProvider.GenerateAndRegisterKeyPair(controller1);
        _didProvider.GenerateAndRegisterKeyPair(controller2);
        _didProvider.GenerateAndRegisterKeyPair(controller3);

        // Create root
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controller1,
            "https://example.com/resource",
            new[] { "read", "write", "delete" });

        // First delegation
        var level1 = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controller2,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(30));

        // Second delegation
        var level2 = await _capabilityService.DelegateCapabilityAsync(
            level1,
            controller3,
            new[] { "read" },
            DateTime.UtcNow.AddDays(20));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(level2);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_ExceedsMaxLength_ShouldReturnFalse()
    {
        // Arrange - Create a chain longer than 10 delegations
        var controllers = new List<string>();
        for (int i = 0; i <= 11; i++)
        {
            var did = $"did:key:z6MkController{i}";
            controllers.Add(did);
            _didProvider.GenerateAndRegisterKeyPair(did);
        }

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllers[0],
            "https://example.com/resource",
            new[] { "read" });

        Capability current = rootCapability;
        for (int i = 1; i <= 11; i++)
        {
            current = await _capabilityService.DelegateCapabilityAsync(
                current,
                controllers[i],
                new[] { "read" },
                DateTime.UtcNow.AddDays(30));
        }

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(current);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityChain_WithExpiredCapability_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        // Create delegation with expiration in the past
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(-1)); // Expired

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Attenuation Validation Tests

    [Fact]
    public async Task VerifyCapabilityChain_ValidAttenuation_ShouldReturnTrue()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read", "write", "delete" });

        // Delegate with subset of actions (proper attenuation)
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" }, // Subset of parent's actions
            DateTime.UtcNow.AddDays(30));

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyCapabilityChain_InvalidTargetAttenuation_ShouldReturnFalse()
    {
        // Arrange
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resource",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Corrupt the invocation target to an invalid value
        delegatedCapability.InvocationTarget = "https://different.com/resource";

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Invocation Verification Tests

    [Fact]
    public async Task VerifyInvocation_ValidInvocation_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        // Sign the invocation
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_AfterJsonRoundTrip_ShouldReturnTrue()
    {
        // Regression for issue #58: a resource server receives invocations as JSON and
        // deserializes them. After the round-trip Proof.Capability is a JsonElement, not a
        // CLR string, so the proof/invocation consistency check must normalize it rather
        // than rely on an `as string` cast (which would reject every valid wire invocation).
        var controllerDid = "did:key:z6MkRoundTripController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Round-trip through JSON exactly as a resource server would receive it. (We verify
        // only the deserialized form — verifying the in-memory form first would consume the
        // invocation's nonce, and replay protection is on by default; the in-memory path is
        // already covered by VerifyInvocation_ValidInvocation_ShouldReturnTrue.)
        var json = JsonSerializer.Serialize(invocation, ZcapJsonOptions.Default);
        var received = JsonSerializer.Deserialize<Invocation>(json, ZcapJsonOptions.Default);
        received.Should().NotBeNull();

        // Act: verify the deserialized invocation.
        var result = await _verificationService.VerifyInvocationAsync(received!, rootCapability);

        // Assert: the same valid, untampered invocation must verify over the wire.
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithInvalidAction_ShouldReturnFalse()
    {
        // Arrange
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "write", // Not allowed
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithMismatchedCapabilityReference_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var invocation = new Invocation
        {
            Capability = "urn:uuid:not-the-capability-under-verification",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithInvalidTarget_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://different.com/resource" // Wrong target
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithValidTargetPrefix_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        // Invoke with a valid prefix extension
        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource/subpath" // Valid prefix
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithoutProof_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource",
            Proof = null // No proof
        };

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithWrongProofPurpose_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        invocation.Proof.ProofPurpose = "capabilityDelegation"; // Wrong purpose

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithMismatchedProofFields_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        invocation.Proof.CapabilityAction = "write";

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithCaveats_ShouldEvaluateThem()
    {
        // Arrange
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var expiredCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(-1) // Expired
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { expiredCaveat });

        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);

        // Assert
        result.Should().BeFalse(); // Caveat should cause failure
    }

    [Fact]
    public async Task VerifyInvocation_WithContextProperties_ShouldPassToCustomCaveat()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var caveat = new ContentTypeCaveat { RequiredContentType = "application/json" };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controllerDid,
            new[] { "write" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { caveat });

        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "write",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act — inject the property the caveat expects
        var result = await _verificationService.VerifyInvocationAsync(
            invocation,
            delegatedCapability,
            new Dictionary<string, object> { ["contentType"] = "application/json" });

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithContextProperties_WrongValue_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var caveat = new ContentTypeCaveat { RequiredContentType = "application/json" };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controllerDid,
            new[] { "write" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { caveat });

        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "write",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act — inject a wrong content type
        var result = await _verificationService.VerifyInvocationAsync(
            invocation,
            delegatedCapability,
            new Dictionary<string, object> { ["contentType"] = "text/plain" });

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithNullContextProperties_ShouldSucceed()
    {
        // Arrange — same setup as valid invocation, but call the 3-param overload with null
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, rootCapability, null);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyInvocation_WithEmptyContextProperties_ShouldSucceed()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(
            invocation, rootCapability, new Dictionary<string, object>());

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region Revocation Tests

    [Fact]
    public async Task VerifyCapabilityChain_WithRevokedLeaf_ShouldReturnFalse()
    {
        // Arrange
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5));

        await _verificationService.RevokeCapabilityAsync(delegatedCapability.Id, rootControllerDid);

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyInvocation_WithRevokedCapability_ShouldReturnFalse()
    {
        // Arrange
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5));

        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = delegatedCapability.InvocationTarget
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        await _verificationService.RevokeCapabilityAsync(delegatedCapability.Id, rootControllerDid);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_AuthorizedUpChainController_RevokesAndReturnsTrue()
    {
        // Issue #60: the Capability overload authorizes the revoker against the delegation chain.
        // The root controller is an up-chain delegator and must be allowed to revoke a child.
        var rootControllerDid = "did:key:z6MkRevokeRoot";
        var delegatedControllerDid = "did:key:z6MkRevokeChild";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, delegatedControllerDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, rootControllerDid);

        revoked.Should().BeTrue();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeCapability_UnauthorizedRevoker_ReturnsFalseAndDoesNotRevoke()
    {
        // Issue #60: Mallory controls nothing in the chain, so the authorizing overload must
        // refuse to revoke — and must NOT record anything (no unauthenticated denial-of-capability).
        var rootControllerDid = "did:key:z6MkAuthzRoot";
        var delegatedControllerDid = "did:key:z6MkAuthzChild";
        const string malloryDid = "did:key:z6MkMalloryHasNoAuthority";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, delegatedControllerDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, malloryDid);

        revoked.Should().BeFalse();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCapability_OwnControllerSelfRevoke_RevokesAndReturnsTrue()
    {
        // A capability's own controller is authorized to revoke it (self-revocation).
        var rootControllerDid = "did:key:z6MkSelfRoot";
        var delegatedControllerDid = "did:key:z6MkSelfChild";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, delegatedControllerDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));

        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, delegatedControllerDid);

        revoked.Should().BeTrue();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    #endregion

    #region DID Resolution Tests

    [Fact]
    public async Task ResolvePublicKey_WithDidKey_ShouldExtractPublicKey()
    {
        // Arrange
        var did = "did:key:z6MkTest";
        var (privateKey, publicKey) = _didProvider.GenerateAndRegisterKeyPair(did);
        var verificationMethod = await _didProvider.GetVerificationMethodAsync(did);

        // Act
        var resolvedKey = await _verificationService.ResolvePublicKeyAsync(verificationMethod);

        // Assert
        resolvedKey.Should().NotBeNull();
        resolvedKey.PublicKeyBytes.Should().HaveCount(32); // Ed25519 public keys are 32 bytes
    }

    [Fact]
    public async Task ResolvePublicKey_WithInvalidDid_ShouldThrow()
    {
        // Arrange
        var invalidDid = "did:invalid:xyz";

        // Act & Assert
        var act = async () => await _verificationService.ResolvePublicKeyAsync(invalidDid);
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }

    [Fact]
    public async Task ResolvePublicKey_WithEmptyDid_ShouldThrow()
    {
        // Arrange
        var emptyDid = "";

        // Act & Assert
        var act = async () => await _verificationService.ResolvePublicKeyAsync(emptyDid);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region Edge Cases and Error Handling

    [Fact]
    public async Task VerifyCapabilityProof_WithNullCapability_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _verificationService.VerifyCapabilityProofAsync(null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyInvocation_WithNullInvocation_ShouldThrow()
    {
        // Arrange
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkTest",
            "https://example.com/resource",
            new[] { "read" });

        // Act & Assert
        var act = async () => await _verificationService.VerifyInvocationAsync(null!, capability);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyInvocation_WithNullCapability_ShouldThrow()
    {
        // Arrange
        var invocation = new Invocation
        {
            Capability = "urn:zcap:root:test",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };

        // Act & Assert
        var act = async () => await _verificationService.VerifyInvocationAsync(invocation, null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task VerifyCapabilityChain_WithNullCapability_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _verificationService.VerifyCapabilityChainAsync(null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    #endregion
}

/// <summary>
/// Test caveat that reads "contentType" from InvocationContext.Properties.
/// Used to verify that contextProperties flow through the verification pipeline.
/// </summary>
internal class ContentTypeCaveat : Caveat
{
    public override string Type => "ContentType";
    public string RequiredContentType { get; set; } = string.Empty;

    public override bool IsSatisfied(InvocationContext context)
    {
        return context.Properties.TryGetValue("contentType", out var value)
            && value is string contentType
            && string.Equals(contentType, RequiredContentType, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Wraps an inner resolver but overrides the resolved key's type with a deliberately wrong value
/// (Issue #68 test support) — the key bytes stay correct so only the key-type/suite binding differs.
/// </summary>
internal sealed class WrongKeyTypeResolver : IDidResolver
{
    private readonly IDidResolver _inner;
    private readonly string _wrongKeyType;

    public WrongKeyTypeResolver(IDidResolver inner, string wrongKeyType)
    {
        _inner = inner;
        _wrongKeyType = wrongKeyType;
    }

    public async Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var key = await _inner.ResolvePublicKeyAsync(didOrVerificationMethod);
        return new ResolvedKey(key.PublicKeyBytes, _wrongKeyType);
    }

    public Task<string> GetVerificationMethodAsync(string did) => _inner.GetVerificationMethodAsync(did);
}

/// <summary>Minimal in-memory <see cref="ILogger{T}"/> that records emitted entries (Issue #64 test support).</summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, Exception? Exception, string Message)> Entries { get; } = new();

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
        => Entries.Add((logLevel, exception, formatter(state, exception)));

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}
