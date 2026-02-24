using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// End-to-end integration tests for complete ZCAP-LD workflows
/// Tests the full lifecycle: create → delegate → invoke → verify
/// </summary>
public class EndToEndTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly CaveatProcessor _caveatProcessor;
    private readonly VerificationService _verificationService;

    public EndToEndTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _caveatProcessor = new CaveatProcessor();
        _verificationService = new VerificationService(_didProvider, _caveatProcessor);
        _capabilityService = new CapabilityService(_signingService);
    }

    #region Complete Workflow Tests

    [Fact]
    public async Task CompleteWorkflow_CreateRootAndInvoke_ShouldSucceed()
    {
        // Arrange - Create a root capability
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        // Act - Create an invocation
        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);

        // Assert - Verify the invocation
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task CompleteWorkflow_CreateDelegateAndInvoke_ShouldSucceed()
    {
        // Arrange - Create root capability
        var rootController = "did:key:z6MkRootController";
        _didProvider.GenerateAndRegisterKeyPair(rootController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootController,
            "https://api.example.com/documents",
            new[] { "read", "write", "delete" });

        // Delegate to a child
        var childController = "did:key:z6MkChildController";
        _didProvider.GenerateAndRegisterKeyPair(childController);

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childController,
            new[] { "read", "write" }, // Attenuated - no delete
            DateTime.UtcNow.AddDays(30));

        // Act - Child invokes the capability
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, childController);

        // Assert - Verify the invocation
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task CompleteWorkflow_MultiLevelDelegation_ShouldSucceed()
    {
        // Arrange - Create 3-level delegation chain
        var controller1 = "did:key:z6MkController1";
        var controller2 = "did:key:z6MkController2";
        var controller3 = "did:key:z6MkController3";

        _didProvider.GenerateAndRegisterKeyPair(controller1);
        _didProvider.GenerateAndRegisterKeyPair(controller2);
        _didProvider.GenerateAndRegisterKeyPair(controller3);

        // Root capability
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controller1,
            "https://api.example.com/resources",
            new[] { "read", "write", "delete", "admin" });

        // First delegation
        var level1Capability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controller2,
            new[] { "read", "write", "delete" }, // No admin
            DateTime.UtcNow.AddDays(60));

        // Second delegation
        var level2Capability = await _capabilityService.DelegateCapabilityAsync(
            level1Capability,
            controller3,
            new[] { "read", "write" }, // Only read and write
            DateTime.UtcNow.AddDays(30));

        // Act - Controller3 invokes
        var invocation = new Invocation
        {
            Capability = level2Capability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/resources/item1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controller3);

        // Assert - Verify the complete chain
        var chainIsValid = await _verificationService.VerifyCapabilityChainAsync(level2Capability);
        chainIsValid.Should().BeTrue();

        var invocationIsValid = await _verificationService.VerifyInvocationAsync(invocation, level2Capability);
        invocationIsValid.Should().BeTrue();
    }

    #endregion

    #region Caveat Integration Tests

    [Fact]
    public async Task CompleteWorkflow_WithExpirationCaveat_ShouldEnforce()
    {
        // Arrange - Create delegated capability with expiration caveat
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var expirationCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddHours(1) // Expires in 1 hour
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { expirationCaveat });

        // Act - Invoke before expiration
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        // Assert - Should succeed
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task CompleteWorkflow_WithExpiredCaveat_ShouldReject()
    {
        // Arrange - Create delegated capability with expired caveat
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var expirationCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddHours(-1) // Already expired
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { expirationCaveat });

        // Act - Try to invoke after expiration
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        // Assert - Should fail
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_WithUsageCountCaveat_ShouldEnforce()
    {
        // Arrange - Create delegated capability with usage count caveat
        var rootControllerDid = "did:key:z6MkRootController";
        var delegatedControllerDid = "did:key:z6MkDelegatedController";
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var usageCaveat = new UsageCountCaveat
        {
            MaxUses = 3,
            CurrentUses = 0
        };

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootControllerDid,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[] { usageCaveat });

        // Act - Invoke within usage limit
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        // Assert - Should succeed
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();

        // Simulate usage increments
        usageCaveat.CurrentUses = 1;
        isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();

        usageCaveat.CurrentUses = 2;
        isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();

        // At limit - should fail
        usageCaveat.CurrentUses = 3;
        isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_WithInheritedCaveats_ShouldEnforceAll()
    {
        // Arrange - Create chain with caveats at each level
        var controller1 = "did:key:z6MkController1";
        var controller2 = "did:key:z6MkController2";

        _didProvider.GenerateAndRegisterKeyPair(controller1);
        _didProvider.GenerateAndRegisterKeyPair(controller2);

        // Root without caveats; add caveat on first delegation.
        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controller1,
            "https://api.example.com/documents",
            new[] { "read", "write" });

        var parentDelegation = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controller1,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(7),
            new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(10) }
            });

        // Second delegation with additional usage count caveat.
        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            parentDelegation,
            controller2,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[]
            {
                new UsageCountCaveat { MaxUses = 5, CurrentUses = 0 }
            });

        // Act - Invoke
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controller2);

        // Assert - Should verify both caveats
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();

        // Verify that both caveats are inherited
        delegatedCapability.Caveat.Should().HaveCount(2);
        delegatedCapability.Caveat.Should().Contain(c => c.Type == "Expiration");
        delegatedCapability.Caveat.Should().Contain(c => c.Type == "UsageCount");
    }

    #endregion

    #region Attenuation Enforcement Tests

    [Fact]
    public async Task CompleteWorkflow_AttenuatedActions_ShouldRejectUnauthorizedAction()
    {
        // Arrange - Delegate with restricted actions
        var rootController = "did:key:z6MkRootController";
        var childController = "did:key:z6MkChildController";

        _didProvider.GenerateAndRegisterKeyPair(rootController);
        _didProvider.GenerateAndRegisterKeyPair(childController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootController,
            "https://api.example.com/documents",
            new[] { "read", "write", "delete" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childController,
            new[] { "read" }, // Only read allowed
            DateTime.UtcNow.AddDays(30));

        // Act - Try to invoke with "write" action (not allowed)
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "write", // Not in allowed actions
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, childController);

        // Assert - Should fail
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_AttenuatedTarget_ShouldRejectWrongTarget()
    {
        // Arrange - Delegate with specific target
        var rootController = "did:key:z6MkRootController";
        var childController = "did:key:z6MkChildController";

        _didProvider.GenerateAndRegisterKeyPair(rootController);
        _didProvider.GenerateAndRegisterKeyPair(childController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootController,
            "https://api.example.com/documents/folder1",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act - Try to invoke with wrong target
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/folder2/doc1" // Different folder
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, childController);

        // Assert - Should fail
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_ValidTargetPrefix_ShouldSucceed()
    {
        // Arrange
        var rootController = "did:key:z6MkRootController";
        var childController = "did:key:z6MkChildController";

        _didProvider.GenerateAndRegisterKeyPair(rootController);
        _didProvider.GenerateAndRegisterKeyPair(childController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            rootController,
            "https://api.example.com/documents",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childController,
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Act - Invoke with valid prefix extension
        var invocation = new Invocation
        {
            Capability = delegatedCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/folder1/doc1" // Valid prefix
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, childController);

        // Assert - Should succeed
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);
        isValid.Should().BeTrue();
    }

    #endregion

    #region Error Handling Tests

    [Fact]
    public async Task CompleteWorkflow_UnauthorizedSigner_ShouldReject()
    {
        // Arrange - Create capability for one controller
        var authorizedController = "did:key:z6MkAuthorizedController";
        var unauthorizedController = "did:key:z6MkUnauthorizedController";

        _didProvider.GenerateAndRegisterKeyPair(authorizedController);
        _didProvider.GenerateAndRegisterKeyPair(unauthorizedController);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            authorizedController,
            "https://api.example.com/documents",
            new[] { "read" });

        // Act - Unauthorized controller tries to invoke
        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://api.example.com/documents/doc1"
        };

        // Sign with wrong controller
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, unauthorizedController);

        // Assert - Should fail
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, rootCapability);
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_TamperedCapability_ShouldReject()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var childDid = "did:key:z6MkChild";

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://api.example.com/documents",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(30));

        // Tamper with the capability after signing
        delegatedCapability.AllowedAction = new[] { "read", "write", "delete" };

        // Act - Try to verify tampered capability
        var isValid = await _verificationService.VerifyCapabilityProofAsync(delegatedCapability);

        // Assert - Should fail
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task CompleteWorkflow_ExpiredCapability_ShouldReject()
    {
        // Arrange - Create capability with past expiration
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var childDid = "did:key:z6MkChild";

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://api.example.com/documents",
            new[] { "read" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(-1)); // Expired

        // Act - Verify chain should fail due to expiration
        var chainIsValid = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert
        chainIsValid.Should().BeFalse();
    }

    #endregion

    #region Real-World Scenario Tests

    [Fact]
    public async Task RealWorldScenario_DocumentSharingWorkflow_ShouldWork()
    {
        // Scenario: Alice shares a document with Bob, Bob shares read-only access with Carol

        // Arrange
        var alice = "did:key:z6MkAlice";
        var bob = "did:key:z6MkBob";
        var carol = "did:key:z6MkCarol";

        _didProvider.GenerateAndRegisterKeyPair(alice);
        _didProvider.GenerateAndRegisterKeyPair(bob);
        _didProvider.GenerateAndRegisterKeyPair(carol);

        // Alice creates root capability for her document
        var aliceCapability = await _capabilityService.CreateRootCapabilityAsync(
            alice,
            "https://storage.example.com/documents/alice-report.pdf",
            new[] { "read", "write", "share" });

        // Alice delegates to Bob with read and share permissions for 7 days
        var bobCapability = await _capabilityService.DelegateCapabilityAsync(
            aliceCapability,
            bob,
            new[] { "read", "share" },
            DateTime.UtcNow.AddDays(7));

        // Bob delegates to Carol with only read permission for 3 days
        var carolCapability = await _capabilityService.DelegateCapabilityAsync(
            bobCapability,
            carol,
            new[] { "read" },
            DateTime.UtcNow.AddDays(3));

        // Act - Carol tries to read the document
        var carolInvocation = new Invocation
        {
            Capability = carolCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://storage.example.com/documents/alice-report.pdf"
        };

        carolInvocation.Proof = await _signingService.SignInvocationAsync(carolInvocation, carol);

        // Assert - Carol can read
        var carolCanRead = await _verificationService.VerifyInvocationAsync(carolInvocation, carolCapability);
        carolCanRead.Should().BeTrue();

        // Act - Carol tries to share (should fail)
        var carolShareInvocation = new Invocation
        {
            Capability = carolCapability.Id,
            CapabilityAction = "share",
            InvocationTarget = "https://storage.example.com/documents/alice-report.pdf"
        };

        carolShareInvocation.Proof = await _signingService.SignInvocationAsync(carolShareInvocation, carol);

        // Assert - Carol cannot share
        var carolCanShare = await _verificationService.VerifyInvocationAsync(carolShareInvocation, carolCapability);
        carolCanShare.Should().BeFalse();

        // Act - Bob tries to read (should succeed)
        var bobInvocation = new Invocation
        {
            Capability = bobCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://storage.example.com/documents/alice-report.pdf"
        };

        bobInvocation.Proof = await _signingService.SignInvocationAsync(bobInvocation, bob);

        // Assert - Bob can read
        var bobCanRead = await _verificationService.VerifyInvocationAsync(bobInvocation, bobCapability);
        bobCanRead.Should().BeTrue();
    }

    [Fact]
    public async Task RealWorldScenario_APIAccessWithRateLimiting_ShouldWork()
    {
        // Scenario: API provider grants access with usage limits

        // Arrange
        var apiProvider = "did:key:z6MkAPIProvider";
        var customer = "did:key:z6MkCustomer";

        _didProvider.GenerateAndRegisterKeyPair(apiProvider);
        _didProvider.GenerateAndRegisterKeyPair(customer);

        // API provider creates root capability
        var apiCapability = await _capabilityService.CreateRootCapabilityAsync(
            apiProvider,
            "https://api.example.com/v1/data",
            new[] { "query", "download" });

        // Delegate to customer with usage count and expiration
        var customerCapability = await _capabilityService.DelegateCapabilityAsync(
            apiCapability,
            customer,
            new[] { "query" }, // Only query, no download
            DateTime.UtcNow.AddMonths(1),
            new Caveat[]
            {
                new UsageCountCaveat { MaxUses = 100, CurrentUses = 0 },
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddMonths(1) }
            });

        // Act - Customer makes valid query
        var invocation = new Invocation
        {
            Capability = customerCapability.Id,
            CapabilityAction = "query",
            InvocationTarget = "https://api.example.com/v1/data?filter=active"
        };

        invocation.Proof = await _signingService.SignInvocationAsync(invocation, customer);

        // Assert - Should succeed
        var isValid = await _verificationService.VerifyInvocationAsync(invocation, customerCapability);
        isValid.Should().BeTrue();

        // Verify caveats are in place
        customerCapability.Caveat.Should().HaveCount(2);
        customerCapability.Caveat.Should().Contain(c => c.Type == "UsageCount");
        customerCapability.Caveat.Should().Contain(c => c.Type == "Expiration");
    }

    #endregion
}
