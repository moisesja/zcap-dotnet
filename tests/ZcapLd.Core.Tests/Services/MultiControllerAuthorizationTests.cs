using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Authorization tests for multi-controller capabilities (Issue #47). A capability whose
/// <c>controller</c> is an array of DIDs must accept an invocation or delegation signed by
/// ANY controller in the set, and reject one signed by a key outside it.
/// </summary>
public class MultiControllerAuthorizationTests
{
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;
    private readonly VerificationService _verificationService;

    private const string Target = "https://api.example.com/resource";

    public MultiControllerAuthorizationTests()
    {
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _verificationService = new VerificationService(_didProvider, new CaveatProcessor());
        _capabilityService = new CapabilityService(_signingService);
    }

    // ─── Root invocation authorization ─────────────────────────────────

    [Theory]
    [InlineData(0)] // signed by Alice (controller[0])
    [InlineData(1)] // signed by Bob (controller[1])
    public async Task RootInvocation_SignedByAnyController_Verifies(int signerIndex)
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var signer = signerIndex == 0 ? alice : bob;

        var root = await _capabilityService.CreateRootCapabilityAsync(
            new[] { alice, bob },
            Target,
            new[] { "read" });
        root.Controller.IsArrayForm.Should().BeTrue();

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, signer);

        var isValid = await _verificationService.VerifyInvocationAsync(invocation, root);

        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task RootInvocation_SignedByNonController_Fails()
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var mallory = _didProvider.GenerateDidKey(); // a real, resolvable key — but not a controller

        var root = await _capabilityService.CreateRootCapabilityAsync(
            new[] { alice, bob },
            Target,
            new[] { "read" });

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        // Mallory's signature is cryptographically valid; authorization must still reject it.
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, mallory);

        var isValid = await _verificationService.VerifyInvocationAsync(invocation, root);

        isValid.Should().BeFalse();
    }

    // ─── Delegation authorization ──────────────────────────────────────

    [Theory]
    [InlineData(0)] // delegation signed by Alice
    [InlineData(1)] // delegation signed by Bob
    public async Task Delegation_SignedByAnyParentController_Verifies(int signerIndex)
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var carol = _didProvider.GenerateDidKey();
        var signer = signerIndex == 0 ? alice : bob;

        var root = await _capabilityService.CreateRootCapabilityAsync(
            new[] { alice, bob },
            Target,
            new[] { "read" });

        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root,
            carol,
            new[] { "read" },
            expires: DateTime.UtcNow.AddDays(1),
            signerDid: signer);

        var chainValid = await _verificationService.VerifyCapabilityChainAsync(delegated);
        var proofValid = await _verificationService.VerifyCapabilityProofAsync(delegated);

        chainValid.Should().BeTrue();
        proofValid.Should().BeTrue();
    }

    [Fact]
    public async Task Delegation_ServiceRejectsSignerOutsideParentControllers()
    {
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var carol = _didProvider.GenerateDidKey();
        var mallory = _didProvider.GenerateDidKey();

        var root = await _capabilityService.CreateRootCapabilityAsync(
            new[] { alice, bob },
            Target,
            new[] { "read" });

        var act = async () => await _capabilityService.DelegateCapabilityAsync(
            root,
            carol,
            new[] { "read" },
            expires: DateTime.UtcNow.AddDays(1),
            signerDid: mallory);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Delegation_SignedByNonController_FailsVerification()
    {
        // Bypass the service guard to construct a delegation actually signed by a
        // non-controller (Mallory). The verifier must reject it because Mallory's
        // verification method is not among the parent root's controllers.
        var alice = _didProvider.GenerateDidKey();
        var bob = _didProvider.GenerateDidKey();
        var carol = _didProvider.GenerateDidKey();
        var mallory = _didProvider.GenerateDidKey();

        var root = await _capabilityService.CreateRootCapabilityAsync(
            new[] { alice, bob },
            Target,
            new[] { "read" });

        var suiteContextUrl = await _signingService.ResolveSuiteContextUrlAsync(mallory);
        var delegated = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", suiteContextUrl },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = carol,
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1)),
            ParentCapability = root.Id
        };
        // Root parent chain: [rootId, rootObject].
        var chain = new object[] { root.Id, root };
        delegated.Proof = await _signingService.SignCapabilityAsync(
            delegated, mallory, "capabilityDelegation", chain);

        var proofValid = await _verificationService.VerifyCapabilityProofAsync(delegated);

        proofValid.Should().BeFalse();
    }
}
