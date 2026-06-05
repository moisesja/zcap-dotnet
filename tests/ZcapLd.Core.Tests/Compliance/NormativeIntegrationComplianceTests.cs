using System.Reflection;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Compliance;

public class NormativeIntegrationComplianceTests
{
    [Fact(DisplayName = "MUST-09 Verifier MUST ensure delegated zcap was created by parent controller")]
    public async Task Must09_Verifier_MustRejectDelegationSignedByUnauthorizedController()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();
        var attackerDid = fixture.RegisterControllerDid();

        // Register the root so the verifier can resolve it (spec-exact first-level chain is [rootId]),
        // isolating the property under test: the signature, not the chain shape, is unauthorized.
        var root = fixture.DidProvider.RegisterRoot(await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" }));

        var delegated = new Capability
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = root.Id,
            Controller = childDid,
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(5))
        };

        // Spec-exact first-level chain, but signed by an attacker who is not the root's controller.
        delegated.Proof = await fixture.SigningService.SignCapabilityAsync(
            delegated,
            attackerDid,
            "capabilityDelegation",
            new object[] { root.Id });

        var result = await fixture.VerificationService.VerifyCapabilityProofAsync(delegated);
        result.Should().BeFalse("MUST-09 requires delegation signatures to be authorized by the parent controller.");
    }

    [Fact(DisplayName = "MUST-10 Verifier MUST enforce invocationTarget attenuation")]
    public async Task Must10_Verifier_MustEnforceInvocationTargetAttenuation()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        delegated.InvocationTarget = "https://another.example.com/resources";

        var result = await fixture.VerificationService.VerifyCapabilityChainAsync(delegated);
        result.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-11 Verifier MUST reject child expiration later than parent")]
    public async Task Must11_Verifier_MustRejectLessRestrictiveExpiration()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var middleDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read" });

        var parentDelegation = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            middleDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(7));

        var act = async () => await fixture.CapabilityService.DelegateCapabilityAsync(
            parentDelegation,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(14));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact(DisplayName = "MUST-12 Verifier MUST reject allowedAction expansion")]
    public async Task Must12_Verifier_MustRejectAllowedActionExpansion()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var middleDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var parentDelegation = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            middleDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(10));

        var act = async () => await fixture.CapabilityService.DelegateCapabilityAsync(
            parentDelegation,
            childDid,
            new[] { "read", "write" },
            DateTime.UtcNow.AddDays(7));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact(DisplayName = "MUST-13 Verifier MUST limit chain length to prevent long-chain attacks")]
    public async Task Must13_Verifier_MustLimitCapabilityChainLength()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDids = Enumerable.Range(0, 12)
            .Select(_ => fixture.RegisterControllerDid())
            .ToArray();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDids[0],
            "https://example.com/resources",
            new[] { "read" });

        Capability current = root;
        var days = 60;
        for (int i = 1; i < controllerDids.Length; i++)
        {
            current = await fixture.CapabilityService.DelegateCapabilityAsync(
                current,
                controllerDids[i],
                new[] { "read" },
                DateTime.UtcNow.AddDays(days--));
        }

        var result = await fixture.VerificationService.VerifyCapabilityChainAsync(current);
        result.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-14 Verifier MUST reject expired delegated capabilities")]
    public async Task Must14_Verifier_MustRejectExpiredDelegatedCapabilities()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read" });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(-1));

        var result = await fixture.VerificationService.VerifyCapabilityChainAsync(delegated);
        result.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-18 Verifier MUST NOT require network/database dereferencing for local chain verification")]
    public async Task Must18_Verifier_MustValidateEmbeddedChainWithoutNetworkDereference()
    {
        var fixture = new ComplianceTestFixture();
        var rootDid = fixture.RegisterControllerDid();
        var level1Did = fixture.RegisterControllerDid();
        var level2Did = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            rootDid,
            "https://example.com/resources",
            new[] { "read", "write" });

        var level1 = new Capability
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = root.Id,
            Controller = level1Did,
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read", "write" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(20))
        };
        level1.Proof = await fixture.SigningService.SignCapabilityAsync(
            level1,
            rootDid,
            "capabilityDelegation",
            new object[] { root.Id }); // spec-exact first-level chain: root by id only, never embedded

        var level2 = new Capability
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = level1.Id,
            Controller = level2Did,
            InvocationTarget = root.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(10))
        };
        level2.Proof = await fixture.SigningService.SignCapabilityAsync(
            level2,
            level1Did,
            "capabilityDelegation",
            new object[] { root.Id, level1 });

        // The root is supplied in-process (explicit-root overload) — verification dereferences NOTHING
        // over the network or a database; the root a spec-exact chain references by id is provided locally.
        var isValid = await fixture.VerificationService.VerifyCapabilityChainAsync(level2, root);
        isValid.Should().BeTrue("MUST-18 requires local chain verification without network dereferencing.");
    }

    [Fact(DisplayName = "MUST-19 Verifier MUST validate signature integrity for each proof")]
    public async Task Must19_Verifier_MustRejectTamperedDelegationProofs()
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
            DateTime.UtcNow.AddDays(7));

        delegated.AllowedAction = new[] { "read", "write" };

        var result = await fixture.VerificationService.VerifyCapabilityProofAsync(delegated);
        result.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-20 Verifier MUST evaluate caveats across the capability chain")]
    public async Task Must20_Verifier_MustEvaluateAllChainCaveats()
    {
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var middleDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read" });

        var parentDelegation = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            middleDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(14),
            new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddMinutes(-5) }
            });

        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            parentDelegation,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(7));

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = delegated.InvocationTarget
        };
        invocation.Proof = await fixture.SigningService.SignInvocationAsync(invocation, childDid);

        var result = await fixture.VerificationService.VerifyInvocationAsync(invocation, delegated);
        result.Should().BeFalse();
    }

    [Fact(DisplayName = "MUST-21 Verifier MUST store revoked zcaps until expiration")]
    public void Must21_Verifier_MustPersistRevokedCapabilitiesUntilExpiration()
    {
        var revocationMembers = typeof(ZcapLd.Core.Services.VerificationService)
            .GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Where(m => m.Name.Contains("Revoke", StringComparison.OrdinalIgnoreCase) ||
                        m.Name.Contains("Revocation", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        revocationMembers.Should()
            .NotBeEmpty("MUST-21 requires revocation storage behavior until capability expiration.");
    }

    [Fact(DisplayName = "MUST-22 Attenuation suffix MUST start with /, ?, or & as applicable")]
    public async Task Must22_Verifier_MustEnforceAttenuationSuffixDelimiterRules()
    {
        var fixture = new ComplianceTestFixture();
        var controllerDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resources",
            new[] { "read" });

        var invalidInvocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resourcesx"
        };
        invalidInvocation.Proof = await fixture.SigningService.SignInvocationAsync(invalidInvocation, controllerDid);

        var invalidResult = await fixture.VerificationService.VerifyInvocationAsync(invalidInvocation, root);
        invalidResult.Should().BeFalse();
    }

    [Fact(DisplayName = "SHOULD-03 Verifier SHOULD limit capability chain length to 10")]
    public void Should03_Verifier_ShouldUseChainLimitOfTen()
    {
        var field = typeof(ZcapLd.Core.Services.VerificationService)
            .GetField("MaxChainLength", BindingFlags.NonPublic | BindingFlags.Static);

        field.Should().NotBeNull("SHOULD-03 recommends a chain length limit of 10.");
        field!.GetRawConstantValue().Should().Be(10);
    }

    [Fact(DisplayName = "SHOULD-04 Delegation does not hard-throw on long expirations at create time")]
    public async Task Should04_Delegation_DoesNotThrowOnLongExpirationAtCreateTime()
    {
        // Issue #61: the W3C 3-month expiration ceiling is a verifier-side SHOULD measured at
        // invocation time, not a create-time MUST. Constructing a long-lived delegation the parent
        // permits must succeed; the ceiling is enforced on the verify path behind a policy flag
        // (Issue #73).
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid,
            "https://example.com/resources",
            new[] { "read" });

        // Constructing a long-lived delegation the parent permits must succeed (no throw).
        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root,
            childDid,
            new[] { "read" },
            DateTime.UtcNow.AddMonths(6));

        // Assert the requested 6-month expiration round-trips intact, not merely that no
        // exception was thrown — this catches a silent truncation in DelegateCapabilityAsync
        // that a NotBeNull() check would miss (PR #81 review).
        delegated.ExpiresAt.Should().NotBeNull();
        delegated.ExpiresAt!.Value.Should().BeCloseTo(
            DateTime.UtcNow.AddMonths(6), TimeSpan.FromSeconds(5));
    }

    [Fact(DisplayName = "SHOULD-04 Verifier SHOULD reject delegated expirations beyond 3 months when policy enabled")]
    public async Task Should04_Verifier_RejectsExpirationBeyondThreeMonths_WhenPolicyEnabled()
    {
        // Issue #73: the W3C 3-month expiration ceiling is a verifier-side SHOULD measured at
        // verification time, behind an opt-in policy flag. Off by default (no behavior change); when
        // enabled, the verifier rejects a delegated zcap whose expiration is more than three months out.
        var fixture = new ComplianceTestFixture();
        var parentDid = fixture.RegisterControllerDid();
        var childDid = fixture.RegisterControllerDid();

        var root = await fixture.CapabilityService.CreateRootCapabilityAsync(
            parentDid, "https://example.com/resources", new[] { "read" });
        var delegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddMonths(6));

        // Default verifier (policy off): the long-lived delegation still verifies.
        (await fixture.VerificationService.VerifyCapabilityChainDetailedAsync(delegated, root))
            .IsValid.Should().BeTrue("the ceiling is a SHOULD and is off by default");

        // Policy-enabled verifier: the same delegation is rejected, with the specific structured
        // outcome (Issue #70 channel) rather than a generic failure.
        var strictVerifier = BuildVerifier(fixture,
            new VerificationPolicy { EnforceMaxDelegationExpiration = true });

        var strictResult = await strictVerifier.VerifyCapabilityChainDetailedAsync(delegated, root);
        strictResult.IsValid.Should().BeFalse(
            "with the policy enabled, an expiration more than 3 months out is rejected");
        strictResult.Outcome.Should().Be(VerificationOutcome.ExpirationTooFarInFuture);

        // A delegation inside the ceiling (1 month) still verifies under the strict policy — the check
        // rejects only the over-long expiration, not every delegated zcap.
        var shortDelegated = await fixture.CapabilityService.DelegateCapabilityAsync(
            root, childDid, new[] { "read" }, DateTime.UtcNow.AddMonths(1));
        (await strictVerifier.VerifyCapabilityChainDetailedAsync(shortDelegated, root))
            .IsValid.Should().BeTrue("an expiration within the 3-month ceiling is permitted");
    }

    private static VerificationService BuildVerifier(ComplianceTestFixture fixture, VerificationPolicy policy)
        => new(
            fixture.DidProvider,
            fixture.CaveatProcessor,
            VerificationService.CreateDefaultSuiteProvider(),
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(),
            SigningService.CreateDefaultCanonicalizerProvider(),
            policy: policy);
}
