using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
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

    // Creates a root capability and registers it with the in-memory resolver so the verifier (which
    // auto-detects _didProvider as an IRootCapabilityResolver) can resolve the root that spec-exact
    // chains reference by id only — first-level chains are [rootId] with the root never embedded (Issue #50).
    private Task<Capability> CreateAndRegisterRootAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null)
        => TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, controller, invocationTarget, allowedActions, expires, caveats);

    #region Capability Proof Verification Tests

    [Fact]
    public async Task VerifyCapabilityProof_RootCapability_ShouldReturnTrue()
    {
        // Arrange
        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var root = await CreateAndRegisterRootAsync(
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
    public async Task VerifyCapabilityProof_WhenResolvedKeyTypeMismatchesSuite_ReturnsFalse()
    {
        // Issue #68 (delegation path): the key-type/suite binding guard lives in BOTH verify paths.
        // The invocation test above covers VerifyInvocationSignatureAsync; this one covers the copy
        // in VerifySingleDelegationProofAsync by verifying a delegated capability's delegation proof.
        var delegatorDid = "did:key:z6MkKeyTypeBindingDelegator";
        _didProvider.GenerateAndRegisterKeyPair(delegatorDid);

        var root = await CreateAndRegisterRootAsync(
            delegatorDid, "https://example.com/resource", new[] { "read" });

        // The delegation proof is signed by the delegator (root controller); the grantee need not
        // have a registered key. Verifying it resolves the delegator's key — which the mismatch
        // resolver returns with correct bytes but a wrong key type, so the guard must reject it.
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, "did:key:z6MkKeyTypeBindingGrantee", new[] { "read" }, DateTime.UtcNow.AddDays(30));

        var mismatchVerifier = new VerificationService(
            new WrongKeyTypeResolver(_didProvider, "EcdsaSecp256r1VerificationKey2019"),
            _caveatProcessor);

        (await mismatchVerifier.VerifyCapabilityProofAsync(delegated)).Should().BeFalse();

        // Sanity: the same delegated capability verifies under the honest resolver, so the only
        // failing factor above is the key-type/suite mismatch.
        var honestVerifier = new VerificationService(_didProvider, _caveatProcessor);
        (await honestVerifier.VerifyCapabilityProofAsync(delegated)).Should().BeTrue();
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
        // PR #84 review (Finding 1): an unbuildable capability is attacker-drivable validation
        // input, so it logs at Debug (not Warning) to avoid log amplification — but the cause must
        // still be recorded, with the exception, attributed to this method.
        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Debug && e.Exception != null && e.Message.Contains("VerifyCapabilityChainAsync"),
            "the swallowed cause must be logged (at Debug for expected input), not discarded");
    }

    [Fact]
    public async Task RevokeCapability_WhenAuthorizationChainWalkFaults_FailsClosedAndLogs()
    {
        // PR #84 review (🔴): the revocation authorization step (IsRevokerAuthorizedAsync) must fail
        // closed on ANY fault from the chain walk — not only CapabilityValidationException — returning
        // false rather than letting the fault escape the authorization decision. The cause is logged
        // (Issue #64) so operators can tell a chain-walk failure apart from a genuine "not authorized".
        // The assertion pins the INNER catch's specific message so the test would fail if that catch
        // were narrowed or removed (the outer RevokeCapabilityAsync catch logs a different message).
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

        var revokerDid = "did:key:z6MkRevokeFaultRevoker";
        _didProvider.GenerateAndRegisterKeyPair(revokerDid);

        // Looks delegated (has parentCapability) but carries no proof/chain, so authorization's
        // BuildCapabilityChainAsync throws — and it throws AFTER the revocation request's own
        // signature has already verified, exercising the authorization-step catch specifically.
        var malformed = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:uuid:revoke-fault",
            Controller = revokerDid,
            InvocationTarget = "https://example.com/resource",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource"
        };

        // A genuinely valid proof-of-possession revocation request bound to the malformed capability,
        // so the structural and signature checks pass and control reaches the chain walk.
        var signedRevocation = await _signingService.SignRevocationAsync(
            malformed.Id, revokerDid, malformed.InvocationTarget);

        // Must NOT throw; must return false (fail-closed) and log the swallowed cause at Debug
        // (CapabilityValidationException is expected, attacker-drivable input — Finding 1).
        var result = await verifier.RevokeCapabilityAsync(malformed, signedRevocation);

        result.Should().BeFalse("an unbuildable authorization chain means 'not authorized'");
        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Debug && e.Exception != null && e.Message.Contains("IsRevokerAuthorizedAsync"),
            "the inner authorization catch must log the cause, attributed to IsRevokerAuthorizedAsync");
    }

    [Fact]
    public async Task VerifyCapabilityChain_WhenUnexpectedFaultOccurs_LogsAtWarning()
    {
        // PR #84 review (Finding 1): the severity seam must work in BOTH directions. A genuinely
        // unexpected, non-library fault — here a revocation-store InvalidOperationException standing
        // in for a transient infra/config error — is exactly what #64 wants an operator to SEE, so it
        // logs at Warning, not the Debug reserved for expected, attacker-drivable validation input.
        var logger = new CapturingLogger<VerificationService>();
        var verifier = new VerificationService(
            _didProvider,
            _caveatProcessor,
            VerificationService.CreateDefaultSuiteProvider(),
            new ThrowingRevocationService(),
            new InMemoryNonceStore(),
            SigningService.CreateDefaultCanonicalizerProvider(),
            nonceWindow: null,
            logger: logger);

        var rootDid = "did:key:z6MkWarnBranchRoot";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read" });

        // The chain builds fine; the per-link revocation check then hits the throwing store, so the
        // fault is a non-library InvalidOperationException reaching a fail-closed catch.
        var result = await verifier.VerifyCapabilityChainAsync(root);

        result.Should().BeFalse("an infrastructure fault fails closed");
        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Warning && e.Exception is InvalidOperationException,
            "a genuinely unexpected fault must surface at Warning so the operator sees it");
    }

    [Fact]
    public async Task VerifyInvocation_WithEmptyProofValue_LogsAtDebugNotWarning()
    {
        // PR #84 review (residual nit): an empty/null proofValue makes MultibaseCodec.Decode throw
        // ArgumentException from a guard BEFORE its own try, so DecodeProofValue must retype that too
        // (not only the wrapped CryptographicException) — otherwise this attacker-drivable input lands
        // at Warning, the exact vector Finding 1 closed. Assert it fails closed and logs at Debug
        // carrying a CapabilityValidationException whose inner cause is the ArgumentException.
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

        var controllerDid = "did:key:z6MkEmptyProofValue";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);
        var rootCapability = await CreateAndRegisterRootAsync(
            controllerDid, "https://example.com/resource", new[] { "read" });

        var invocation = new Invocation
        {
            Capability = rootCapability.Id,
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, controllerDid);
        // Structurally intact, but the signature encoding is empty — invalid input, not a config fault.
        invocation.Proof.ProofValue = "";

        var result = await verifier.VerifyInvocationAsync(invocation, rootCapability);

        result.Should().BeFalse("an empty proofValue fails closed");
        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Debug && e.Exception is CapabilityValidationException
                && e.Exception.InnerException is ArgumentException,
            "an empty proofValue is malformed input — Debug, retyped from the decode ArgumentException");
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning,
            "a malformed proofValue must not reach the Warning channel");
    }

    [Fact]
    public async Task VerifyCapabilityProof_OverbroadChild_ShouldReturnFalse()
    {
        // Issue #69: a re-signed child that EXPANDS authority beyond its parent must be rejected by
        // the single-proof check too (it was previously accepted, while VerifyCapabilityChainAsync
        // correctly rejected it). Build root → mid(["read"]) → a leaf claiming ["read","write"],
        // validly signed by mid's controller — the only invalid factor is attenuation.
        var rootDid = "did:key:z6MkAttenRoot";
        var midDid = "did:key:z6MkAttenMid";
        var leafDid = "did:key:z6MkAttenLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(midDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await _capabilityService.CreateRootCapabilityAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));

        // Hand-craft a child that expands ["read"] → ["read","write"]; everything else attenuates.
        var overbroad = new Capability
        {
            Context = mid.Context,
            Id = $"urn:uuid:{Guid.NewGuid()}",
            Controller = leafDid,
            InvocationTarget = mid.InvocationTarget,
            AllowedAction = new[] { "read", "write" },
            Expires = mid.Expires,
            ParentCapability = mid.Id
        };
        overbroad.Proof = await _signingService.SignCapabilityAsync(
            overbroad, midDid, "capabilityDelegation", new object[] { root.Id, mid });

        // The single-link proof check must reject the over-broad child (attenuation), matching the chain check.
        (await _verificationService.VerifyCapabilityProofAsync(overbroad)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(overbroad)).Should().BeFalse();
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

        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            mid, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(10));

        // Sanity: before revocation the leaf's proof verifies.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeTrue();

        // Revoke the immediate parent (mid). rootDid controls the root (mid's ancestor), so a
        // revocation it signs is authorized via the signed Capability/Invocation overload.
        var midRevocation = await _signingService.SignRevocationAsync(mid.Id, rootDid, mid.InvocationTarget);
        (await _verificationService.RevokeCapabilityAsync(mid, midRevocation)).Should().BeTrue();

        // The single-proof check must now also reject the leaf, matching VerifyCapabilityChainAsync.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(leaf)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_WithRevokedRootAncestor_ShouldReturnFalse()
    {
        // Issue #63 (depth-1 gap): the original fix only revocation-checked the leaf's IMMEDIATE
        // parent embedded in proof.capabilityChain. A revoked grandparent/root still passed the
        // single-proof check while VerifyCapabilityChainAsync rejected it — the exact divergence the
        // PR set out to remove. Revoking the ROOT (the grandparent) must now fail BOTH paths.
        var rootDid = "did:key:z6MkRevRootRoot";
        var midDid = "did:key:z6MkRevRootMid";
        var leafDid = "did:key:z6MkRevRootLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(midDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var mid = await _capabilityService.DelegateCapabilityAsync(
            root, midDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            mid, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(10));

        // Sanity: before revocation the leaf's proof verifies on both paths.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeTrue();
        (await _verificationService.VerifyCapabilityChainAsync(leaf)).Should().BeTrue();

        // Revoke the ROOT (leaf's grandparent). rootDid controls the root, so it may self-revoke it.
        var rootRevocation = await _signingService.SignRevocationAsync(root.Id, rootDid, root.InvocationTarget);
        (await _verificationService.RevokeCapabilityAsync(root, rootRevocation)).Should().BeTrue();

        // Both paths must now reject the leaf — ancestor revocation honoured at every depth.
        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(leaf)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_WithRevokedIntermediateAncestor_ShouldReturnFalse()
    {
        // A 4-deep chain root -> a -> b -> leaf. Revoke 'a', an intermediate ancestor that is
        // neither the root nor the leaf's immediate parent (b). The intermediate's id is carried as
        // a string in leaf's capabilityChain, so the standalone sweep must catch it (Issue #63).
        var rootDid = "did:key:z6MkRevMidRoot";
        var aDid = "did:key:z6MkRevMidA";
        var bDid = "did:key:z6MkRevMidB";
        var leafDid = "did:key:z6MkRevMidLeaf";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(aDid);
        _didProvider.GenerateAndRegisterKeyPair(bDid);
        _didProvider.GenerateAndRegisterKeyPair(leafDid);

        var root = await CreateAndRegisterRootAsync(
            rootDid, "https://example.com/resource", new[] { "read", "write" });
        var a = await _capabilityService.DelegateCapabilityAsync(
            root, aDid, new[] { "read" }, DateTime.UtcNow.AddDays(30));
        var b = await _capabilityService.DelegateCapabilityAsync(
            a, bDid, new[] { "read" }, DateTime.UtcNow.AddDays(20));
        var leaf = await _capabilityService.DelegateCapabilityAsync(
            b, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(10));

        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeTrue();

        // 'a' self-revokes (aDid controls a).
        var aRevocation = await _signingService.SignRevocationAsync(a.Id, aDid, a.InvocationTarget);
        (await _verificationService.RevokeCapabilityAsync(a, aRevocation)).Should().BeTrue();

        (await _verificationService.VerifyCapabilityProofAsync(leaf)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(leaf)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCapabilityProof_AfterJsonRoundTrip_ShouldReturnTrue()
    {
        // Arrange — simulates HTTP POST: serialize capability → deserialize on server
        var parentDid = "did:key:z6MkParent";
        _didProvider.GenerateAndRegisterKeyPair(parentDid);

        var rootCapability = await CreateAndRegisterRootAsync(
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
        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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
    public async Task VerifyCapabilityChain_FirstLevelDelegationNotSignedByRootController_ShouldReturnFalse()
    {
        // Arrange. A first-level delegation's spec-exact chain is [rootId] (root by id only, no embedded
        // object) — so the verifier resolves the root and authorizes the delegation against the ROOT's
        // controller. Here the child self-signs its own delegation from a root it does not control, so
        // authorization MUST fail even though the chain shape is now valid (Issue #50).
        var rootDid = "did:key:z6MkRoot";
        var childDid = "did:key:z6MkChild";
        _didProvider.GenerateAndRegisterKeyPair(rootDid);
        _didProvider.GenerateAndRegisterKeyPair(childDid);

        var rootCapability = await CreateAndRegisterRootAsync(
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

        // Spec-exact first-level chain, but self-signed by the child rather than the root's controller.
        delegatedCapability.Proof = await _signingService.SignCapabilityAsync(
            delegatedCapability,
            childDid,
            "capabilityDelegation",
            new object[] { rootCapability.Id });

        // Act
        var result = await _verificationService.VerifyCapabilityChainAsync(delegatedCapability);

        // Assert — rejected: the first delegation is not authorized by the root's controller.
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
        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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
            Capability = InvocationCapability.FromCapability(delegatedCapability),
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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
            Capability = InvocationCapability.FromCapability(delegatedCapability),
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

        var rootCapability = await CreateAndRegisterRootAsync(
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
            Capability = InvocationCapability.FromCapability(delegatedCapability),
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

        var rootCapability = await CreateAndRegisterRootAsync(
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
            Capability = InvocationCapability.FromCapability(delegatedCapability),
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
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

        var rootCapability = await CreateAndRegisterRootAsync(
            rootControllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            delegatedControllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5));

        var signedRevocation = await _signingService.SignRevocationAsync(
            delegatedCapability.Id, rootControllerDid, delegatedCapability.InvocationTarget);
        await _verificationService.RevokeCapabilityAsync(delegatedCapability, signedRevocation);

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

        var rootCapability = await CreateAndRegisterRootAsync(
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
            Capability = InvocationCapability.FromCapability(delegatedCapability),
            CapabilityAction = "read",
            InvocationTarget = delegatedCapability.InvocationTarget
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, delegatedControllerDid);

        var signedRevocation = await _signingService.SignRevocationAsync(
            delegatedCapability.Id, rootControllerDid, delegatedCapability.InvocationTarget);
        await _verificationService.RevokeCapabilityAsync(delegatedCapability, signedRevocation);

        // Act
        var result = await _verificationService.VerifyInvocationAsync(invocation, delegatedCapability);

        // Assert
        result.Should().BeFalse();
    }

    // ── Signed revocation (proof-of-possession) ──────────────────────────────────────────
    // Revocation requires a cryptographically signed request. The signature authenticates the
    // revoker (proof of key possession); the chain-walk authorizes it. There is no bare-DID path.

    /// <summary>Builds root → delegated chain, registering keys for both controllers.</summary>
    private async Task<(Capability Root, Capability Delegated)> BuildDelegatedChainAsync(
        string rootControllerDid, string delegatedControllerDid)
    {
        _didProvider.GenerateAndRegisterKeyPair(rootControllerDid);
        _didProvider.GenerateAndRegisterKeyPair(delegatedControllerDid);

        var root = await CreateAndRegisterRootAsync(
            rootControllerDid, "https://example.com/resource", new[] { "read", "write" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, delegatedControllerDid, new[] { "read" }, DateTime.UtcNow.AddDays(5));
        return (root, delegated);
    }

    /// <summary>A VerificationService whose revocation store/service is held for assertions.</summary>
    private (VerificationService Verifier, RevocationService Revocation, InMemoryRevocationStore Store)
        CreateVerifierWithRevocationStore()
    {
        var store = new InMemoryRevocationStore();
        var revocation = new RevocationService(store);
        var suiteProvider = new CryptoSuiteProvider();
        suiteProvider.Register(CryptoSuite.Ed25519());
        var canon = new DocumentCanonicalizerProvider();
        canon.Register(new JcsDocumentCanonicalizer());
        var verifier = new VerificationService(
            _didProvider, _caveatProcessor, suiteProvider, revocation, new InMemoryNonceStore(), canon);
        return (verifier, revocation, store);
    }

    [Fact]
    public async Task SignedRevoke_AuthorizedUpChainController_RevokesAndReturnsTrue()
    {
        // The root controller is an up-chain delegator and may revoke a child — when it proves
        // possession of its key by signing the revocation request.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkRevokeRoot", "did:key:z6MkRevokeChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkRevokeRoot", delegated.InvocationTarget);
        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, signed);

        revoked.Should().BeTrue();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_OwnControllerSelfRevoke_RevokesAndReturnsTrue()
    {
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkSelfRoot", "did:key:z6MkSelfChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkSelfChild", delegated.InvocationTarget);
        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, signed);

        revoked.Should().BeTrue();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task SignedRevoke_UnauthorizedButValidlySigned_ReturnsFalse()
    {
        // Mallory holds a real, resolvable key and signs a perfectly valid revocation request —
        // but she controls nothing in the chain. Authentication succeeds; authorization fails.
        // Nothing is recorded (no denial-of-capability).
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkAuthzRoot", "did:key:z6MkAuthzChild");
        const string malloryDid = "did:key:z6MkMalloryHasNoAuthority";
        _didProvider.GenerateAndRegisterKeyPair(malloryDid);

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, malloryDid, delegated.InvocationTarget);
        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, signed);

        revoked.Should().BeFalse();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeFalse();
        (await _verificationService.VerifyCapabilityChainAsync(delegated)).Should().BeTrue();
    }

    [Fact]
    public async Task SignedRevoke_ImpersonationVmClaimsControllerButSignedByAnotherKey_ReturnsFalse()
    {
        // THE proof-of-possession regression: Mallory crafts a request CLAIMING the root
        // controller's verification method, but the bytes are signed with Mallory's key. The
        // verifier resolves the controller's public key and the signature fails — knowing the
        // (public) controller DID is not enough to revoke.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkImpRoot", "did:key:z6MkImpChild");
        const string malloryDid = "did:key:z6MkMalloryImpersonator";
        _didProvider.GenerateAndRegisterKeyPair(malloryDid);

        var forged = await _signingService.SignRevocationAsync(
            delegated.Id, malloryDid, delegated.InvocationTarget);
        // Claim the root controller's identity without holding its key.
        forged.Proof!.VerificationMethod = await _didProvider.GetVerificationMethodAsync("did:key:z6MkImpRoot");

        var revoked = await _verificationService.RevokeCapabilityAsync(delegated, forged);

        revoked.Should().BeFalse();
        (await _verificationService.IsCapabilityRevokedAsync(delegated.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_ReplayedRequest_SecondAttemptReturnsFalse()
    {
        // Replay protection (nonce = request id). To isolate it from the revocation-state guard,
        // evict the recorded revocation after the first success so the chain verifies again; the
        // replayed request must still be rejected because its id was already consumed.
        var (verifier, _, store) = CreateVerifierWithRevocationStore();
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkReplayRoot", "did:key:z6MkReplayChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkReplayRoot", delegated.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(delegated, signed)).Should().BeTrue();
        await store.DeleteAsync(delegated.Id);
        (await verifier.RevokeCapabilityAsync(delegated, signed)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_WrongCapabilityBinding_ReturnsFalse()
    {
        // A revocation signed for capability X cannot be used to revoke capability Y.
        var (_, delegatedX) = await BuildDelegatedChainAsync("did:key:z6MkBindRootX", "did:key:z6MkBindChildX");
        var (_, delegatedY) = await BuildDelegatedChainAsync("did:key:z6MkBindRootY", "did:key:z6MkBindChildY");

        var signedForX = await _signingService.SignRevocationAsync(
            delegatedX.Id, "did:key:z6MkBindRootX", delegatedX.InvocationTarget);

        (await _verificationService.RevokeCapabilityAsync(delegatedY, signedForX)).Should().BeFalse();
        (await _verificationService.IsCapabilityRevokedAsync(delegatedY.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_WrongProofPurpose_ReturnsFalse()
    {
        // Confused-deputy regression: a normal capabilityInvocation proof must not be accepted as
        // a revocation, even if its capabilityAction happens to be "revoke".
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkPurposeRoot", "did:key:z6MkPurposeChild");

        var invocation = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = Invocation.RevokeAction,
            InvocationTarget = delegated.InvocationTarget
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, "did:key:z6MkPurposeRoot");
        invocation.Proof.ProofPurpose.Should().Be(Proof.CapabilityInvocationPurpose);

        (await _verificationService.RevokeCapabilityAsync(delegated, invocation)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_WrongCapabilityAction_ReturnsFalse()
    {
        // A capabilityRevocation-purpose proof whose action is not "revoke" is rejected.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkActionRoot", "did:key:z6MkActionChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkActionRoot", delegated.InvocationTarget);
        signed.CapabilityAction = "read"; // body no longer says "revoke"

        (await _verificationService.RevokeCapabilityAsync(delegated, signed)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_ProofBodyMismatch_ReturnsFalse()
    {
        // Tampering the body's invocationTarget after signing breaks proof/body consistency.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkMismatchRoot", "did:key:z6MkMismatchChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkMismatchRoot", delegated.InvocationTarget);
        signed.InvocationTarget = "https://evil.example.com/other";

        (await _verificationService.RevokeCapabilityAsync(delegated, signed)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_SignedReason_IsRecordedOnRevocationRecord()
    {
        var (verifier, revocation, _) = CreateVerifierWithRevocationStore();
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkReasonRoot", "did:key:z6MkReasonChild");

        var metadata = new Dictionary<string, string> { ["ticket"] = "SEC-123" };
        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkReasonRoot", delegated.InvocationTarget,
            reason: "key compromised", metadata: metadata);

        (await verifier.RevokeCapabilityAsync(delegated, signed)).Should().BeTrue();

        var record = await revocation.GetRevocationAsync(delegated.Id);
        record.Should().NotBeNull();
        record!.Reason.Should().Be("key compromised");
        record.RevokedBy.Should().Be("did:key:z6MkReasonRoot");
        record.Metadata.Should().ContainKey("ticket").WhoseValue.Should().Be("SEC-123");
    }

    [Fact]
    public async Task SignedRevoke_TamperedReason_FailsSignature_ReturnsFalse()
    {
        // The reason is part of the signed bytes — flipping it after signing invalidates the proof.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkTamperRoot", "did:key:z6MkTamperChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkTamperRoot", delegated.InvocationTarget, reason: "legitimate");
        signed.Proof!.AdditionalProperties![Proof.RevocationReasonField] =
            JsonSerializer.SerializeToElement("forged-reason");

        (await _verificationService.RevokeCapabilityAsync(delegated, signed)).Should().BeFalse();
    }

    [Fact]
    public async Task SignedRevoke_NullCapability_ThrowsArgumentNullException()
    {
        var act = () => _verificationService.RevokeCapabilityAsync(null!, new Invocation());
        await act.Should().ThrowAsync<ArgumentNullException>().WithParameterName("capability");
    }

    [Fact]
    public async Task SignedRevoke_NullInvocation_ThrowsArgumentNullException()
    {
        var capability = new Capability { Id = "urn:uuid:some-id" };
        var act = () => _verificationService.RevokeCapabilityAsync(capability, null!);
        await act.Should().ThrowAsync<ArgumentNullException>().WithParameterName("signedRevocation");
    }

    [Fact]
    public async Task VerifyInvocation_WithCapabilityRevocationPurpose_ReturnsFalse()
    {
        // Cross-direction exclusivity: a signed revocation must not pass as a normal invocation.
        var (_, delegated) = await BuildDelegatedChainAsync("did:key:z6MkXdirRoot", "did:key:z6MkXdirChild");

        var signed = await _signingService.SignRevocationAsync(
            delegated.Id, "did:key:z6MkXdirChild", delegated.InvocationTarget);

        (await _verificationService.VerifyInvocationAsync(signed, delegated)).Should().BeFalse();
    }

    [Fact]
    public async Task SignRevocation_ProducesCapabilityRevocationPurposeAndRevokeAction()
    {
        var did = "did:key:z6MkSignShape";
        _didProvider.GenerateAndRegisterKeyPair(did);

        var signed = await _signingService.SignRevocationAsync(
            "urn:uuid:target-cap", did, "https://example.com/resource");

        signed.CapabilityAction.Should().Be(Invocation.RevokeAction);
        signed.Capability.CapabilityId.Should().Be("urn:uuid:target-cap");
        signed.Proof.Should().NotBeNull();
        signed.Proof!.ProofPurpose.Should().Be(Proof.CapabilityRevocationPurpose);
        signed.Proof.ProofValue.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SignInvocation_BehaviorUnchanged_StillCapabilityInvocation()
    {
        // Regression guard for the SignInvocationAsync → SignInvocationProofAsync refactor.
        var did = "did:key:z6MkInvShape";
        _didProvider.GenerateAndRegisterKeyPair(did);

        var invocation = new Invocation
        {
            Capability = "urn:uuid:some-cap",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/resource"
        };
        var proof = await _signingService.SignInvocationAsync(invocation, did);

        proof.ProofPurpose.Should().Be(Proof.CapabilityInvocationPurpose);
        proof.CapabilityAction.Should().Be("read");
        proof.ProofValue.Should().NotBeNullOrEmpty();
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
        var capability = await CreateAndRegisterRootAsync(
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

    #region Invocation Target Prefix Matching (Issue #74 — ordinal StartsWith)

    // IsValidInvocationTarget must test the prefix ordinally, consistent with the ordinal Substring
    // index math that follows it. A culture-sensitive StartsWith treats ignorable Unicode code points
    // (e.g. U+00AD SOFT HYPHEN) as zero-width, which disagrees with the ordinal length used by
    // Substring — and, when the capability target is ordinally longer than the invocation target,
    // drives Substring past the end of the string (ArgumentOutOfRangeException). These exercise the
    // method directly: the call sites are fail-closed (catch → false), so a black-box test cannot
    // distinguish the ordinal fix from the buggy culture-sensitive comparison.

    [Theory]
    [InlineData("https://example.com/resource", "https://example.com/resource")]             // exact match
    [InlineData("https://example.com/resource/sub", "https://example.com/resource")]         // path suffix
    [InlineData("https://example.com/resource?q=1", "https://example.com/resource")]         // query suffix
    [InlineData("https://example.com/resource?a=1&b=2", "https://example.com/resource?a=1")] // extra query param after '?'
    public void IsValidInvocationTarget_ValidPrefixes_ReturnsTrue(string invocationTarget, string capabilityTarget)
    {
        _verificationService.IsValidInvocationTarget(invocationTarget, capabilityTarget)
            .Should().BeTrue();
    }

    [Theory]
    [InlineData("https://example.com/resource", "https://other.com/resource")]               // different host
    [InlineData("https://example.com/resourceX", "https://example.com/resource")]            // suffix lacks a delimiter
    [InlineData("https://example.com/re\u00ADsource/x", "https://example.com/resource")]     // ignorable char breaks the ordinal prefix
    public void IsValidInvocationTarget_InvalidPrefixes_ReturnsFalse(string invocationTarget, string capabilityTarget)
    {
        _verificationService.IsValidInvocationTarget(invocationTarget, capabilityTarget)
            .Should().BeFalse();
    }

    [Fact]
    public void IsValidInvocationTarget_CapabilityTargetOrdinallyLongerViaIgnorableChar_ReturnsFalseWithoutThrowing()
    {
        // The capability target carries a trailing SOFT HYPHEN (U+00AD), making it ordinally LONGER
        // than the invocation target. The pre-#74 culture-sensitive StartsWith returns true (the soft
        // hyphen is ignorable), after which Substring(capabilityTarget.Length) runs past the end of the
        // shorter invocation target and throws ArgumentOutOfRangeException. Ordinal comparison returns
        // false cleanly — this is the deterministic regression guard for Issue #74.
        var invocationTarget = "https://example.com/resource";
        var capabilityTarget = "https://example.com/resource\u00AD";

        var result = true;
        var act = () => { result = _verificationService.IsValidInvocationTarget(invocationTarget, capabilityTarget); };

        act.Should().NotThrow("ordinal comparison must not index Substring past the end of the shorter target");
        result.Should().BeFalse();
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
/// Revocation service whose status check throws a non-library fault, standing in for a transient
/// infrastructure/config error. Drives the Warning branch of <c>LogFailedClosed</c> (PR #84, Finding 1).
/// </summary>
internal sealed class ThrowingRevocationService : IRevocationService
{
    public Task<RevocationRecord> RevokeAsync(RevocationRequest request, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<RevocationRecord?> GetRevocationAsync(string capabilityId, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<bool> IsRevokedAsync(string capabilityId, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("simulated revocation-store outage");
}

/// <summary>
/// Wraps an inner resolver but overrides the resolved key's type with a deliberately wrong value
/// (Issue #68 test support) — the key bytes stay correct so only the key-type/suite binding differs.
/// Also forwards <see cref="IVerificationRelationshipResolver"/> to the inner provider so controller
/// authorization (verify step 6) PASSES; otherwise the verifier would fall back to a real
/// <c>did:key</c> relationship resolver that cannot decode the test's synthetic controller, failing on
/// an unrelated gate and masking the keytype guard this helper exists to exercise.
/// </summary>
internal sealed class WrongKeyTypeResolver : IDidResolver, IVerificationRelationshipResolver
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

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
        => ((IVerificationRelationshipResolver)_inner).IsAuthorizedForRelationshipAsync(
            controllerDid, verificationMethodDidUrl, relationship, ct);
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
