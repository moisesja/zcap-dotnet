using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// In-stack round-trip + adversarial-regression tests for the @digitalbazaar/zcap-compatible "Path A"
/// Data Integrity invocation. The live cross-stack proof against the real @digitalbazaar/zcap is in
/// <c>interop/run-interop.sh</c>; these lock the security gates an adversarial review identified:
/// the application-document <c>@context</c> binding (forgery defense) and the relying-party
/// expected action/target gate (confused-deputy defense).
/// </summary>
public class DataIntegrityInvocationTests
{
    private const string SuiteContext = "https://w3id.org/security/suites/ed25519-2020/v1";

    private readonly InMemoryDidProvider _did;
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly VerificationService _verifier;

    public DataIntegrityInvocationTests()
    {
        _did = new InMemoryDidProvider();
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
        _verifier = new VerificationService(
            _did, new CaveatProcessor(),
            new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore());
    }

    [Fact]
    public async Task RootInvocation_DataIntegrity_SignAndVerify_Succeeds()
    {
        const string owner = "did:key:z6MkDiRootOwner";
        const string target = "https://api.example.com/docs";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);

        (await _verifier.VerifyCapabilityInvocationAsync(secured, "read", new[] { target })).Should().BeTrue();
    }

    [Fact]
    public async Task DelegatedInvocation_DataIntegrity_SignAndVerify_Succeeds()
    {
        const string owner = "did:key:z6MkDiDelOwner";
        const string delegateDid = "did:key:z6MkDiDelDelegate";
        const string target = "https://api.example.com/res";
        _did.GenerateAndRegisterKeyPair(owner);
        _did.GenerateAndRegisterKeyPair(delegateDid);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target, new[] { "read", "write" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, delegateDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "read", target, delegateDid);

        (await _verifier.VerifyCapabilityInvocationAsync(secured, "read", new[] { target })).Should().BeTrue();
    }

    [Fact]
    public async Task DataIntegrityInvocation_TamperedSignedAction_FailsSignature()
    {
        const string owner = "did:key:z6MkDiTamper";
        const string target = "https://api.example.com/t";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);
        secured["proof"]!.AsObject()["capabilityAction"] = "write";

        // Verify with the (tampered) action as expected so the expectation gate passes and the
        // SIGNATURE check is what rejects it — the auth terms are bound because @context carries zcap/v1.
        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured, "write", target);
        result.Outcome.Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact]
    public async Task DataIntegrityInvocation_ActionNotInAllowedAction_Rejected()
    {
        const string owner = "did:key:z6MkDiActOwner";
        const string delegateDid = "did:key:z6MkDiActDelegate";
        const string target = "https://api.example.com/a";
        _did.GenerateAndRegisterKeyPair(owner);
        _did.GenerateAndRegisterKeyPair(delegateDid);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target, new[] { "read", "write" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, delegateDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        // Validly signed "write" (and the relying party expects "write"), but the delegated cap only allows "read".
        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "write", target, delegateDid);

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured, "write", target);
        result.Outcome.Should().Be(VerificationOutcome.ActionNotAllowed);
    }

    // ─── Adversarial regressions (would-be exploits the review found) ───

    [Fact]
    public async Task DataIntegrityInvocation_StrippedZcapContext_RejectedAsMalformed()
    {
        // FORGERY DEFENSE: if the attacker strips zcap/v1 from the application document's @context, RDFC
        // drops capabilityAction/invocationTarget/capability from the signed N-Quads (they are zcap/v1
        // terms), leaving them unauthenticated and rewritable. The verifier MUST reject such a document
        // before trusting the signature. Here the attacker signs over a stripped-context document and then
        // rewrites the (now-unbound) action — without the @context gate this returned Valid.
        const string owner = "did:key:z6MkDiStrip";
        const string target = "https://api.example.com/strip";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var attackerDoc = new JsonObject
        {
            ["@context"] = new JsonArray(SuiteContext), // zcap/v1 deliberately STRIPPED
            ["id"] = "urn:uuid:attacker-doc",
            ["type"] = "https://w3id.org/zcap#CapabilityInvocationRequest",
        };
        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner, attackerDoc);
        secured["proof"]!.AsObject()["capabilityAction"] = "delete-everything"; // unbound rewrite

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured, "delete-everything", target);
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability,
            "an application document whose @context does not bind the invocation terms must be rejected");
    }

    [Fact]
    public async Task DataIntegrityInvocation_ExpectedTargetMismatch_Rejected()
    {
        // CONFUSED-DEPUTY DEFENSE: a valid invocation for one target presented to an endpoint expecting a
        // DIFFERENT target must be rejected — the relying party declares the target it authorizes.
        const string owner = "did:key:z6MkDiTgt";
        const string target = "https://api.example.com/owned";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(
            secured, "read", "https://api.example.com/admin");
        result.Outcome.Should().Be(VerificationOutcome.InvalidTarget);
    }

    [Fact]
    public async Task DataIntegrityInvocation_ExpectedActionMismatch_Rejected()
    {
        // CONFUSED-DEPUTY DEFENSE: a valid "read" invocation presented where the endpoint authorizes only
        // "delete" must be rejected (and vice-versa) — the action is gated by the relying party's expectation.
        const string owner = "did:key:z6MkDiAct2";
        const string target = "https://api.example.com/act2";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured, "delete", target);
        result.Outcome.Should().Be(VerificationOutcome.ActionNotAllowed);
    }

    [Fact]
    public async Task DataIntegrityInvocation_ExpectedRootMismatch_Rejected()
    {
        // DEFENSE IN DEPTH: when the relying party pins the acceptable root capabilities, a valid
        // invocation whose chain root is not among them is rejected.
        const string owner = "did:key:z6MkDiRootPin";
        const string target = "https://api.example.com/pin";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(
            secured, "read", new[] { target }, expectedRootCapabilityIds: new[] { "urn:zcap:root:some-other-root" });
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
    }
}
