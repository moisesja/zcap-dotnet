using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// In-stack round-trip tests for the @digitalbazaar/zcap-compatible "Path A" Data Integrity
/// invocation: <see cref="SigningService.SignCapabilityInvocationAsync(InvocationCapability, string, string, string, JsonObject?)"/>
/// produces a secured application document (proof carries the invocation metadata), and
/// <see cref="VerificationService.VerifyCapabilityInvocationAsync(JsonObject)"/> verifies it. The live
/// cross-stack proof against the real @digitalbazaar/zcap is in <c>interop/run-interop.sh</c>.
/// </summary>
public class DataIntegrityInvocationTests
{
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

        (await _verifier.VerifyCapabilityInvocationAsync(secured)).Should().BeTrue();
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

        (await _verifier.VerifyCapabilityInvocationAsync(secured)).Should().BeTrue();
    }

    [Fact]
    public async Task DataIntegrityInvocation_TamperedSignedAction_Rejected()
    {
        const string owner = "did:key:z6MkDiTamper";
        const string target = "https://api.example.com/t";
        _did.GenerateAndRegisterKeyPair(owner);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, target));

        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromId(root.Id), "read", target, owner);

        // Flip the signed capabilityAction in the proof after signing → signature must not verify.
        secured["proof"]!.AsObject()["capabilityAction"] = "write";

        (await _verifier.VerifyCapabilityInvocationAsync(secured)).Should().BeFalse(
            "altering a signed proof field invalidates the invocation signature");
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

        // Validly signed, but invoking "write" which the delegated cap (allowedAction ["read"]) forbids.
        var secured = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "write", target, delegateDid);

        var result = await _verifier.VerifyCapabilityInvocationDetailedAsync(secured);
        result.Outcome.Should().Be(VerificationOutcome.ActionNotAllowed);
    }
}
