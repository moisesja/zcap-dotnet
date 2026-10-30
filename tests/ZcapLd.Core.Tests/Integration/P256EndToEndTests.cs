using System.Text.Json.Nodes;
using DataProofsDotnet;
using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// End-to-end P-256 (<c>EcdsaSecp256r1Signature2019</c>) coverage under RDFC-1.0 (#159): delegation, chain
/// verification, envelope and Data Integrity invocations, revocation, a chain mixing both suites, and the
/// context binding that keeps a P-256 proof's terms signed. Before #159 every P-256 signing failed: the
/// suite's advertised context (<c>…/suites/ecdsa-2019/v1</c>) was never published and the offline loader
/// fails closed, so the suite could not be used at all.
/// </summary>
public class P256EndToEndTests
{
    private const string ZcapContext = "https://w3id.org/zcap/v1";
    private const string Ed25519Context = "https://w3id.org/security/suites/ed25519-2020/v1";
    private const string P256Context = "urn:zcap-dotnet:ecdsa-secp256r1-2019-context:v1";
    private const string Target = "https://p256.example/resource";

    private readonly InMemoryDidProvider _did = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly VerificationService _verifier;

    public P256EndToEndTests()
    {
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
        _verifier = new VerificationService(
            _did, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore());
    }

    private async Task<(string Owner, string Agent, Capability Root, Capability Delegated)> DelegateP256Async()
    {
        var owner = _did.GenerateDidKey(KeyType.P256);
        var agent = _did.GenerateDidKey(KeyType.P256);
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read", "write" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        return (owner, agent, root, delegated);
    }

    private static Capability UnsignedChild(Capability root, string controller, object context) => new()
    {
        Context = context,
        Id = $"urn:uuid:{Guid.NewGuid()}",
        ParentCapability = root.Id,
        Controller = controller,
        InvocationTarget = Target,
        AllowedAction = new[] { "read" },
        Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddHours(1)),
    };

    [Fact(DisplayName = "A P-256 signer resolves to the local P-256 suite context")]
    public async Task ResolveSuiteContextUrl_P256Signer_IsTheLocalContext()
    {
        var owner = _did.GenerateDidKey(KeyType.P256);

        (await _signing.ResolveSuiteContextUrlAsync(owner)).Should().Be(P256Context);
        ZcapSuiteCatalog.P256ContextUrl.Should().Be(P256Context);
    }

    [Fact(DisplayName = "A P-256 delegation signs and verifies under RDFC-1.0")]
    public async Task Delegation_P256ToP256_SignsAndVerifies()
    {
        var (_, _, _, delegated) = await DelegateP256Async();

        delegated.Context.Should().BeOfType<object[]>().Which.Should().Equal(ZcapContext, P256Context);
        var proof = delegated.Proof!.Primary;
        proof.Type.Should().Be("EcdsaSecp256r1Signature2019");
        proof.VerificationMethod.Should().StartWith("did:key:zDn");
        MultibaseCodec.Decode(proof.ProofValue).Should().HaveCount(64, "the P-256 proofValue is the IEEE P1363 r||s signature");

        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.VerifyCapabilityProofDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "Envelope invocations by a P-256 root controller and a P-256 delegatee verify")]
    public async Task EnvelopeInvocation_P256_Verifies()
    {
        var (owner, agent, root, delegated) = await DelegateP256Async();

        var rootInvocation = new Invocation { Capability = root.Id, CapabilityAction = "write", InvocationTarget = Target };
        rootInvocation.Proof = await _signing.SignInvocationAsync(rootInvocation, owner);
        (await _verifier.VerifyInvocationDetailedAsync(rootInvocation, root)).Outcome.Should().Be(VerificationOutcome.Valid);

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated), CapabilityAction = "read", InvocationTarget = Target,
        };
        invocation.Proof = await _signing.SignInvocationAsync(invocation, agent);
        invocation.Proof.Type.Should().Be("EcdsaSecp256r1Signature2019");
        (await _verifier.VerifyInvocationDetailedAsync(invocation, delegated)).Outcome.Should().Be(VerificationOutcome.Valid);

        // The delegatee holds read only; the suite does not change authorization.
        var denied = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated), CapabilityAction = "write", InvocationTarget = Target,
        };
        denied.Proof = await _signing.SignInvocationAsync(denied, agent);
        (await _verifier.VerifyInvocationDetailedAsync(denied, delegated)).Outcome.Should().Be(VerificationOutcome.ActionNotAllowed);
    }

    [Fact(DisplayName = "Data Integrity invocations signed with P-256 carry the P-256 context and verify")]
    public async Task DataIntegrityInvocation_P256_RootAndDelegated_Verify()
    {
        var (owner, agent, root, delegated) = await DelegateP256Async();

        var securedRoot = await _signing.SignCapabilityInvocationAsync(InvocationCapability.FromId(root.Id), "read", Target, owner);
        securedRoot["@context"]!.AsArray().Select(node => node!.GetValue<string>()).Should().Equal(ZcapContext, P256Context);
        securedRoot["proof"]!["type"]!.GetValue<string>().Should().Be("EcdsaSecp256r1Signature2019");
        (await _verifier.VerifyCapabilityInvocationAsync(securedRoot, "read", new[] { Target })).Should().BeTrue();

        var securedDelegated = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "read", Target, agent);
        (await _verifier.VerifyCapabilityInvocationAsync(securedDelegated, "read", new[] { Target })).Should().BeTrue();
        (await _verifier.VerifyCapabilityInvocationAsync(securedDelegated, "write", new[] { Target })).Should().BeFalse();
    }

    [Fact(DisplayName = "A signed revocation by a P-256 controller is authenticated and recorded")]
    public async Task Revocation_SignedByP256Controller_IsRecorded()
    {
        var (owner, _, _, delegated) = await DelegateP256Async();

        var revocation = await _signing.SignRevocationAsync(
            delegated.Id, owner, delegated.InvocationTarget, "key rotated", new Dictionary<string, string> { ["ticket"] = "42" });
        revocation.Proof!.Type.Should().Be("EcdsaSecp256r1Signature2019");

        (await _verifier.RevokeCapabilityAsync(delegated, revocation)).Should().BeTrue();
        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Revoked);
    }

    [Fact(DisplayName = "A chain mixing Ed25519 and P-256 links binds each link to its signer's suite context")]
    public async Task MixedSuiteChain_Ed25519ToP256ToEd25519_Verifies()
    {
        var owner = _did.GenerateDidKey();
        var middle = _did.GenerateDidKey(KeyType.P256);
        var leaf = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read", "write" }));

        var first = await _caps.DelegateCapabilityAsync(root, middle, new[] { "read", "write" }, DateTime.UtcNow.AddHours(2));
        var second = await _caps.DelegateCapabilityAsync(first, leaf, new[] { "read" }, DateTime.UtcNow.AddHours(1));

        first.Context.Should().BeOfType<object[]>().Which.Should().Equal(ZcapContext, Ed25519Context);
        first.Proof!.Primary.Type.Should().Be("Ed25519Signature2020");
        second.Context.Should().BeOfType<object[]>().Which.Should().Equal(ZcapContext, P256Context);
        second.Proof!.Primary.Type.Should().Be("EcdsaSecp256r1Signature2019");

        (await _verifier.VerifyCapabilityChainDetailedAsync(second)).Outcome.Should().Be(VerificationOutcome.Valid);

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(second), CapabilityAction = "read", InvocationTarget = Target,
        };
        invocation.Proof = await _signing.SignInvocationAsync(invocation, leaf);
        invocation.Proof.Type.Should().Be("Ed25519Signature2020");
        (await _verifier.VerifyInvocationDetailedAsync(invocation, second)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "Tampering with a P-256 delegation after signing is an invalid signature")]
    public async Task TamperedP256Delegation_IsInvalidSignature()
    {
        var (_, _, _, delegated) = await DelegateP256Async();

        // Still within the root's actions, so attenuation passes and only the signature can fail.
        delegated.AllowedAction = new[] { "read", "write" };

        (await _verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "A P-256 proof's terms are defined only by the P-256 context: the Ed25519 context is refused")]
    public async Task P256Capability_WithTheEd25519SuiteContext_IsRejected()
    {
        var (owner, agent, root, delegated) = await DelegateP256Async();

        // A post-signing context swap leaves the document triples intact, but the proof's created,
        // proofPurpose and verificationMethod would no longer be defined. The verifier refuses the shape
        // before the signature is considered (R-CTX-2).
        delegated.Context = new object[] { ZcapContext, Ed25519Context };
        var swapped = await _verifier.VerifyCapabilityChainDetailedAsync(delegated);
        swapped.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        swapped.Message.Should().Contain(P256Context);

        // Signing refuses it outright: EcdsaSecp256r1Signature2019 is undefined under the Ed25519 context,
        // and DataProofs 1.5.0 refuses to drop it from the signature.
        var unsigned = UnsignedChild(root, agent, new object[] { ZcapContext, Ed25519Context });
        var act = () => _signing.SignCapabilityAsync(unsigned, owner, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        await act.Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact(DisplayName = "An Ed25519 proof under the P-256 context is refused the same way")]
    public async Task Ed25519Capability_WithTheP256SuiteContext_IsRejected()
    {
        var owner = _did.GenerateDidKey();
        var agent = _did.GenerateDidKey();
        var root = _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(owner, Target, new[] { "read" }));
        var delegated = await _caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));

        delegated.Context = new object[] { ZcapContext, P256Context };
        var result = await _verifier.VerifyCapabilityChainDetailedAsync(delegated);
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        result.Message.Should().Contain(Ed25519Context);

        var unsigned = UnsignedChild(root, agent, new object[] { ZcapContext, P256Context });
        var act = () => _signing.SignCapabilityAsync(unsigned, owner, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        await act.Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact(DisplayName = "The unpublished ecdsa-2019/v1 URL is rejected as an unsupported context")]
    public async Task UnpublishedEcdsa2019Url_IsRejected()
    {
        const string unpublished = "https://w3id.org/security/suites/ecdsa-2019/v1";
        var (owner, agent, root, delegated) = await DelegateP256Async();

        delegated.Context = new object[] { ZcapContext, unpublished };
        var result = await _verifier.VerifyCapabilityChainDetailedAsync(delegated);
        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        result.Message.Should().Contain("context");

        var unsigned = UnsignedChild(root, agent, new object[] { ZcapContext, unpublished });
        var act = () => _signing.SignCapabilityAsync(unsigned, owner, Proof.CapabilityDelegationPurpose, new object[] { root.Id });
        await act.Should().ThrowAsync<CapabilityValidationException>();
    }
}
