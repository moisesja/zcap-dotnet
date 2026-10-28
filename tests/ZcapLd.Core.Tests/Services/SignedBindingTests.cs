using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Fields the verifier relies on for freshness, replay and parent selection must be bound by the
/// signature that authorizes them (#157 Phase 0). Each case signs a valid object, changes one such
/// field afterwards, and expects verification to fail.
/// </summary>
public class SignedBindingTests
{
    private const string Target = "https://example.com/bound";
    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;

    public SignedBindingTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService CreateVerifier()
        => new(_didProvider, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore());

    private async Task<(Capability root, Capability delegated, string rootDid, string leafDid)> DelegateAsync(
        string target = Target)
    {
        var rootDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(1));
        return (root, delegated, rootDid, leafDid);
    }

    private async Task<Invocation> SignEnvelopeAsync(Capability capability, string signerDid, string? id = null)
    {
        var invocation = _capabilityService.CreateInvocation(capability, "read");
        if (id is not null) invocation.Id = id;
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, signerDid);
        return invocation;
    }

    [Fact(DisplayName = "Positive control: raw-signed delegation and invocation verify")]
    public async Task RawProofSigner_ProducesProofsTheVerifierAccepts()
    {
        // The adversarial cases below sign with RawProofSigner; this proves its signatures are
        // genuine, so their rejections come from the guard under test and not from a bad signature.
        var (root, delegated, rootDid, leafDid) = await DelegateAsync();
        delegated.Proof = await RawProofSigner.SignCapabilityAsync(
            _didProvider, delegated, rootDid, new object[] { root.Id });
        var invocation = _capabilityService.CreateInvocation(delegated, "read");
        invocation.Proof = await RawProofSigner.SignInvocationAsync(_didProvider, invocation, leafDid);

        (await CreateVerifier().VerifyInvocationDetailedAsync(invocation, delegated)).Outcome
            .Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "Envelope invocation: re-stamping proof.created breaks the signature")]
    public async Task EnvelopeInvocation_RestampedCreated_IsRejected()
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();
        var invocation = await SignEnvelopeAsync(delegated, leafDid);
        invocation.Proof!.Created = ZcapTimestamps.Format(invocation.Proof.CreatedAt!.Value.AddSeconds(-30));

        var result = await CreateVerifier().VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.InvalidSignature,
            "freshness depends on created, so created must be inside the signed proof options");
    }

    [Fact(DisplayName = "Signed revocation: re-stamping proof.created breaks the signature")]
    public async Task SignedRevocation_RestampedCreated_IsRejected()
    {
        var (root, delegated, rootDid, _) = await DelegateAsync();
        var revocation = await _signingService.SignRevocationAsync(delegated.Id, rootDid, delegated.InvocationTarget);
        revocation.Proof!.Created = ZcapTimestamps.Format(revocation.Proof.CreatedAt!.Value.AddSeconds(-30));

        (await CreateVerifier().RevokeCapabilityAsync(delegated, revocation, root)).Should().BeFalse();
    }

    [Fact(DisplayName = "Envelope invocation: changing an absolute id breaks the signature")]
    public async Task EnvelopeInvocation_ChangedAbsoluteId_IsRejected()
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();
        var invocation = await SignEnvelopeAsync(delegated, leafDid);
        invocation.Id = $"urn:uuid:{Guid.NewGuid()}";

        (await CreateVerifier().VerifyInvocationDetailedAsync(invocation, delegated)).Outcome
            .Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Theory(DisplayName = "Envelope invocation: an id that RDF cannot bind is refused")]
    [InlineData("nonce-1", "nonce-2")]
    [InlineData("urn:uuid:5c0a1a3e-4d4e-4a8f-9f43-8f3b3f1b6a11", "URN:uuid:5c0a1a3e-4d4e-4a8f-9f43-8f3b3f1b6a11")]
    public async Task EnvelopeInvocation_UnboundId_IsRefused(string signedId, string presentedId)
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();
        var invocation = _capabilityService.CreateInvocation(delegated, "read");
        invocation.Id = signedId;
        // SigningService refuses such ids; an attacker's own signer would not.
        invocation.Proof = await RawProofSigner.SignInvocationAsync(_didProvider, invocation, leafDid);
        invocation.Id = presentedId;

        var result = await CreateVerifier().VerifyInvocationDetailedAsync(invocation, delegated);

        result.Outcome.Should().Be(VerificationOutcome.MalformedCapability,
            "the replay nonce must be an id the signature binds, so a different nonce must not verify");
    }

    [Theory(DisplayName = "Signing refuses an invocation id the signature cannot bind")]
    [InlineData("nonce-1")]
    [InlineData("URN:uuid:5c0a1a3e-4d4e-4a8f-9f43-8f3b3f1b6a11")]
    public async Task SignInvocation_UnboundId_Throws(string id)
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();

        var act = () => SignEnvelopeAsync(delegated, leafDid, id);

        await act.Should().ThrowAsync<ZcapLd.Core.Exceptions.CapabilityValidationException>();
    }

    [Fact(DisplayName = "DI invocation: a relative document id (the nonce) is refused")]
    public async Task DataIntegrityInvocation_RelativeDocumentId_IsRefused()
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();
        var secured = await _signingService.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "read", Target, leafDid);
        secured["id"] = "nonce-2";

        (await CreateVerifier().VerifyCapabilityInvocationDetailedAsync(secured, "read", Target)).Outcome
            .Should().Be(VerificationOutcome.MalformedCapability,
                "a relative id is not bound by RDF, so it cannot serve as the replay nonce");
    }

    [Fact(DisplayName = "DI invocation signing refuses a relative document id")]
    public async Task SignDataIntegrityInvocation_RelativeDocumentId_Throws()
    {
        var (_, delegated, _, leafDid) = await DelegateAsync();
        var document = new JsonObject
        {
            ["@context"] = new JsonArray("https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1"),
            ["id"] = "nonce-1",
            ["type"] = "https://w3id.org/zcap#CapabilityInvocationRequest",
        };

        var act = () => _signingService.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(delegated), "read", Target, leafDid, document);

        await act.Should().ThrowAsync<ZcapLd.Core.Exceptions.CapabilityValidationException>();
    }

    [Fact(DisplayName = "Capability id: a case variant of the scheme is not the signed id")]
    public async Task DelegatedCapability_SchemeCaseVariantId_IsRefused()
    {
        var (_, delegated, _, _) = await DelegateAsync();
        var json = JsonNode.Parse(JsonSerializer.Serialize(delegated, ZcapJsonOptions.Default))!;
        json["id"] = "URN" + delegated.Id["urn".Length..];
        var variant = json.Deserialize<Capability>(ZcapJsonOptions.Default)!;

        (await CreateVerifier().VerifyCapabilityChainDetailedAsync(variant)).IsValid
            .Should().BeFalse("revocation is keyed by the id string, so a variant id must not verify as the same capability");
    }

    [Fact(DisplayName = "Proof set: the parent comes from the proof that verifies, not a junk proof")]
    public async Task ProofSet_JunkProofCannotChooseTheParent()
    {
        // alice (root controller) has two grants for dave sharing one id: P (read) and P* (read, write).
        // dave signs C (read, write) under P, which P does not allow; the real proof embeds P. A junk
        // first proof embedding P* must not let the chain walk judge C against P*.
        var alice = _didProvider.GenerateDidKey();
        var dave = _didProvider.GenerateDidKey();
        var carol = _didProvider.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, alice, Target, new[] { "read", "write" });
        var expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1));
        var parentId = $"urn:uuid:{Guid.NewGuid()}";

        async Task<Capability> SignAsync(Capability capability, string signer, object[] chain)
        {
            capability.Proof = await _signingService.SignCapabilityAsync(capability, signer, "capabilityDelegation", chain);
            return capability;
        }

        Capability Delegated(string id, string parent, string controller, string[] actions) => new()
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = id,
            ParentCapability = parent,
            Controller = controller,
            InvocationTarget = Target,
            AllowedAction = actions,
            Expires = expires,
        };

        var p = await SignAsync(Delegated(parentId, root.Id, dave, new[] { "read" }), alice, new object[] { root.Id });
        var pStar = await SignAsync(Delegated(parentId, root.Id, dave, new[] { "read", "write" }), alice, new object[] { root.Id });
        var c = await SignAsync(
            Delegated($"urn:uuid:{Guid.NewGuid()}", parentId, carol, new[] { "read", "write" }), dave, new object[] { root.Id, p });

        var realProof = c.Proof!.Primary;
        var junkProof = new Proof
        {
            Type = realProof.Type,
            Created = realProof.Created,
            ProofPurpose = realProof.ProofPurpose,
            VerificationMethod = realProof.VerificationMethod,
            CapabilityChain = new object[] { root.Id, pStar },
            ProofValue = MultibaseCodec.Encode(new byte[64]),
        };
        c.Proof = ProofSet.FromValues(new[] { junkProof, realProof });

        var result = await CreateVerifier().VerifyCapabilityChainDetailedAsync(c);

        result.IsValid.Should().BeFalse("the only valid signature binds C to P, and C exceeds P");
    }
}
