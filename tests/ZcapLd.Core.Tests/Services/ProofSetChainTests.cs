using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// A delegated capability is valid when at least one of its delegation proofs verifies together with
/// the chain that proof names. An unverified proof must neither choose the parent another proof is
/// judged against (<see cref="SignedBindingTests.ProofSet_JunkProofCannotChooseTheParent"/>) nor
/// exclude a valid proof whose embedded parent is represented differently (PR #160 review).
/// </summary>
public class ProofSetChainTests
{
    private const string Target = "https://example.com/proof-sets";
    private readonly InMemoryDidProvider _did = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly string _expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1));

    public ProofSetChainTests()
    {
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
    }

    private VerificationService Verifier() =>
        new(_did, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore());

    private Capability Delegated(string id, string parent, string controller) => new()
    {
        Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
        Id = id,
        ParentCapability = parent,
        Controller = controller,
        InvocationTarget = Target,
        AllowedAction = new[] { "read" },
        Expires = _expires,
    };

    private async Task<Capability> SignAsync(Capability capability, string signer, object[] chain, DateTime created)
    {
        var copy = CapabilityJson.Parse(CapabilityJson.Serialize(capability));
        copy.Proof = await _signing.SignCapabilityAsync(copy, signer, Proof.CapabilityDelegationPurpose, chain, created);
        return copy;
    }

    // A delegation proof whose signature does not verify, naming another valid representation of the parent.
    private static Proof Junk(Proof genuine, object[] chain) => new()
    {
        Type = genuine.Type,
        Created = genuine.Created,
        ProofPurpose = genuine.ProofPurpose,
        VerificationMethod = genuine.VerificationMethod,
        CapabilityChain = chain,
        ProofValue = MultibaseCodec.Encode(new byte[64]),
    };

    private static Capability WithProofs(Capability capability, params Proof[] proofs)
    {
        var copy = CapabilityJson.Parse(CapabilityJson.Serialize(capability));
        copy.Proof = ProofSet.FromValues(proofs);
        return copy;
    }

    [Theory(DisplayName = "An unverified proof embedding another valid parent does not exclude the valid proof")]
    [InlineData(true)]
    [InlineData(false)]
    public async Task JunkProofWithAnotherValidParent_DoesNotExcludeTheValidProof(bool junkFirst)
    {
        // P1 and P2 grant the same authority under the same id; they differ only in their proof.
        var alice = _did.GenerateDidKey();
        var dave = _did.GenerateDidKey();
        var carol = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, alice, Target, new[] { "read" });
        var parent = Delegated($"urn:uuid:{Guid.NewGuid()}", root.Id, dave);
        var p1 = await SignAsync(parent, alice, new object[] { root.Id }, DateTime.UtcNow.AddMinutes(-2));
        var p2 = await SignAsync(parent, alice, new object[] { root.Id }, DateTime.UtcNow.AddMinutes(-1));
        var signed = await SignAsync(Delegated($"urn:uuid:{Guid.NewGuid()}", parent.Id, carol), dave,
            new object[] { root.Id, p2 }, DateTime.UtcNow);
        var genuine = signed.Proof!.Primary;
        var junk = Junk(genuine, new object[] { root.Id, p1 });
        var c = junkFirst ? WithProofs(signed, junk, genuine) : WithProofs(signed, genuine, junk);

        (await Verifier().VerifyCapabilityChainDetailedAsync(p1)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await Verifier().VerifyCapabilityChainDetailedAsync(p2)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await Verifier().VerifyCapabilityChainDetailedAsync(signed)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await Verifier().VerifyCapabilityChainDetailedAsync(c)).Outcome.Should().Be(VerificationOutcome.Valid);

        var invocation = _caps.CreateInvocation(c, "read");
        invocation.Proof = await _signing.SignInvocationAsync(invocation, carol);
        (await Verifier().VerifyInvocationDetailedAsync(invocation, c)).Outcome.Should().Be(VerificationOutcome.Valid);

        var revocation = await _signing.SignRevocationAsync(c.Id, dave, c.InvocationTarget);
        (await Verifier().RevokeCapabilityAsync(c, revocation)).Should().BeTrue();
    }

    [Theory(DisplayName = "The same holds for an embedded parent's own proof set")]
    [InlineData(true)]
    [InlineData(false)]
    public async Task JunkProofInsideAnEmbeddedParent_DoesNotExcludeItsValidProof(bool junkFirst)
    {
        // root → A (alice→bob) → B (bob→dave) → C (dave→carol). B carries a junk proof naming A', a
        // valid re-signed copy of A, next to its genuine proof naming A.
        var alice = _did.GenerateDidKey();
        var bob = _did.GenerateDidKey();
        var dave = _did.GenerateDidKey();
        var carol = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, alice, Target, new[] { "read" });
        var aTemplate = Delegated($"urn:uuid:{Guid.NewGuid()}", root.Id, bob);
        var a = await SignAsync(aTemplate, alice, new object[] { root.Id }, DateTime.UtcNow.AddMinutes(-3));
        var aPrime = await SignAsync(aTemplate, alice, new object[] { root.Id }, DateTime.UtcNow.AddMinutes(-2));
        var bSigned = await SignAsync(Delegated($"urn:uuid:{Guid.NewGuid()}", a.Id, dave), bob,
            new object[] { root.Id, a }, DateTime.UtcNow.AddMinutes(-1));
        var bGenuine = bSigned.Proof!.Primary;
        var bJunk = Junk(bGenuine, new object[] { root.Id, aPrime });
        var b = junkFirst ? WithProofs(bSigned, bJunk, bGenuine) : WithProofs(bSigned, bGenuine, bJunk);
        var c = await SignAsync(Delegated($"urn:uuid:{Guid.NewGuid()}", b.Id, carol), dave,
            new object[] { root.Id, a.Id, b }, DateTime.UtcNow);

        (await Verifier().VerifyCapabilityChainDetailedAsync(b)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await Verifier().VerifyCapabilityChainDetailedAsync(c)).Outcome.Should().Be(VerificationOutcome.Valid);
    }

    [Fact(DisplayName = "Only valid proofs: the result is the last proof's failure")]
    public async Task NoValidProof_IsInvalid()
    {
        var alice = _did.GenerateDidKey();
        var dave = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, alice, Target, new[] { "read" });
        var signed = await SignAsync(Delegated($"urn:uuid:{Guid.NewGuid()}", root.Id, dave), alice,
            new object[] { root.Id }, DateTime.UtcNow);
        var junk = Junk(signed.Proof!.Primary, new object[] { root.Id });

        (await Verifier().VerifyCapabilityChainDetailedAsync(WithProofs(signed, junk, junk))).Outcome
            .Should().Be(VerificationOutcome.InvalidSignature);
    }

    [Fact(DisplayName = "The search over proof sets is bounded")]
    public async Task ManyJunkProofs_StopAtTheCandidateLimit()
    {
        var alice = _did.GenerateDidKey();
        var dave = _did.GenerateDidKey();
        var root = await TestRoots.CreateAndRegisterRootAsync(_caps, _did, alice, Target, new[] { "read" });
        var signed = await SignAsync(Delegated($"urn:uuid:{Guid.NewGuid()}", root.Id, dave), alice,
            new object[] { root.Id }, DateTime.UtcNow);
        var genuine = signed.Proof!.Primary;
        var junk = Enumerable.Range(0, VerificationService.MaxChainCandidates)
            .Select(_ => Junk(genuine, new object[] { root.Id }));

        var result = await Verifier().VerifyCapabilityChainDetailedAsync(WithProofs(signed, junk.Append(genuine).ToArray()));

        result.IsValid.Should().BeFalse("the genuine proof lies beyond the candidate limit");
        result.Message.Should().Contain(VerificationService.MaxChainCandidates.ToString());
    }
}
