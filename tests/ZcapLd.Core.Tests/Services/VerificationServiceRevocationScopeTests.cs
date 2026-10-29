using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Revocation records are scoped to the delegator that signed the capability (#158), as
/// <c>bedrock-zcap-storage</c> keys them. A delegated id is chosen by whoever signs the delegation,
/// so a record keyed by the bare id let anyone with a chain under any trusted root revoke another
/// party's capability by minting a copy of its id under their own chain. A forged copy is signed by
/// the forger, so its record lands in the forger's scope, where no genuine chain looks.
/// </summary>
public class VerificationServiceRevocationScopeTests
{
    private readonly InMemoryDidProvider _dids = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    private readonly InMemoryRevocationStore _store = new();
    private readonly RevocationService _revocations;
    private readonly InMemoryRootCapabilityResolver _roots = new();
    private readonly VerificationService _verifier;

    public VerificationServiceRevocationScopeTests()
    {
        _signing = new SigningService(_dids, _dids);
        _caps = new CapabilityService(_signing);
        _revocations = new RevocationService(_store);
        _verifier = NewVerifier(_roots);
    }

    private VerificationService NewVerifier(IRootCapabilityResolver roots, IRevocationService? revocations = null)
        => new(_dids, revocations ?? _revocations, new InMemoryNonceStore(), relationshipResolver: _dids, rootResolver: roots);

    private async Task<Capability> RootAsync(ControllerSet controller, string target)
        => _roots.Register(await _caps.CreateRootCapabilityAsync(controller, target));

    /// <summary>Delegates with an expiry inside the parent's, so deeper links attenuate correctly.</summary>
    private Task<Capability> DelegateAsync(Capability parent, string controller, string? signerDid = null)
        => _caps.DelegateCapabilityAsync(
            parent, controller, new[] { "read" },
            parent.ExpiresAt is { } parentExpires ? parentExpires.AddMinutes(-1) : DateTime.UtcNow.AddDays(1),
            signerDid);

    /// <summary>A delegated capability with a chosen id, as an attacker's own tooling would mint it.</summary>
    private static Capability Forge(string id, string controller, Capability parent, string[]? allowedAction = null)
        => new()
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = id,
            Controller = controller,
            InvocationTarget = parent.InvocationTarget,
            AllowedAction = allowedAction,
            Expires = parent.Expires ?? ZcapTimestamps.Format(DateTime.UtcNow.AddDays(1)),
            ParentCapability = parent.Id
        };

    private async Task<bool> RevokeAsync(VerificationService verifier, Capability capability, string signerDid)
    {
        var request = await _signing.SignRevocationAsync(capability.Id, signerDid, capability.InvocationTarget);
        return await verifier.RevokeCapabilityAsync(capability, request);
    }

    private async Task<VerificationOutcome> EnvelopeInvocationOutcomeAsync(Capability leaf, string invokerDid)
    {
        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(leaf),
            CapabilityAction = "read",
            InvocationTarget = leaf.InvocationTarget
        };
        invocation.Proof = await _signing.SignInvocationAsync(invocation, invokerDid);
        return (await _verifier.VerifyInvocationDetailedAsync(invocation, leaf)).Outcome;
    }

    private async Task<VerificationOutcome> DataIntegrityInvocationOutcomeAsync(Capability leaf, string invokerDid)
    {
        var document = await _signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(leaf), "read", leaf.InvocationTarget, invokerDid);
        return (await _verifier.VerifyCapabilityInvocationDetailedAsync(document, "read", leaf.InvocationTarget)).Outcome;
    }

    // ----- (a) the issue's reproduction: cross-root delegated id, one verifier, standard roots -----

    [Fact]
    public async Task CrossRoot_ForgedCopyOfAVictimsDelegatedId_RevokesOnlyTheForgersScope()
    {
        var attacker = _dids.GenerateDidKey();
        var victim = _dids.GenerateDidKey();
        var victimChild = _dids.GenerateDidKey();
        var attackerRoot = await RootAsync(attacker, "https://attacker.example/r");
        var victimRoot = await RootAsync(victim, "https://victim.example/r");
        var victimDelegation = await DelegateAsync(victimRoot, victimChild);

        var forged = Forge(victimDelegation.Id, attacker, attackerRoot);
        forged.Proof = await _signing.SignCapabilityAsync(forged, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });

        (await RevokeAsync(_verifier, forged, attacker)).Should().BeTrue(
            "the forgery is a genuine capability under the attacker's own root; revoking it is legitimate");

        (await _verifier.VerifyCapabilityChainDetailedAsync(victimDelegation)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.VerifyCapabilityProofDetailedAsync(victimDelegation)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.IsCapabilityRevokedAsync(victimDelegation.Id, RevocationScope.Delegated(victim))).Should().BeFalse();
        (await _verifier.IsCapabilityRevokedAsync(victimDelegation.Id, RevocationScope.Delegated(attacker))).Should().BeTrue();
        (await _verifier.VerifyCapabilityChainDetailedAsync(forged)).Outcome.Should().Be(VerificationOutcome.Revoked);

        var id = victimDelegation.Id;
        (await _store.GetAsync([RevocationScope.Delegated(victim).KeyFor(id), RevocationScope.Unscoped.KeyFor(id), RevocationScope.Root.KeyFor(id)]))
            .Should().BeEmpty("the signed path writes only the forger's scope, never an unscoped record");
    }

    // ----- (b) a custom root another verifier trusts, two verifiers sharing one store -----

    [Fact]
    public async Task SharedStore_ForgedCopyOfAnotherVerifiersCustomRootId_DoesNotRevokeThatRoot()
    {
        var attacker = _dids.GenerateDidKey();
        var victim = _dids.GenerateDidKey();

        var rootsA = new InMemoryRootCapabilityResolver();
        var attackerRoot = rootsA.Register(await _caps.CreateRootCapabilityAsync(attacker, "https://attacker.example/r2"));
        var verifierA = NewVerifier(rootsA);

        var rootsB = new InMemoryRootCapabilityResolver();
        var customRoot = rootsB.Register(new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "https://victim.example/custom-root",
            Controller = victim,
            InvocationTarget = "https://victim.example/resource"
        });
        var verifierB = NewVerifier(rootsB); // same RevocationService, hence the same store

        var forged = Forge(customRoot.Id, attacker, attackerRoot);
        forged.Proof = await _signing.SignCapabilityAsync(forged, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });

        (await RevokeAsync(verifierA, forged, attacker)).Should().BeTrue(
            "verifier A does not know the id as a root, and the forgery is a genuine delegation under A's root");

        (await verifierB.VerifyCapabilityProofDetailedAsync(customRoot)).Outcome.Should().Be(VerificationOutcome.Valid);
        var underB = await DelegateAsync(customRoot, _dids.GenerateDidKey());
        (await verifierB.VerifyCapabilityChainDetailedAsync(underB)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await verifierB.IsCapabilityRevokedAsync(customRoot.Id, RevocationScope.Root)).Should().BeFalse();
        (await verifierB.IsCapabilityRevokedAsync(customRoot.Id, RevocationScope.Delegated(attacker))).Should().BeTrue(
            "the record exists, in the forger's scope only");
    }

    // ----- (c) a sibling under the same root -----

    [Fact]
    public async Task SameRoot_SiblingForgingAnotherSiblingsId_DoesNotRevokeIt()
    {
        var owner = _dids.GenerateDidKey();
        var holderA = _dids.GenerateDidKey();
        var holderB = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/siblings");
        var a = await DelegateAsync(root, holderA);
        var b = await DelegateAsync(root, holderB);

        // Holder A controls a and may delegate it, so a child of a carrying b's id is a genuine capability.
        var forged = Forge(b.Id, holderA, a, new[] { "read" });
        forged.Proof = await _signing.SignCapabilityAsync(forged, holderA, "capabilityDelegation", new object[] { root.Id, a });

        (await RevokeAsync(_verifier, forged, holderA)).Should().BeTrue();

        (await _verifier.VerifyCapabilityChainDetailedAsync(b)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.IsCapabilityRevokedAsync(b.Id, RevocationScope.Delegated(owner))).Should().BeFalse(
            "b was delegated by the owner; only a record in the owner's scope revokes it");
        (await _verifier.IsCapabilityRevokedAsync(b.Id, RevocationScope.Delegated(holderA))).Should().BeTrue();
    }

    // ----- (d) a forged parent and a forged leaf, both borrowing the victim's ids -----

    [Fact]
    public async Task ForgedParentAndLeaf_RevokingBoth_LeavesTheVictimsChainValid()
    {
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var attacker = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/deep");
        var p = await DelegateAsync(root, mid);
        var x = await DelegateAsync(p, holder);
        var attackerRoot = await RootAsync(attacker, "https://attacker.example/deep");

        var pStar = Forge(p.Id, attacker, attackerRoot);
        pStar.Proof = await _signing.SignCapabilityAsync(pStar, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });
        var xStar = Forge(x.Id, attacker, pStar);
        xStar.Proof = await _signing.SignCapabilityAsync(xStar, attacker, "capabilityDelegation", new object[] { attackerRoot.Id, pStar });

        (await RevokeAsync(_verifier, xStar, attacker)).Should().BeTrue();
        (await RevokeAsync(_verifier, pStar, attacker)).Should().BeTrue();

        (await _verifier.VerifyCapabilityChainDetailedAsync(x)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.VerifyCapabilityProofDetailedAsync(x)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.IsCapabilityRevokedAsync(x.Id, RevocationScope.Delegated(mid))).Should().BeFalse();
        (await _verifier.IsCapabilityRevokedAsync(p.Id, RevocationScope.Delegated(owner))).Should().BeFalse();
    }

    // ----- (e) genuine revocations are seen on every verification path -----

    [Theory]
    [InlineData("owner", "mid")]
    [InlineData("owner", "leaf")]
    [InlineData("mid", "mid")]
    [InlineData("mid", "leaf")]
    [InlineData("holder", "leaf")]
    public async Task GenuineRevocation_IsSeenOnEveryPath(string revoker, string target)
    {
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, $"https://example.com/paths/{revoker}/{target}");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);

        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await EnvelopeInvocationOutcomeAsync(leaf, holder)).Should().Be(VerificationOutcome.Valid);
        (await DataIntegrityInvocationOutcomeAsync(leaf, holder)).Should().Be(VerificationOutcome.Valid);

        var revokerDid = revoker switch { "owner" => owner, "mid" => mid, _ => holder };
        var revoked = target == "mid" ? p : leaf;
        (await RevokeAsync(_verifier, revoked, revokerDid)).Should().BeTrue();

        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
        (await EnvelopeInvocationOutcomeAsync(leaf, holder)).Should().Be(VerificationOutcome.Revoked);
        (await DataIntegrityInvocationOutcomeAsync(leaf, holder)).Should().Be(VerificationOutcome.Revoked);

        // The record names the delegator of the revoked link, whoever signed the request, and the chain's root.
        var expectedScope = RevocationScope.Delegated(target == "mid" ? owner : mid);
        var record = await _revocations.GetRevocationAsync(revoked.Id, expectedScope);
        record.Should().NotBeNull();
        record!.Scope.Should().Be(expectedScope);
        record.RevokedBy.Should().Be(revokerDid);
        record.RootCapabilityId.Should().Be(root.Id);
    }

    // ----- (f) forged and genuine records for one id coexist in either order -----

    [Fact]
    public async Task ForgedAndGenuineRecords_CoexistInEitherOrder()
    {
        var owner = _dids.GenerateDidKey();
        var attacker = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/order");
        var attackerRoot = await RootAsync(attacker, "https://attacker.example/order");

        async Task<(Capability Victim, Capability Forged)> PairAsync()
        {
            var victim = await DelegateAsync(root, _dids.GenerateDidKey());
            var forged = Forge(victim.Id, attacker, attackerRoot);
            forged.Proof = await _signing.SignCapabilityAsync(forged, attacker, "capabilityDelegation", new object[] { attackerRoot.Id });
            return (victim, forged);
        }

        var (victim1, forged1) = await PairAsync();
        (await RevokeAsync(_verifier, forged1, attacker)).Should().BeTrue();
        (await RevokeAsync(_verifier, victim1, owner)).Should().BeTrue("a forged record never blocks the genuine revocation as 'already revoked'");
        (await _verifier.VerifyCapabilityChainDetailedAsync(victim1)).Outcome.Should().Be(VerificationOutcome.Revoked);

        var (victim2, forged2) = await PairAsync();
        (await RevokeAsync(_verifier, victim2, owner)).Should().BeTrue();
        (await RevokeAsync(_verifier, forged2, attacker)).Should().BeTrue();
        (await _verifier.VerifyCapabilityChainDetailedAsync(victim2)).Outcome.Should().Be(VerificationOutcome.Revoked,
            "a later forged write must not overwrite or shadow the genuine record");
        (await _store.GetAsync([RevocationScope.Delegated(owner).KeyFor(victim2.Id), RevocationScope.Delegated(attacker).KeyFor(victim2.Id)]))
            .Should().HaveCount(2);
    }

    // ----- (g) unscoped records (5.x / operator) apply everywhere; the signed path never writes one -----

    [Fact]
    public async Task UnscopedRecord_RevokesOnEveryPath_AndTheSignedPathNeverWritesOne()
    {
        var owner = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/legacy");
        var leaf = await DelegateAsync(root, holder);

        await _revocations.RevokeAsync(new RevocationRequest
        {
            CapabilityId = leaf.Id, Scope = RevocationScope.Unscoped, RevokedBy = "did:example:operator"
        });

        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
        (await DataIntegrityInvocationOutcomeAsync(leaf, holder)).Should().Be(VerificationOutcome.Revoked);

        var another = await DelegateAsync(root, _dids.GenerateDidKey());
        (await RevokeAsync(_verifier, another, owner)).Should().BeTrue();
        (await _store.GetAsync([RevocationScope.Unscoped.KeyFor(another.Id)])).Should().BeEmpty();
        (await _store.GetAsync([RevocationScope.Delegated(owner).KeyFor(another.Id)])).Should().ContainSingle();
    }

    // ----- (h) a leaf signed by two co-controllers of its parent -----

    [Fact]
    public async Task CoSignedDelegation_RecordsEverySigner_SoDroppingAProofDoesNotRevive()
    {
        var alice = _dids.GenerateDidKey();
        var bob = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(new[] { alice, bob }, "https://example.com/co-signed");
        var leaf = await DelegateAsync(root, holder, signerDid: alice);
        var aliceProof = leaf.Proof!.Primary;
        var bobProof = await _signing.SignCapabilityAsync(leaf, bob, "capabilityDelegation", new object[] { root.Id });
        leaf.Proof = ProofSet.FromValues([aliceProof, bobProof]);
        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);

        (await RevokeAsync(_verifier, leaf, alice)).Should().BeTrue();

        (await _verifier.IsCapabilityRevokedAsync(leaf.Id, RevocationScope.Delegated(alice))).Should().BeTrue();
        (await _verifier.IsCapabilityRevokedAsync(leaf.Id, RevocationScope.Delegated(bob))).Should().BeTrue(
            "Bob's proof names the same chain and verifies, so his scope is recorded too");

        var bobOnly = CapabilityJson.Parse(CapabilityJson.Serialize(leaf));
        bobOnly.Proof = bobProof;
        (await _verifier.VerifyCapabilityChainDetailedAsync(bobOnly)).Outcome.Should().Be(VerificationOutcome.Revoked,
            "stripping the recorded signer's proof must not revive the capability");
        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
    }

    // ----- (i) a misbehaving store fails closed, and a failed write leaves the nonce unconsumed -----

    [Fact]
    public async Task StoreThatLosesWrites_FailsTheRevocationClosed_AndTheSameRequestSucceedsOnRetry()
    {
        var owner = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/lossy");
        var leaf = await DelegateAsync(root, _dids.GenerateDidKey());
        var lossy = new LossyStore { LoseWrites = true };
        var verifier = NewVerifier(_roots, new RevocationService(lossy));
        var request = await _signing.SignRevocationAsync(leaf.Id, owner, leaf.InvocationTarget);

        (await verifier.RevokeCapabilityAsync(leaf, request)).Should().BeFalse(
            "the record did not read back under its key, so nothing was revoked");
        (await verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);

        lossy.LoseWrites = false;
        (await verifier.RevokeCapabilityAsync(leaf, request)).Should().BeTrue(
            "the replay nonce is consumed only after a confirmed write, so the same request can be retried");
        (await verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
    }

    [Fact]
    public async Task StoreThatAnswersByBareId_MakesVerificationFailClosed_NotOpen()
    {
        var owner = _dids.GenerateDidKey();
        var attacker = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/by-id");
        var victim = await DelegateAsync(root, _dids.GenerateDidKey());
        var byId = new ByCapabilityIdStore();
        await byId.UpsertAsync(new RevocationRecord
        {
            CapabilityId = victim.Id, Scope = RevocationScope.Delegated(attacker), RevokedBy = attacker, RevokedAt = DateTime.UtcNow
        });
        var verifier = NewVerifier(_roots, new RevocationService(byId));

        var result = await verifier.VerifyCapabilityChainDetailedAsync(victim);

        result.Outcome.Should().Be(VerificationOutcome.CouldNotVerify,
            "a store that ignores the scope is a misconfiguration to surface, not a record to honour");
    }

    // ----- (k) the standalone path reads an unverified ancestry: it must fail closed, never throw -----

    [Fact]
    public async Task Standalone_EmbeddedParentWithoutAProof_FailsClosedInsteadOfLookingUpUnscoped()
    {
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/proofless-parent");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);
        (await RevokeAsync(_verifier, p, owner)).Should().BeTrue();
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);

        // mid still holds its key and re-signs the leaf around a copy of p stripped of its proof, so the
        // sweep could look p up only unscoped. The route is unusable instead (red team, #158).
        var strippedParent = CapabilityJson.Parse(CapabilityJson.Serialize(p));
        strippedParent.Proof = null;
        var resigned = CapabilityJson.Parse(CapabilityJson.Serialize(leaf));
        resigned.Proof = await RawProofSigner.SignCapabilityAsync(_dids, resigned, mid, new object[] { root.Id, strippedParent });

        (await _verifier.VerifyCapabilityProofDetailedAsync(resigned)).Outcome.Should().Be(VerificationOutcome.MalformedCapability);
        (await _verifier.VerifyCapabilityChainDetailedAsync(resigned)).IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task Standalone_JunkProofAheadOfTheGenuineOneOnTheEmbeddedParent_StillFindsTheRevocation()
    {
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/decoy-parent");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);
        (await RevokeAsync(_verifier, p, owner)).Should().BeTrue();

        // A proof naming another route is skipped, not counted against the budget or the genuine proof.
        var decoy = CapabilityJson.Parse(CapabilityJson.Serialize(p));
        var genuine = decoy.Proof!.Primary;
        var junk = JsonSerializer.Deserialize<Proof>(JsonSerializer.Serialize(genuine, ZcapJsonOptions.Default), ZcapJsonOptions.Default)!;
        junk.CapabilityChain = new object[] { "urn:uuid:" + Guid.NewGuid() };
        decoy.Proof = ProofSet.FromValues([junk, genuine]);
        var resigned = CapabilityJson.Parse(CapabilityJson.Serialize(leaf));
        resigned.Proof = await RawProofSigner.SignCapabilityAsync(_dids, resigned, mid, new object[] { root.Id, decoy });

        (await _verifier.VerifyCapabilityProofDetailedAsync(resigned)).Outcome.Should().Be(VerificationOutcome.Revoked);
    }

    [Fact]
    public async Task Standalone_NestedWhitespaceIdOrUnparsableParent_ReturnsAResultInsteadOfThrowing()
    {
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/crafted-ancestry");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);

        // A whitespace id nested in the embedded parent's chain reached the store as an ArgumentException.
        var blank = CapabilityJson.Parse(CapabilityJson.Serialize(p));
        blank.Proof!.Primary.CapabilityChain = new object[] { " " };
        var aroundBlank = CapabilityJson.Parse(CapabilityJson.Serialize(leaf));
        aroundBlank.Proof = await RawProofSigner.SignCapabilityAsync(_dids, aroundBlank, mid, new object[] { root.Id, blank });
        var blankAct = () => _verifier.VerifyCapabilityProofDetailedAsync(aroundBlank);
        (await blankAct.Should().NotThrowAsync()).Which.IsValid.Should().BeFalse();

        // An embedded parent that does not deserialize escaped as a JsonException.
        var unparsable = CapabilityJson.Edit(leaf, json => json["proof"]!["capabilityChain"]![1]!["expires"] = 123);
        var unparsableAct = () => _verifier.VerifyCapabilityProofDetailedAsync(unparsable);
        (await unparsableAct.Should().NotThrowAsync()).Which.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task Standalone_EmbeddedParentWithASwappedVerificationMethod_FailsClosedInsteadOfQueryingTheWrongScope()
    {
        // PR #162 review, finding 1: the parent's controller keeps its key after the parent is revoked.
        // It clones the parent, points the parent's proof at a fresh DID (the signature is now invalid,
        // but the standalone path never checked it), re-signs the leaf around that copy with the
        // ordinary signing service, and the sweep would query the parent under the fabricated delegator.
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, "https://example.com/swapped-method");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);
        (await RevokeAsync(_verifier, p, owner)).Should().BeTrue();
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);

        var swapped = CapabilityJson.Parse(CapabilityJson.Serialize(p));
        swapped.Proof!.Primary.VerificationMethod = await _dids.GetVerificationMethodAsync(_dids.GenerateDidKey());
        var resigned = CapabilityJson.Parse(CapabilityJson.Serialize(leaf));
        resigned.Proof = await _signing.SignCapabilityAsync(resigned, mid, "capabilityDelegation", new object[] { root.Id, swapped });

        var standalone = await _verifier.VerifyCapabilityProofDetailedAsync(resigned);
        standalone.IsValid.Should().BeFalse("the ancestor's delegator is established only by verifying its proof");
        standalone.Outcome.Should().Be(VerificationOutcome.InvalidSignature);
        (await _verifier.VerifyCapabilityChainDetailedAsync(resigned)).IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Standalone_UnusableExtraProof_DoesNotVetoTheGenuineOne(bool genuineFirst)
    {
        // PR #162 review, finding 2: a proof set with the genuine leaf proof and a clone whose embedded
        // parent lost its proof. Nothing is re-signed; the genuine proof stays valid and must win on the
        // standalone path as it does on the chain path, in either order.
        var owner = _dids.GenerateDidKey();
        var mid = _dids.GenerateDidKey();
        var holder = _dids.GenerateDidKey();
        var root = await RootAsync(owner, $"https://example.com/no-veto/{genuineFirst}");
        var p = await DelegateAsync(root, mid);
        var leaf = await DelegateAsync(p, holder);

        var genuine = leaf.Proof!.Primary;
        var junk = JsonSerializer.Deserialize<Proof>(JsonSerializer.Serialize(genuine, ZcapJsonOptions.Default), ZcapJsonOptions.Default)!;
        var prooflessParent = CapabilityJson.Parse(CapabilityJson.Serialize(p));
        prooflessParent.Proof = null;
        junk.CapabilityChain = new object[] { root.Id, prooflessParent };
        leaf.Proof = ProofSet.FromValues(genuineFirst ? [genuine, junk] : [junk, genuine]);

        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);
        (await _verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Valid);

        // The same set still reports a revocation found on the genuine route.
        (await RevokeAsync(_verifier, p, owner)).Should().BeTrue();
        (await _verifier.VerifyCapabilityProofDetailedAsync(leaf)).Outcome.Should().Be(VerificationOutcome.Revoked);
    }

    /// <summary>Drops writes while <see cref="LoseWrites"/> is set, as a store with a broken key column would.</summary>
    private sealed class LossyStore : IRevocationStore
    {
        private readonly InMemoryRevocationStore _inner = new();

        public bool LoseWrites { get; set; }

        public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
            => LoseWrites ? Task.CompletedTask : _inner.UpsertAsync(record, cancellationToken);

        public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
            => _inner.GetAsync(keys, cancellationToken);

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => _inner.DeleteAsync(key, cancellationToken);
    }

    /// <summary>Keys by bare capability id and answers every read with every record, as a 5.x backend did.</summary>
    private sealed class ByCapabilityIdStore : IRevocationStore
    {
        private readonly Dictionary<string, RevocationRecord> _records = new(StringComparer.Ordinal);

        public Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
        {
            _records[record.CapabilityId] = record;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<RevocationRecord>>(_records.Values.ToList());

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
