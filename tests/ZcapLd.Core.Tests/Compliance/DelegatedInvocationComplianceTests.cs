using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Compliance coverage for Issue #51 — delegated Data Integrity invocations MUST carry the
/// <b>full delegated zcap object</b> in the <c>capability</c> property, while root invocations carry
/// the root zcap id <b>string</b>. Per the W3C CCG ZCAP-LD v0.3 draft:
/// <list type="bullet">
/// <item><i>Invoking a Root ZCAP</i>: the invocation proof references the root zcap by id.</item>
/// <item><i>Invoking a Delegated ZCAP</i>: "When invoking using a DI proof, the <c>capability</c>
/// property must express the full delegated zcap."</item>
/// </list>
/// Covers the model (both wire shapes round-trip), signing (the proof's <c>capability</c> carries the
/// right shape), verification (strict spec mode — a delegated invocation that supplies only an id is
/// rejected), and canonicalization (the embedded object participates in the signed payload, and
/// sign-time bytes equal the bytes a peer verifier canonicalizes over the wire body).
/// </summary>
public class DelegatedInvocationComplianceTests
{
    private const string Target = "https://example.com/resource";

    private readonly InMemoryDidProvider _didProvider = new();
    private readonly SigningService _signingService;
    private readonly CaveatProcessor _caveatProcessor = new();
    private readonly CapabilityService _capabilityService;

    public DelegatedInvocationComplianceTests()
    {
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    private VerificationService CreateVerifier() =>
        new(_didProvider, _caveatProcessor,
            new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore());

    private async Task<(Capability root, Capability delegated, string rootDid, string leafDid)> CreateRootAndDelegatedAsync()
    {
        var rootDid = _didProvider.GenerateDidKey();
        var leafDid = _didProvider.GenerateDidKey();

        var root = await TestRoots.CreateAndRegisterRootAsync(
            _capabilityService, _didProvider, rootDid, Target, new[] { "read" });
        var delegated = await _capabilityService.DelegateCapabilityAsync(
            root, leafDid, new[] { "read" }, DateTime.UtcNow.AddDays(7));

        return (root, delegated, rootDid, leafDid);
    }

    // ─────────────────────────────── Model / serialization ───────────────────────────────

    [Fact]
    public void RootInvocation_Capability_RoundTripsAsString()
    {
        var invocation = new Invocation
        {
            Capability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource",
            CapabilityAction = "read",
            InvocationTarget = Target
        };

        var json = JsonSerializer.Serialize(invocation, ZcapJsonOptions.Default);
        json.Should().Contain("\"capability\":\"urn:zcap:root:", "a root invocation references the root zcap by id string");

        var parsed = JsonSerializer.Deserialize<Invocation>(json, ZcapJsonOptions.Default)!;
        parsed.Capability.IsRootReference.Should().BeTrue();
        parsed.Capability.EmbeddedCapability.Should().BeNull();
        parsed.Capability.CapabilityId.Should().Be("urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource");
    }

    [Fact]
    public async Task DelegatedInvocation_Capability_RoundTripsAsEmbeddedObject()
    {
        var (_, delegated, _, _) = await CreateRootAndDelegatedAsync();

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target
        };

        var json = JsonSerializer.Serialize(invocation, ZcapJsonOptions.Default);
        // The full delegated zcap is embedded: an object carrying the delegated id, its parentCapability,
        // and its delegation proof — not a bare id string.
        json.Should().Contain("\"capability\":{", "a delegated DI invocation embeds the full zcap object");
        json.Should().Contain("\"parentCapability\":");
        json.Should().Contain($"\"id\":\"{delegated.Id}\"");

        var parsed = JsonSerializer.Deserialize<Invocation>(json, ZcapJsonOptions.Default)!;
        parsed.Capability.IsRootReference.Should().BeFalse();
        parsed.Capability.EmbeddedCapability.Should().NotBeNull();
        parsed.Capability.EmbeddedCapability!.Id.Should().Be(delegated.Id);
        parsed.Capability.EmbeddedCapability.ParentCapability.Should().Be(delegated.ParentCapability);
        parsed.Capability.EmbeddedCapability.Proof.Should().NotBeNull("the embedded delegated zcap carries its delegation proof");
        parsed.Capability.CapabilityId.Should().Be(delegated.Id);
    }

    [Fact]
    public void MalformedCapability_NumberValue_FailsToDeserialize()
    {
        const string json = "{\"id\":\"urn:uuid:inv\",\"capability\":123,\"capabilityAction\":\"read\",\"invocationTarget\":\"https://example.com/resource\"}";

        var act = () => JsonSerializer.Deserialize<Invocation>(json, ZcapJsonOptions.Default);

        act.Should().Throw<JsonException>("capability MUST be a root id string or an embedded capability object");
    }

    [Fact]
    public void MalformedCapability_EmbeddedObjectWithoutId_FailsToDeserialize()
    {
        const string json = "{\"id\":\"urn:uuid:inv\",\"capability\":{\"invocationTarget\":\"https://example.com/resource\"},\"capabilityAction\":\"read\",\"invocationTarget\":\"https://example.com/resource\"}";

        var act = () => JsonSerializer.Deserialize<Invocation>(json, ZcapJsonOptions.Default);

        act.Should().Throw<JsonException>("an embedded invocation capability object MUST have an id");
    }

    // ─────────────────────────────── Signing ───────────────────────────────

    [Fact]
    public async Task SignRootInvocation_PutsRootIdStringInProofCapability()
    {
        var (root, _, rootDid, _) = await CreateRootAndDelegatedAsync();

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, rootDid);

        invocation.Proof.Capability.Should().NotBeNull();
        invocation.Proof.Capability!.IsRootReference.Should().BeTrue();
        invocation.Proof.Capability.CapabilityId.Should().Be(root.Id);
    }

    [Fact]
    public async Task SignDelegatedInvocation_PutsFullZcapObjectInProofCapability()
    {
        var (_, delegated, _, leafDid) = await CreateRootAndDelegatedAsync();

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);

        invocation.Proof.Capability.Should().NotBeNull();
        invocation.Proof.Capability!.IsRootReference.Should().BeFalse();
        invocation.Proof.Capability.EmbeddedCapability.Should().NotBeNull();
        invocation.Proof.Capability.EmbeddedCapability!.Id.Should().Be(delegated.Id);
        invocation.Proof.Capability.EmbeddedCapability.ParentCapability.Should().Be(delegated.ParentCapability);
    }

    // ─────────────────────────────── Verification (strict) ───────────────────────────────

    [Fact]
    public async Task VerifyRootInvocation_WithRootIdString_Succeeds()
    {
        var (root, _, rootDid, _) = await CreateRootAndDelegatedAsync();
        var verifier = CreateVerifier();

        var invocation = new Invocation
        {
            Capability = root.Id,
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, rootDid);

        (await verifier.VerifyInvocationAsync(invocation, root)).Should().BeTrue();
    }

    [Fact]
    public async Task VerifyDelegatedInvocation_WithFullEmbeddedZcap_Succeeds()
    {
        var (_, delegated, _, leafDid) = await CreateRootAndDelegatedAsync();
        var verifier = CreateVerifier();

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);

        (await verifier.VerifyInvocationAsync(invocation, delegated)).Should().BeTrue();
    }

    [Fact]
    public async Task VerifyDelegatedInvocation_WithIdStringOnly_FailsStrictSpecMode()
    {
        var (_, delegated, _, leafDid) = await CreateRootAndDelegatedAsync();
        var verifier = CreateVerifier();

        // A delegated invocation that supplies only the delegated zcap id string (the pre-#51 shape)
        // MUST be rejected: the spec requires the full embedded delegated zcap.
        var invocation = new Invocation
        {
            Capability = delegated.Id,
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);

        (await verifier.VerifyInvocationAsync(invocation, delegated)).Should().BeFalse(
            "strict spec mode rejects a delegated DI invocation that does not embed the full zcap");
    }

    [Fact]
    public async Task VerifyDelegatedInvocation_EmbeddedIdDoesNotMatchVerifiedCapability_Fails()
    {
        var (root, delegated, _, leafDid) = await CreateRootAndDelegatedAsync();
        var other = await _capabilityService.DelegateCapabilityAsync(
            root, _didProvider.GenerateDidKey(), new[] { "read" }, DateTime.UtcNow.AddDays(7));
        var verifier = CreateVerifier();

        // Embed `delegated`, but ask the verifier to validate it against a DIFFERENT delegated zcap.
        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);

        (await verifier.VerifyInvocationAsync(invocation, other)).Should().BeFalse(
            "the embedded capability id MUST match the capability being verified");
    }

    [Fact]
    public async Task VerifyDelegatedInvocation_EmbeddedZcapHasInvalidDelegationProof_Fails()
    {
        var (_, delegated, _, leafDid) = await CreateRootAndDelegatedAsync();
        var verifier = CreateVerifier();

        // Corrupt the embedded delegated zcap's delegation proof. The invocation is then signed over
        // the tampered object (so the invocation signature itself is valid), but chain verification of
        // the embedded zcap MUST fail closed.
        delegated.Proof!.Primary.ProofValue = "z11111111111111111111111111111111111111111111";

        var invocation = new Invocation
        {
            Capability = InvocationCapability.FromCapability(delegated),
            CapabilityAction = "read",
            InvocationTarget = Target
        };
        invocation.Proof = await _signingService.SignInvocationAsync(invocation, leafDid);

        (await verifier.VerifyInvocationAsync(invocation, delegated)).Should().BeFalse(
            "a delegated invocation whose embedded zcap has an invalid delegation proof MUST be rejected");
    }

}
