using System.Linq;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

/// <summary>
/// Spec-exact <c>capabilityChain</c> shape (Issue #50). Generation produces the minimal W3C ZCAP-LD
/// shape — <c>[rootId]</c> / <c>[rootId, {D1}]</c> / <c>[rootId, D1.id, {D2}]</c> — with the root
/// referenced by id only (never embedded) and only the immediate parent embedded; verification
/// resolves the root by id (explicit root or <see cref="IRootCapabilityResolver"/>) and rejects every
/// non-spec shape, failing closed when no root is available.
/// </summary>
public class CapabilityChainShapeTests
{
    private const string Target = "https://example.com/foo";
    // A single shared expiry for every level: equal child/parent expiry is valid attenuation, whereas
    // recomputing UtcNow per level would make a child expire microseconds after its parent (rejected).
    private static readonly DateTime Expiry = DateTime.UtcNow.AddDays(10);
    private readonly InMemoryDidProvider _did = new();
    private readonly SigningService _signing;
    private readonly CapabilityService _caps;
    // _did is auto-detected by VerificationService as the IRootCapabilityResolver, so a root
    // registered via RootAsync below is resolvable without passing it on each verify call.
    private readonly VerificationService _verifier;

    public CapabilityChainShapeTests()
    {
        _signing = new SigningService(_did, _did);
        _caps = new CapabilityService(_signing);
        _verifier = new VerificationService(_did, new CaveatProcessor());
    }

    private string NewController() => _did.GenerateDidKey();

    // Creates AND registers a root (registered roots are resolvable by the auto-wired resolver).
    private async Task<Capability> RootAsync(string controller, string[]? actions = null)
        => _did.RegisterRoot(await _caps.CreateRootCapabilityAsync(controller, Target, actions ?? new[] { "read", "write" }));

    private Task<Capability> DelegateAsync(Capability parent, string childController, string[] actions)
        => _caps.DelegateCapabilityAsync(parent, childController, actions, Expiry);

    // Builds a delegated capability whose proof is signed over an EXPLICIT (possibly malformed)
    // capabilityChain by an authorized signer, so verification fails (if at all) on chain SHAPE, not
    // on the signature or authorization.
    private async Task<Capability> SignedChildAsync(Capability parent, string childController, string signerDid, object[] chain)
    {
        var suiteContext = await _signing.ResolveSuiteContextUrlAsync(childController);
        var child = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", suiteContext },
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = parent.Id,
            Controller = childController,
            InvocationTarget = parent.InvocationTarget,
            AllowedAction = new[] { "read" },
            Expires = ZcapTimestamps.Format(DateTime.UtcNow.AddDays(5))
        };
        child.Proof = await _signing.SignCapabilityAsync(child, signerDid, "capabilityDelegation", chain);
        return child;
    }

    // ─────────────────────────── Generation shape ───────────────────────────

    [Fact]
    public async Task FirstLevel_Generates_RootIdOnly()
    {
        var root = await RootAsync(NewController());
        var d1 = await DelegateAsync(root, NewController(), new[] { "read" });

        var chain = d1.Proof!.Primary.CapabilityChain!;
        chain.Should().ContainSingle("a first-level chain is exactly [rootId]");
        chain[0].Should().BeOfType<string>().Which.Should().Be(root.Id);
        chain.OfType<Capability>().Should().BeEmpty("the root is referenced by id only, never embedded");
    }

    [Fact]
    public async Task SecondLevel_Generates_RootIdThenEmbeddedParent()
    {
        var root = await RootAsync(NewController());
        var d1 = await DelegateAsync(root, NewController(), new[] { "read", "write" });
        var d2 = await DelegateAsync(d1, NewController(), new[] { "read" });

        var chain = d2.Proof!.Primary.CapabilityChain!;
        chain.Should().HaveCount(2);
        chain[0].Should().BeOfType<string>().Which.Should().Be(root.Id);
        chain[^1].Should().BeOfType<Capability>().Which.Id.Should().Be(d1.Id);
        chain.Should().NotContain(d1.Id, "the immediate parent is embedded only, not also referenced by id");
        chain.OfType<Capability>().Select(c => c.Id).Should().NotContain(root.Id, "the root is never embedded");
    }

    [Fact]
    public async Task ThirdLevel_Generates_RootId_IntermediateId_EmbeddedParent()
    {
        var root = await RootAsync(NewController());
        var d1 = await DelegateAsync(root, NewController(), new[] { "read", "write" });
        var d2 = await DelegateAsync(d1, NewController(), new[] { "read", "write" });
        var d3 = await DelegateAsync(d2, NewController(), new[] { "read" });

        var chain = d3.Proof!.Primary.CapabilityChain!;
        chain.Should().HaveCount(3);
        chain[0].Should().BeOfType<string>().Which.Should().Be(root.Id);
        chain[1].Should().BeOfType<string>().Which.Should().Be(d1.Id);
        chain[^1].Should().BeOfType<Capability>().Which.Id.Should().Be(d2.Id);
        chain.OfType<Capability>().Select(c => c.Id).Should().NotContain(new[] { root.Id, d1.Id });
    }

    // ─────────────────────────── Verification accepts spec-exact ───────────────────────────

    [Fact]
    public async Task Verify_SpecExactChains_AllLevels_Succeed_ViaResolver()
    {
        var root = await RootAsync(NewController());
        var d1 = await DelegateAsync(root, NewController(), new[] { "read", "write" });
        var d2 = await DelegateAsync(d1, NewController(), new[] { "read", "write" });
        var d3 = await DelegateAsync(d2, NewController(), new[] { "read" });

        (await _verifier.VerifyCapabilityChainAsync(d1)).Should().BeTrue();
        (await _verifier.VerifyCapabilityChainAsync(d2)).Should().BeTrue();
        (await _verifier.VerifyCapabilityChainAsync(d3)).Should().BeTrue();
        (await _verifier.VerifyCapabilityProofAsync(d1)).Should().BeTrue();
        (await _verifier.VerifyCapabilityProofAsync(d3)).Should().BeTrue();
    }

    [Fact]
    public async Task Verify_FirstLevel_Succeeds_ViaExplicitRoot_WithoutResolver()
    {
        // Root is NOT registered, so the auto-wired resolver cannot find it; the explicit-root overload supplies it.
        var rootDid = NewController();
        var root = await _caps.CreateRootCapabilityAsync(rootDid, Target, new[] { "read" });
        var d1 = await DelegateAsync(root, NewController(), new[] { "read" });

        (await _verifier.VerifyCapabilityChainAsync(d1, root)).Should().BeTrue();
    }

    // ─────────────────────────── Verification fails closed / rejects non-spec ───────────────────────────

    [Fact]
    public async Task Verify_FirstLevel_FailsClosed_WhenRootUnavailable()
    {
        // Root is NOT registered and not supplied — the verifier cannot obtain it, so it MUST fail closed.
        var rootDid = NewController();
        var root = await _caps.CreateRootCapabilityAsync(rootDid, Target, new[] { "read" });
        var d1 = await DelegateAsync(root, NewController(), new[] { "read" });

        (await _verifier.VerifyCapabilityChainAsync(d1)).Should().BeFalse();
        (await _verifier.VerifyCapabilityProofAsync(d1)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_Rejects_EmbeddedRoot_AtFirstLevel()
    {
        var rootDid = NewController();
        var root = await RootAsync(rootDid);
        // First-level chain that wrongly EMBEDS the root: [rootId, {root}].
        var bad = await SignedChildAsync(root, NewController(), signerDid: rootDid, chain: new object[] { root.Id, root });

        (await _verifier.VerifyCapabilityChainAsync(bad)).Should().BeFalse();
        (await _verifier.VerifyCapabilityProofAsync(bad)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_Rejects_DuplicateRootId()
    {
        var rootDid = NewController();
        var d1Did = NewController();
        var root = await RootAsync(rootDid);
        var d1 = await DelegateAsync(root, d1Did, new[] { "read" });
        // Second-level chain with a DUPLICATE root id: [rootId, rootId, {d1}].
        var bad = await SignedChildAsync(d1, NewController(), signerDid: d1Did, chain: new object[] { root.Id, root.Id, d1 });

        (await _verifier.VerifyCapabilityChainAsync(bad)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_Rejects_ImmediateParent_ReferencedByIdAndEmbedded()
    {
        var rootDid = NewController();
        var d1Did = NewController();
        var root = await RootAsync(rootDid);
        var d1 = await DelegateAsync(root, d1Did, new[] { "read" });
        // Second-level chain where the parent appears BOTH by id and embedded: [rootId, d1.id, {d1}].
        var bad = await SignedChildAsync(d1, NewController(), signerDid: d1Did, chain: new object[] { root.Id, d1.Id, d1 });

        (await _verifier.VerifyCapabilityChainAsync(bad)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_Rejects_WrongEmbeddedParent()
    {
        var rootDid = NewController();
        var d1Did = NewController();
        var root = await RootAsync(rootDid);
        var d1 = await DelegateAsync(root, d1Did, new[] { "read" });
        // Second-level chain whose embedded final entry is the ROOT, not the immediate parent d1.
        var bad = await SignedChildAsync(d1, NewController(), signerDid: d1Did, chain: new object[] { root.Id, root });

        (await _verifier.VerifyCapabilityChainAsync(bad)).Should().BeFalse();
    }
}
