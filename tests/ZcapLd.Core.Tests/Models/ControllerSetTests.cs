using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>
/// Unit tests for <see cref="ControllerSet"/> and its JSON converter (Issue #47).
/// Covers both spec-allowed wire shapes (string / array of strings), shape preservation
/// across round-trips, malformed-value rejection, and verification-method matching.
/// </summary>
public class ControllerSetTests
{
    private static readonly JsonSerializerOptions Options = ZcapJsonOptions.Default;

    // ─── Deserialization ───────────────────────────────────────────────

    [Fact]
    public void Deserialize_ControllerAsString_ProducesScalarSet()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": "did:key:z6MkAlice", "invocationTarget": "https://example.com/r" }
        """;

        var capability = JsonSerializer.Deserialize<Capability>(json, Options)!;

        capability.Controller.IsArrayForm.Should().BeFalse();
        capability.Controller.Count.Should().Be(1);
        capability.Controller.Primary.Should().Be("did:key:z6MkAlice");
        capability.Controller.Values.Should().ContainSingle().Which.Should().Be("did:key:z6MkAlice");
    }

    [Fact]
    public void Deserialize_ControllerAsArray_ProducesArraySet()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": ["did:key:z6MkAlice", "did:key:z6MkBob"], "invocationTarget": "https://example.com/r" }
        """;

        var capability = JsonSerializer.Deserialize<Capability>(json, Options)!;

        capability.Controller.IsArrayForm.Should().BeTrue();
        capability.Controller.Count.Should().Be(2);
        capability.Controller.Values.Should().Equal("did:key:z6MkAlice", "did:key:z6MkBob");
    }

    // ─── Serialization (shape preservation) ────────────────────────────

    [Fact]
    public void Serialize_SingleController_EmitsBareString()
    {
        var capability = new Capability
        {
            Id = "urn:zcap:root:x",
            Controller = "did:key:z6MkAlice",
            InvocationTarget = "https://example.com/r"
        };

        var json = JsonSerializer.Serialize(capability, Options);

        json.Should().Contain("\"controller\":\"did:key:z6MkAlice\"");
        json.Should().NotContain("\"controller\":[");
    }

    [Fact]
    public void Serialize_MultiController_EmitsArray()
    {
        var capability = new Capability
        {
            Id = "urn:zcap:root:x",
            Controller = new[] { "did:key:z6MkAlice", "did:key:z6MkBob" },
            InvocationTarget = "https://example.com/r"
        };

        var json = JsonSerializer.Serialize(capability, Options);

        json.Should().Contain("\"controller\":[\"did:key:z6MkAlice\",\"did:key:z6MkBob\"]");
    }

    [Fact]
    public void RoundTrip_SingleElementArray_StaysArrayForm()
    {
        // A one-element array must NOT collapse to a bare string — the JCS canonical
        // bytes differ between the two shapes, and cross-language verifiers re-hash
        // whatever shape the signer wrote (#47).
        const string json = """
        { "id": "urn:zcap:root:x", "controller": ["did:key:z6MkAlice"], "invocationTarget": "https://example.com/r" }
        """;

        var capability = JsonSerializer.Deserialize<Capability>(json, Options)!;
        capability.Controller.IsArrayForm.Should().BeTrue();

        var reserialized = JsonSerializer.Serialize(capability, Options);
        reserialized.Should().Contain("\"controller\":[\"did:key:z6MkAlice\"]");
    }

    // ─── Malformed-value rejection ─────────────────────────────────────

    [Fact]
    public void Deserialize_EmptyControllerArray_Throws()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": [], "invocationTarget": "https://example.com/r" }
        """;

        var act = () => JsonSerializer.Deserialize<Capability>(json, Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_ControllerArrayWithNonString_Throws()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": ["did:key:z6MkAlice", 42], "invocationTarget": "https://example.com/r" }
        """;

        var act = () => JsonSerializer.Deserialize<Capability>(json, Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_ControllerArrayWithEmptyString_Throws()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": ["did:key:z6MkAlice", ""], "invocationTarget": "https://example.com/r" }
        """;

        var act = () => JsonSerializer.Deserialize<Capability>(json, Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_EmptyControllerString_Throws()
    {
        const string json = """
        { "id": "urn:zcap:root:x", "controller": "", "invocationTarget": "https://example.com/r" }
        """;

        var act = () => JsonSerializer.Deserialize<Capability>(json, Options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void FromValues_EmptyArray_Throws()
    {
        var act = () => ControllerSet.FromValues(Array.Empty<string>());
        act.Should().Throw<ArgumentException>();
    }

    // ─── Verification-method matching ──────────────────────────────────

    [Fact]
    public void ContainsVerificationMethod_MatchesByBareDid()
    {
        var set = ControllerSet.FromValues(new[] { "did:key:z6MkAlice", "did:key:z6MkBob" });

        set.ContainsVerificationMethod("did:key:z6MkBob#z6MkBob").Should().BeTrue();
        set.ContainsVerificationMethod("did:key:z6MkAlice").Should().BeTrue();
        set.ContainsVerificationMethod("did:key:z6MkMallory#z6MkMallory").Should().BeFalse();
        set.ContainsVerificationMethod("").Should().BeFalse();
    }

    [Fact]
    public void ContainsVerificationMethod_MatchesFullVerificationMethodUri()
    {
        var set = ControllerSet.FromSingle("did:example:alice#key-1");

        set.ContainsVerificationMethod("did:example:alice#key-1").Should().BeTrue();
    }

    [Fact]
    public void ContainsVerificationMethod_MatchesKeyFragmentAgainstBareControllerDid()
    {
        // A revoker/invoker authenticates with a specific key fragment (did#key-1) while the
        // capability's controller is the bare DID. The bare-DID split authorizes correctly —
        // the relevant case for a did:web controller that lists keyed verification methods.
        // (PR #81 review: IsRevokerAuthorizedAsync key-fragment edge case.)
        var set = ControllerSet.FromSingle("did:web:issuer.example");

        set.ContainsVerificationMethod("did:web:issuer.example#key-1").Should().BeTrue();
    }

    [Fact]
    public void ContainsVerificationMethod_DoesNotResolveCrossDidController()
    {
        // Documents a known limitation: authorization is a string-level controller match, NOT a
        // DID-document resolution. A key belonging to a DIFFERENT DID — even one the controller's
        // DID document would authorize — is not matched. Cross-DID key authorization is future
        // work (see the TODO in VerificationService.IsRevokerAuthorizedAsync). (PR #81 review.)
        var set = ControllerSet.FromSingle("did:web:issuer.example");

        set.ContainsVerificationMethod("did:key:z6MkSomeOtherKey#z6MkSomeOtherKey")
            .Should().BeFalse();
    }

    // ─── Implicit conversions + equality ───────────────────────────────

    [Fact]
    public void ImplicitConversion_FromString_IsScalarForm()
    {
        ControllerSet set = "did:key:z6MkAlice";

        set.IsArrayForm.Should().BeFalse();
        set.Primary.Should().Be("did:key:z6MkAlice");
    }

    [Fact]
    public void ImplicitConversion_FromArray_IsArrayForm()
    {
        ControllerSet set = new[] { "did:key:z6MkAlice", "did:key:z6MkBob" };

        set.IsArrayForm.Should().BeTrue();
        set.Values.Should().Equal("did:key:z6MkAlice", "did:key:z6MkBob");
    }

    [Fact]
    public void Equality_SameValuesAndForm_AreEqual()
    {
        var a = ControllerSet.FromValues(new[] { "did:key:z6MkAlice", "did:key:z6MkBob" });
        var b = ControllerSet.FromValues(new[] { "did:key:z6MkAlice", "did:key:z6MkBob" });

        a.Should().Be(b);
        a.GetHashCode().Should().Be(b.GetHashCode());
    }

    [Fact]
    public void Equality_ScalarVsSingleElementArray_AreNotEqual()
    {
        // Same single value, different wire form → different canonical bytes → not equal.
        var scalar = ControllerSet.FromSingle("did:key:z6MkAlice");
        var array = ControllerSet.FromValues(new[] { "did:key:z6MkAlice" });

        scalar.Should().NotBe(array);
    }
}
