using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

/// <summary>The revocation scope (#158): construction rules, keys, equality and the text/JSON form.</summary>
public class RevocationScopeTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("did:key:z6MkA#z6MkA")]
    [InlineData("not an iri")]
    [InlineData("relative/path")]
    public void Delegated_RejectsAnythingButABareAbsoluteIri(string? delegator)
    {
        var act = () => RevocationScope.Delegated(delegator!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ForDelegationProof_UsesTheVerificationMethodsControllerIdentifier()
    {
        var proof = new Proof { VerificationMethod = "did:key:z6MkDelegator#z6MkDelegator" };

        var scope = RevocationScope.ForDelegationProof(proof);

        scope.Kind.Should().Be(RevocationScopeKind.Delegated);
        scope.Delegator.Should().Be("did:key:z6MkDelegator");
        scope.Should().Be(RevocationScope.Delegated("did:key:z6MkDelegator"));
    }

    [Fact]
    public void ForDelegationProof_WithoutAVerificationMethod_Throws()
    {
        var act = () => RevocationScope.ForDelegationProof(new Proof());
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Equality_IsByKindAndDelegator()
    {
        RevocationScope.Delegated("did:key:z6MkA").Should().Be(RevocationScope.Delegated("did:key:z6MkA"));
        RevocationScope.Delegated("did:key:z6MkA").Should().NotBe(RevocationScope.Delegated("did:key:z6MkB"));
        RevocationScope.Delegated("did:key:z6MkA").Should().NotBe(RevocationScope.Delegated("did:key:z6MKA"),
            "identifiers are compared exactly, as everywhere else in the verifier");
        RevocationScope.Root.Should().NotBe(RevocationScope.Unscoped);
        RevocationScope.Delegated("did:key:z6MkA").Should().NotBe(RevocationScope.Root);
    }

    [Fact]
    public void KeyFor_IsAnOpaqueDigestDistinctPerIdAndScope()
    {
        const string id = "urn:uuid:7a3b8d6e-1111-4f6a-9c1e-0a2b3c4d5e6f";
        var alice = RevocationScope.Delegated("did:key:z6MkAlice");
        var mallory = RevocationScope.Delegated("did:key:z6MkMallory");

        var keys = new[]
        {
            alice.KeyFor(id), mallory.KeyFor(id), RevocationScope.Root.KeyFor(id), RevocationScope.Unscoped.KeyFor(id),
            alice.KeyFor("urn:uuid:other"),
        };

        keys.Should().OnlyHaveUniqueItems();
        keys.Should().AllSatisfy(key => key.Should().MatchRegex("^[0-9a-f]{64}$"));
        alice.KeyFor(id).Should().Be(RevocationScope.Delegated("did:key:z6MkAlice").KeyFor(id), "the key is deterministic");
        alice.KeyFor(id).Should().NotContain(id, "no bare id is ever a key");
        // A case-insensitive store would merge URN:UUID:… with urn:uuid:…; distinct digests keep them apart.
        RevocationScope.Unscoped.KeyFor(id).Should().NotBe(RevocationScope.Unscoped.KeyFor(id.ToUpperInvariant()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void KeyFor_RequiresACapabilityId(string? id)
    {
        var act = () => RevocationScope.Root.KeyFor(id!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void TextForm_RoundTrips()
    {
        RevocationScope.Unscoped.ToString().Should().Be("unscoped");
        RevocationScope.Root.ToString().Should().Be("root");
        RevocationScope.Delegated("did:key:z6MkA").ToString().Should().Be("delegated:did:key:z6MkA");

        foreach (var scope in new[] { RevocationScope.Unscoped, RevocationScope.Root, RevocationScope.Delegated("https://issuer.example/controllers/7") })
        {
            RevocationScope.Parse(scope.ToString()).Should().Be(scope);
        }
    }

    [Theory]
    [InlineData("delegated:")]
    [InlineData("delegated:did:key:z6MkA#z6MkA")]
    [InlineData("delegated:not an iri")]
    [InlineData("DELEGATED:did:key:z6MkA")]
    [InlineData("Root")]
    [InlineData("")]
    [InlineData(null)]
    public void Parse_RejectsOtherText(string? text)
    {
        RevocationScope.TryParse(text, out _).Should().BeFalse();
        var act = () => RevocationScope.Parse(text!);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Json_IsTheTextForm()
    {
        var record = new RevocationRecord
        {
            CapabilityId = "urn:uuid:json", Scope = RevocationScope.Delegated("did:key:z6MkA"), RevokedBy = "did:key:z6MkA"
        };

        var json = JsonSerializer.Serialize(record);

        json.Should().Contain("\"Scope\":\"delegated:did:key:z6MkA\"");
        json.Should().NotContain("\"Key\"", "the key is derived, never persisted as a field");
        var parsed = JsonSerializer.Deserialize<RevocationRecord>(json)!;
        parsed.Scope.Should().Be(record.Scope);
        parsed.Key.Should().Be(record.Key);

        var act = () => JsonSerializer.Deserialize<RevocationScope>("\"delegated:\"");
        act.Should().Throw<JsonException>();
        var notAString = () => JsonSerializer.Deserialize<RevocationScope>("{\"kind\":\"root\"}");
        notAString.Should().Throw<JsonException>();
    }
}
