using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Integration;

/// <summary>
/// Integration tests verifying that RDFC-1.0 canonicalization works end-to-end
/// through the signing and verification pipeline.
/// </summary>
public class RdfcCanonicalizeIntegrationTests
{
    private readonly InMemoryDidProvider _didProvider;

    public RdfcCanonicalizeIntegrationTests()
    {
        _didProvider = new InMemoryDidProvider();
    }

    [Fact]
    public void ProofSigningPayloadBuilder_RdfcProducesHashConcatPayload()
    {
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
            Id = "urn:uuid:test-cap",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            Controller = "did:key:example",
            InvocationTarget = "https://example.com/foo"
        };

        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2024-01-01T00:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:example#key-1",
            CapabilityChain = new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo" }
        };

        var rdfc = new RdfcDocumentCanonicalizer();

        // RDFC-1.0 signing payload = SHA-256(proofOptions) || SHA-256(document) = 64 bytes.
        var rdfcBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof, rdfc);
        var defaultBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);

        rdfcBytes.Length.Should().Be(64);
        defaultBytes.Should().Equal(rdfcBytes); // the default canonicalizer is RDFC-1.0
    }

    [Fact]
    public void RdfcCanonicalizer_IsDeterministic_AcrossMultipleCalls()
    {
        var rdfc = new RdfcDocumentCanonicalizer();

        var doc = new Dictionary<string, object>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["id"] = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            ["controller"] = "did:key:z6MkExample123",
            ["invocationTarget"] = "https://example.com/foo"
        };

        var results = Enumerable.Range(0, 5)
            .Select(_ => rdfc.Canonicalize(doc))
            .ToList();

        for (int i = 1; i < results.Count; i++)
        {
            results[i].Should().Equal(results[0]);
        }
    }

    private const string Contexts =
        "[\"https://w3id.org/zcap/v1\",\"https://w3id.org/security/suites/ed25519-2020/v1\"]";

    [Theory(DisplayName = "The production canonicalizer refuses what a lenient one silently signs")]
    [InlineData("\"invocationTarget\":\"https://example.com/foo\",\"maxUses\":1", "does not define")]
    [InlineData("\"invocationTarget\":\"https://example.com/foo?filter[id]=1\"", "well-formed")]
    [InlineData("\"invocationTarget\":\"https://example.com/a/%2E%2E/foo\"", "spell differently")]
    [InlineData("\"invocationTarget\":\"HTTPS://example.com/foo\"", "spell differently")]
    public void LossyInput_RefusedByProductionButSignedByLenient(string member, string cause)
    {
        // DataProofs 1.5.0 is a second layer behind zcap's own checks. Tests that forge such documents
        // sign them with LenientRdfcCanonicalizer, so they keep proving zcap rejects them first.
        var json = $"{{\"@context\":{Contexts},\"id\":\"urn:uuid:lossy\",\"allowedAction\":\"read\",{member}}}";

        var strict = () => new RdfcDocumentCanonicalizer().Canonicalize(json);

        strict.Should().Throw<DataProofsDotnet.Rdfc.JsonLdDataLossException>().WithMessage($"*{cause}*");
        LenientRdfcCanonicalizer.Instance.Canonicalize(json).Should().NotBeEmpty();
    }

    [Fact(DisplayName = "The lenient test canonicalizer matches production on input both accept")]
    public void LenientCanonicalizer_MatchesProduction_OnAcceptedInput()
    {
        var json = $"{{\"@context\":{Contexts},\"id\":\"urn:uuid:ok\",\"invocationTarget\":\"https://example.com/foo\"," +
                   "\"allowedAction\":[\"read\"],\"expires\":\"2027-01-01T00:00:00Z\"}";

        LenientRdfcCanonicalizer.Instance.Canonicalize(json).Should().Equal(new RdfcDocumentCanonicalizer().Canonicalize(json));
    }
}
