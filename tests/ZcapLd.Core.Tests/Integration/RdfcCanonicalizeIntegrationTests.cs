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
    public void RdfcCanonicalizer_ProducesDifferentOutputThanJcs()
    {
        // A ZCAP-LD capability has @context, making it valid JSON-LD
        var capability = new Capability
        {
            Context = new object[] { "https://w3id.org/zcap/v1" },
            Id = "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
            Controller = "did:key:example",
            InvocationTarget = "https://example.com/foo"
        };

        var jcs = new JcsDocumentCanonicalizer();
        var rdfc = new RdfcDocumentCanonicalizer();

        var jcsBytes = jcs.Canonicalize(capability);
        var rdfcBytes = rdfc.Canonicalize(capability);

        // Different canonical representations
        jcsBytes.Should().NotEqual(rdfcBytes);
        jcsBytes.Length.Should().BeGreaterThan(0);
        rdfcBytes.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public void ProofSigningPayloadBuilder_WithJcsCanonicalizer_ProducesExpectedOutput()
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
            Created = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:example#key-1",
            CapabilityChain = new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo" }
        };

        var jcs = new JcsDocumentCanonicalizer();

        // Default (no canonicalizer) should match explicit JCS
        var defaultBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var jcsBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof, jcs);

        defaultBytes.Should().Equal(jcsBytes);
    }

    [Fact]
    public void ProofSigningPayloadBuilder_RdfcProducesDifferentPayloadThanJcs()
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
            Created = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:example#key-1",
            CapabilityChain = new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo" }
        };

        var jcs = new JcsDocumentCanonicalizer();
        var rdfc = new RdfcDocumentCanonicalizer();

        var jcsBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof, jcs);
        var rdfcBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof, rdfc);

        // RDFC-1.0 produces SHA-256(proofOptions) || SHA-256(document) = 64 bytes
        rdfcBytes.Length.Should().Be(64);
        jcsBytes.Should().NotEqual(rdfcBytes);
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

    [Fact]
    public void ICryptoSuite_DefaultCanonicalizationMethod_IsJcs()
    {
        ICryptoSuite ed25519 = CryptoSuite.Ed25519();
        ICryptoSuite p256 = CryptoSuite.P256();

        ed25519.CanonicalizationMethod.Should().Be("JCS");
        p256.CanonicalizationMethod.Should().Be("JCS");
    }
}
