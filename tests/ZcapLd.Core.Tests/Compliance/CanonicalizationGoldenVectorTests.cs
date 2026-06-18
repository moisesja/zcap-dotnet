using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Canonicalization KNOWN-ANSWER vector. RDFC-1.0 is the only canonicalization ZCAP-LD supports;
/// this locks the <see cref="RdfcDocumentCanonicalizer"/> document N-Quads and the hash-concat
/// signing payload byte-for-byte against future changes (the canonicalizer is a thin adapter over
/// <c>DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer</c>). If the vector here changes, a
/// canonicalizer swap broke wire compatibility — investigate, do not "update the golden".
/// </summary>
public class CanonicalizationGoldenVectorTests
{
    [Fact(DisplayName = "Golden: RDFC-1.0 document N-Quads + hash-concat signing payload")]
    public void Rdfc_CapabilityNQuadsAndPayload_MatchGolden()
    {
        var capability = new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "urn:uuid:00000000-0000-0000-0000-0000000000de",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            Controller = "did:key:z6MkfixedController",
            InvocationTarget = "https://example.com/api/resource",
            AllowedAction = new[] { "read" },
            Expires = "2027-01-01T00:00:00.000000Z",
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            CapabilityChain = new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource" },
            ProofValue = string.Empty,
        };

        // The document's canonical N-Quads — exactly what Stage B's canonicalizer must reproduce.
        const string ExpectedNQuads =
            "<urn:uuid:00000000-0000-0000-0000-0000000000de> <https://w3id.org/security#allowedAction> \"read\" .\n" +
            "<urn:uuid:00000000-0000-0000-0000-0000000000de> <https://w3id.org/security#controller> <did:key:z6MkfixedController> .\n" +
            "<urn:uuid:00000000-0000-0000-0000-0000000000de> <https://w3id.org/security#expiration> \"2027-01-01T00:00:00.000000Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n" +
            "<urn:uuid:00000000-0000-0000-0000-0000000000de> <https://w3id.org/security#invocationTarget> <https://example.com/api/resource> .\n" +
            "<urn:uuid:00000000-0000-0000-0000-0000000000de> <https://w3id.org/security#parentCapability> <urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource> .\n";

        var nquads = Encoding.UTF8.GetString(new RdfcDocumentCanonicalizer().Canonicalize(capability));
        nquads.Should().Be(ExpectedNQuads,
            "the RDFC-1.0 document canonicalization must stay byte-stable across the Stage B swap to " +
            "DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer");

        // The full RDFC signing payload = SHA-256(proofOptions N-Quads) || SHA-256(document N-Quads),
        // locked via its SHA-256 (the 64-byte payload is what gets signed).
        var payload = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            capability, proof, new RdfcDocumentCanonicalizer());
        Convert.ToHexString(SHA256.HashData(payload)).Should().Be(
            "1A9A00A5066EE02B0E3B3AAB2BA3E9E6B125FE876CC5C4EFA4C3100CCD039586",
            "the RDFC hash-concat signing payload (canonicalize doc + proofOptions, SHA-256 each, " +
            "concatenate) must be byte-identical after the Stage B canonicalizer swap");
    }
}
