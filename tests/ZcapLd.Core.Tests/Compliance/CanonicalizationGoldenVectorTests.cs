using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Canonicalization KNOWN-ANSWER vectors (Phase 0 of issue #108). Stage B is complete (this PR):
/// these now lock the two delegating implementations' behavior byte-for-byte against future
/// changes, or previously-issued capabilities stop verifying:
/// <list type="number">
/// <item><description>The RDFC-1.0 document N-Quads and the hash-concat signing payload —
/// <see cref="RdfcDocumentCanonicalizer"/> is now a thin adapter over
/// <c>DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer</c> (also over dotNetRdf 3.5.1).</description></item>
/// <item><description>The JCS present-but-null member SKIP — <see cref="JsonCanonicalizer"/> now
/// delegates RFC 8785 canonicalization to <c>NetCid.JcsCanonicalizer</c> after a null-member
/// strip. RFC 8785 has no skip-null rule, so NetCid emits <c>null</c> literally; this vector pins
/// the strip-then-canonicalize behavior so that divergence is caught before it changes signed
/// bytes for any wire field carrying an explicit null.</description></item>
/// </list>
/// If a vector here changes, a canonicalizer swap broke wire compatibility — investigate, do
/// not "update the golden".
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

    [Fact(DisplayName = "Golden: JCS skips present-but-null members (diverges from NetCid JCS)")]
    public void Jcs_PresentButNullMember_IsSkipped()
    {
        // A wire body carrying an explicit null unmodeled member alongside a non-null one.
        const string OnWire = """
        {
          "@context": "https://w3id.org/zcap/v1",
          "id": "urn:uuid:null-member",
          "controller": "did:key:zC",
          "invocationTarget": "https://example.com/r",
          "extraPresent": "kept",
          "extraNull": null
        }
        """;
        var capability = JsonSerializer.Deserialize<Capability>(OnWire)!;
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:zX#zX",
            CapabilityChain = new object[] { "urn:zcap:root:test" },
            ProofValue = string.Empty,
        };

        var canonical = Encoding.UTF8.GetString(
            ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof));

        const string Expected =
            "{" +
                "\"@context\":\"https://w3id.org/zcap/v1\"," +
                "\"controller\":\"did:key:zC\"," +
                "\"extraPresent\":\"kept\"," +
                "\"id\":\"urn:uuid:null-member\"," +
                "\"invocationTarget\":\"https://example.com/r\"," +
                "\"proof\":{" +
                    "\"capabilityChain\":[\"urn:zcap:root:test\"]," +
                    "\"created\":\"2026-06-13T00:00:00.000000Z\"," +
                    "\"proofPurpose\":\"capabilityDelegation\"," +
                    "\"type\":\"Ed25519Signature2020\"," +
                    "\"verificationMethod\":\"did:key:zX#zX\"" +
                "}" +
            "}";

        canonical.Should().Be(Expected);
        canonical.Should().Contain("\"extraPresent\":\"kept\"");
        canonical.Should().NotContain("extraNull",
            "zcap's JcsCanonicalizer skips present-but-null members; NetCid.JcsCanonicalizer emits " +
            "them as `null` (RFC 8785 has no skip-null rule). Stage B must preserve this skip or the " +
            "signed bytes change for any wire field carrying an explicit null.");
    }
}
