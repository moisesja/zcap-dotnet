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
            // The context CapabilityService emits. With zcap/v1 alone the suite's proof terms were
            // never signed, and DataProofs 1.5.0 refuses to canonicalize it. This input, not the wire,
            // changed the payload below: DataProofs 1.4.0 produces the same bytes for it.
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
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
            "34C3D9D91712FBFF12D3B3408B86C4782A6800E62D58681CAD3E836AEFDC0522",
            "the RDFC hash-concat signing payload (canonicalize doc + proofOptions, SHA-256 each, " +
            "concatenate) must be byte-identical after the Stage B canonicalizer swap");
    }

    [Fact(DisplayName = "Golden: RDFC-1.0 invocation hash-concat signing payload")]
    public void Rdfc_InvocationPayload_MatchesGolden()
    {
        // Locks the RDFC-1.0 signing payload for an INVOCATION (the per-stack byte-stability guard the
        // deleted JCS invocation pin used to provide). Cross-stack invocation interop is separate and
        // deferred (#117); this only pins zcap-dotnet's own invocation signing bytes against drift.
        // #157 deliberately changed this vector: envelopes are now canonicalized under zcap/v1 plus
        // the suite context, so created/proofPurpose/verificationMethod are signed (they were dropped).
        var invocation = new Invocation
        {
            Id = "urn:uuid:00000000-0000-0000-0000-0000000000a1",
            Capability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/api/resource",
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            Capability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/api/resource",
            ProofValue = string.Empty,
        };

        var payload = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            invocation, proof, new RdfcDocumentCanonicalizer());
        Convert.ToHexString(SHA256.HashData(payload)).Should().Be(
            "A89BAA5F2BFBBF3FC74A08DB5870D9FDDF453611087D87336146ACC811933983",
            "the RDFC-1.0 invocation signing payload must stay byte-stable");

        proof.Created = "2026-06-13T00:00:01.000000Z";
        ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(invocation, proof, new RdfcDocumentCanonicalizer())
            .Should().NotEqual(payload, "proof.created must be part of the signed invocation payload");
    }

    [Fact(DisplayName = "Golden: signed revocation binds its purpose, reason and metadata")]
    public void Rdfc_RevocationPayload_MatchesGolden()
    {
        // zcap-dotnet's revocation context defines the capabilityRevocation purpose and the reason and
        // metadata extensions, which no published context does. Before it, RDFC dropped all three, and
        // DataProofs 1.5.0 refuses to canonicalize them at all.
        var revocation = new Invocation
        {
            Id = "urn:uuid:00000000-0000-0000-0000-0000000000a2",
            Capability = "urn:uuid:00000000-0000-0000-0000-0000000000de",
            CapabilityAction = Invocation.RevokeAction,
            InvocationTarget = "https://example.com/api/resource",
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-06-13T00:00:00.000000Z",
            ProofPurpose = Proof.CapabilityRevocationPurpose,
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            Capability = revocation.Capability,
            CapabilityAction = revocation.CapabilityAction,
            InvocationTarget = revocation.InvocationTarget,
            ProofValue = string.Empty,
            AdditionalProperties = new()
            {
                [Proof.RevocationReasonField] = JsonSerializer.SerializeToElement("key compromised"),
                [Proof.RevocationMetadataField] = JsonSerializer.SerializeToElement(
                    new Dictionary<string, string> { ["ticket"] = "SEC-1" }),
            },
        };

        var options = JsonSerializer.SerializeToNode(proof, ZcapJsonOptions.Default)!.AsObject();
        options.Remove("proofValue");
        options["@context"] = JsonSerializer.SerializeToNode(LegacyProofCrypto.EnvelopeContext(proof));
        var nquads = Encoding.UTF8.GetString(new RdfcDocumentCanonicalizer().Canonicalize(options.ToJsonString()));
        nquads.Should()
            .Contain("<https://w3id.org/security#proofPurpose> <urn:zcap-dotnet:revocation:v1#capabilityRevocation> .")
            .And.Contain("<urn:zcap-dotnet:revocation:v1#revocationReason> \"key compromised\" .")
            .And.Contain("<urn:zcap-dotnet:revocation:v1#revocationMetadata> " +
                "\"{\\\"ticket\\\":\\\"SEC-1\\\"}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .");

        var payload = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            revocation, proof, new RdfcDocumentCanonicalizer());
        Convert.ToHexString(SHA256.HashData(payload)).Should().Be(
            "71BB1368AA95EB694E29ADAE5EE321ED1CB13ADB777873C87E8034DB6E91D540",
            "the RDFC-1.0 revocation signing payload must stay byte-stable");
    }
}
