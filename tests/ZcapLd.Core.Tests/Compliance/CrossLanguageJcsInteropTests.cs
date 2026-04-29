using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Known-answer interop tests that pin the JCS canonicalization shape of capabilities
/// and invocations to the W3C Verifiable Credentials Data Integrity convention —
/// the same shape every other Data Integrity library (zcap-py, JS, Rust) produces.
///
/// If the canonical bytes here ever drift, cross-language verification breaks silently:
/// signatures produced by zcap-dotnet stop verifying in zcap-py and vice versa. This
/// fixture is the only test in the suite that catches that drift, because every
/// in-process round-trip would still pass even with the wrong shape (the same wrong
/// shape is on both sides). See https://github.com/moisesja/zcap-dotnet/issues/34.
/// </summary>
public class CrossLanguageJcsInteropTests
{
    [Fact(DisplayName = "JCS capability payload uses W3C flat shape (document fields + proof minus proofValue)")]
    public void CapabilityJcsPayload_UsesFlatW3cDataIntegrityShape()
    {
        var capability = new Capability
        {
            Id = "urn:uuid:fixed-delegated",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkfixedController",
            InvocationTarget = "https://example.com/api/resource",
            AllowedAction = new[] { "read" },
            Expires = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ParentCapability = "urn:zcap:root:fixed",
            Caveat = Array.Empty<Caveat>(),
            Proof = null
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc),
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            CapabilityChain = new object[] { "urn:zcap:root:fixed" },
            ProofValue = "this-must-be-excluded"
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        // Flat W3C Data Integrity shape: capability's own top-level fields plus a
        // "proof" field carrying the on-document proof minus proofValue.
        // Keys alphabetically sorted (JCS / RFC 8785). Six-digit microsecond DateTimes.
        const string Expected =
            "{" +
                "\"@context\":\"https://w3id.org/zcap/v1\"," +
                "\"allowedAction\":[\"read\"]," +
                "\"caveat\":[]," +
                "\"controller\":\"did:key:z6MkfixedController\"," +
                "\"expires\":\"2027-01-01T00:00:00.000000Z\"," +
                "\"id\":\"urn:uuid:fixed-delegated\"," +
                "\"invocationTarget\":\"https://example.com/api/resource\"," +
                "\"parentCapability\":\"urn:zcap:root:fixed\"," +
                "\"proof\":{" +
                    "\"capabilityChain\":[\"urn:zcap:root:fixed\"]," +
                    "\"created\":\"2026-04-29T12:00:00.000000Z\"," +
                    "\"proofPurpose\":\"capabilityDelegation\"," +
                    "\"type\":\"Ed25519Signature2020\"," +
                    "\"verificationMethod\":\"did:key:z6MkfixedSigner#z6MkfixedSigner\"" +
                "}" +
            "}";

        canonical.Should().Be(Expected);
        canonical.Should().NotContain("\"capability\":{", "wrapper-shape `{capability:..., proof:...}` breaks W3C Data Integrity interop");
        canonical.Should().NotContain("\"proofValue\"", "proofValue must never appear in the signing payload");
    }

    [Fact(DisplayName = "JCS invocation payload uses W3C flat shape")]
    public void InvocationJcsPayload_UsesFlatW3cDataIntegrityShape()
    {
        var invocation = new Invocation
        {
            Id = "urn:uuid:fixed-invocation",
            Capability = "urn:uuid:fixed-delegated",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/api/resource",
            Proof = null
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc),
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = "did:key:z6MkfixedInvoker#z6MkfixedInvoker",
            CapabilityChain = Array.Empty<object>(),
            ProofValue = "this-must-be-excluded",
            Capability = "urn:uuid:fixed-delegated",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/api/resource"
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(invocation, proof);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        const string Expected =
            "{" +
                "\"capability\":\"urn:uuid:fixed-delegated\"," +
                "\"capabilityAction\":\"read\"," +
                "\"id\":\"urn:uuid:fixed-invocation\"," +
                "\"invocationTarget\":\"https://example.com/api/resource\"," +
                "\"proof\":{" +
                    "\"capability\":\"urn:uuid:fixed-delegated\"," +
                    "\"capabilityAction\":\"read\"," +
                    "\"capabilityChain\":[]," +
                    "\"created\":\"2026-04-29T12:00:00.000000Z\"," +
                    "\"invocationTarget\":\"https://example.com/api/resource\"," +
                    "\"proofPurpose\":\"capabilityInvocation\"," +
                    "\"type\":\"Ed25519Signature2020\"," +
                    "\"verificationMethod\":\"did:key:z6MkfixedInvoker#z6MkfixedInvoker\"" +
                "}" +
            "}";

        canonical.Should().Be(Expected);
        canonical.Should().NotContain("\"invocation\":{", "wrapper-shape `{invocation:..., proof:...}` breaks W3C Data Integrity interop");
        canonical.Should().NotContain("\"proofValue\"");
    }

    [Fact(DisplayName = "Proof.Created on-wire JSON uses 6-digit microsecond ISO-8601 UTC")]
    public void Proof_OnWireDateTime_UsesSixDigitMicrosecondUtc()
    {
        // Pick a DateTime with sub-microsecond precision (.NET tick = 100ns).
        // The converter must truncate to 6 digits for cross-stack JCS interop.
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = new DateTime(638829918538521234L, DateTimeKind.Utc),
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:zX",
            CapabilityChain = Array.Empty<object>(),
            ProofValue = "z..."
        };

        var json = JsonSerializer.Serialize(proof);

        // 7-digit (.NET default) would be ".8538521" — that breaks Python interop.
        // We want exactly 6 digits + "Z".
        json.Should().Contain("\"created\":\"");
        json.Should().MatchRegex("\"created\":\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z\"");
        json.Should().NotMatchRegex("\"created\":\"[^\"]*\\.\\d{7}Z\"",
            "7-digit fractional seconds break JCS interop with zcap-py");
    }

    [Fact(DisplayName = "Capability.Expires on-wire JSON uses 6-digit microsecond ISO-8601 UTC")]
    public void Capability_OnWireExpires_UsesSixDigitMicrosecondUtc()
    {
        var capability = new Capability
        {
            Id = "urn:uuid:test",
            Controller = "did:key:zX",
            InvocationTarget = "https://example.com/x",
            Expires = new DateTime(638829918538521234L, DateTimeKind.Utc)
        };

        var json = JsonSerializer.Serialize(capability);

        json.Should().MatchRegex("\"expires\":\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z\"");
        json.Should().NotMatchRegex("\"expires\":\"[^\"]*\\.\\d{7}Z\"");
    }

    [Fact(DisplayName = "DateTime kind=Local is normalized to UTC before serialization")]
    public void DateTime_LocalKind_IsConvertedToUtc()
    {
        var local = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Local);
        var expectedUtc = local.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ss.ffffffZ", System.Globalization.CultureInfo.InvariantCulture);

        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = local,
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:zX",
            CapabilityChain = Array.Empty<object>(),
            ProofValue = "z..."
        };

        var json = JsonSerializer.Serialize(proof);

        json.Should().Contain($"\"created\":\"{expectedUtc}\"",
            "Local-kind DateTimes must be normalized to UTC with explicit Z suffix before serialization");
        json.Should().NotMatchRegex("\"created\":\"[^\"Z]*[+-]\\d{2}:\\d{2}\"",
            "DateTime offsets like +05:00 break JCS interop — Z (UTC) is required");
    }
}
