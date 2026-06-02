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
/// shape is on both sides). See https://github.com/moisesja/zcap-dotnet/issues/34
/// and https://github.com/moisesja/zcap-dotnet/issues/36.
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
            Expires = "2027-01-01T00:00:00.000000Z",
            ParentCapability = "urn:zcap:root:fixed",
            Caveat = Array.Empty<Caveat>(),
            Proof = null
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            CapabilityChain = new object[] { "urn:zcap:root:fixed" },
            ProofValue = "this-must-be-excluded"
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        // Flat W3C Data Integrity shape: capability's own top-level fields plus a
        // "proof" field carrying the on-document proof minus proofValue.
        // Keys alphabetically sorted (JCS / RFC 8785). Timestamps preserved verbatim.
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

    [Fact(DisplayName = "Issue #39 — sign-time and wire-time bytes match for capability with derived caveats")]
    public void CapabilityWithDerivedCaveat_SignTimeAndWireBytes_AreByteEqual()
    {
        // The cross-stack failure mode: zcap-dotnet signs JCS over a payload where
        // Caveat[] elements drop their derived fields (sign-time sees `{"type":"Expiration"}`).
        // The orchestrator emits the wire body via the runtime concrete type, so zcap-py sees
        // `{"type":"Expiration","expires":"..."}` and re-canonicalizes — different bytes,
        // signature verification fails. After the converter ships, both paths produce the
        // same bytes for any registered caveat type.
        var capability = new Capability
        {
            Id = "urn:uuid:fixed-delegated-with-caveat",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkfixedController",
            InvocationTarget = "https://example.com/api/resource",
            AllowedAction = new[] { "read" },
            Expires = "2027-01-01T00:00:00.000000Z",
            ParentCapability = "urn:zcap:root:fixed",
            Caveat = new Caveat[]
            {
                new ExpirationCaveat { Expires = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ValidWhileTrueCaveat { Uri = "https://revocation.example.com/abc" }
            },
            Proof = null
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
            CapabilityChain = new object[] { "urn:zcap:root:fixed" },
            ProofValue = "this-must-be-excluded"
        };

        // Sign-time path — what gets hashed and signed.
        var signTimeBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var signTimeJson = Encoding.UTF8.GetString(signTimeBytes);

        // Both derived-class fields must be in the signed bytes — that's the regression
        // guard for #39. STJ's default DateTime serialization for DateTimeKind.Utc emits
        // an ISO-8601 string with `Z` suffix; we just check for the date component.
        signTimeJson.Should().Contain("\"type\":\"Expiration\"");
        signTimeJson.Should().Contain("2027-01-01",
            "ExpirationCaveat.Expires is part of the signed wire bytes (#39)");
        signTimeJson.Should().Contain("\"type\":\"ValidWhileTrue\"");
        signTimeJson.Should().Contain("\"uri\":\"https://revocation.example.com/abc\"",
            "ValidWhileTrueCaveat.Uri is part of the signed wire bytes (#39)");

        // Wire-time path — what zcap-py would JCS-canonicalize over the same wire body.
        // Build the JCS payload by hand using the shared options + flat W3C shape, the
        // same way ProofSigningPayloadBuilder does internally.
        var canonicalizer = new JcsDocumentCanonicalizer();
        var wireDoc = new Dictionary<string, object>(StringComparer.Ordinal);
        var capElement = JsonSerializer.SerializeToElement(capability, ZcapJsonOptions.Default);
        foreach (var prop in capElement.EnumerateObject())
            wireDoc[prop.Name] = prop.Value;
        var proofElement = JsonSerializer.SerializeToElement(proof, ZcapJsonOptions.Default);
        var proofDict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var prop in proofElement.EnumerateObject())
            if (prop.Name != "proofValue") proofDict[prop.Name] = prop.Value;
        wireDoc["proof"] = proofDict;
        var wireBytes = canonicalizer.Canonicalize(wireDoc);

        // Load-bearing assertion: signed bytes == bytes any other Data Integrity verifier sees.
        wireBytes.Should().Equal(signTimeBytes,
            "the bytes signed by zcap-dotnet must equal the bytes zcap-py JCS-canonicalizes " +
            "over the wire body — otherwise signature verification fails at the chain link " +
            "with the caveat (#39).");
    }

    [Fact(DisplayName = "Issue #47 — controller array preserves shape and sign-time bytes match wire bytes")]
    public void CapabilityWithControllerArray_PreservesArrayShape_AndSignTimeBytesMatchWireBytes()
    {
        // ZCAP-LD allows `controller` to be a string or an array of strings. The two shapes
        // produce DIFFERENT JCS canonical bytes, so we must preserve whichever shape the
        // signer wrote — a single controller stays a bare string (existing pins cover that),
        // an array stays an array. If sign-time bytes diverge from what a cross-language
        // verifier JCS-canonicalizes over the wire body, the signature fails (#47).
        var capability = new Capability
        {
            Id = "urn:zcap:root:multi-controller",
            Context = "https://w3id.org/zcap/v1",
            Controller = new[] { "did:key:z6MkAlice", "did:key:z6MkBob" },
            InvocationTarget = "https://example.com/api/resource"
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkAlice#z6MkAlice",
            CapabilityChain = new object[] { "urn:zcap:root:multi-controller" },
            ProofValue = "this-must-be-excluded"
        };

        // Sign-time path — controller serialized as an array, keys alphabetically sorted.
        var signTimeBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var signTimeJson = Encoding.UTF8.GetString(signTimeBytes);

        signTimeJson.Should().Contain("\"controller\":[\"did:key:z6MkAlice\",\"did:key:z6MkBob\"]",
            "controller array shape must be preserved verbatim in the signed JCS bytes (#47)");

        // Wire-time path — what a peer verifier (zcap-py) JCS-canonicalizes over the wire body.
        var canonicalizer = new JcsDocumentCanonicalizer();
        var wireDoc = new Dictionary<string, object>(StringComparer.Ordinal);
        var capElement = JsonSerializer.SerializeToElement(capability, ZcapJsonOptions.Default);
        foreach (var prop in capElement.EnumerateObject())
            wireDoc[prop.Name] = prop.Value;
        var proofElement = JsonSerializer.SerializeToElement(proof, ZcapJsonOptions.Default);
        var proofDict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var prop in proofElement.EnumerateObject())
            if (prop.Name != "proofValue") proofDict[prop.Name] = prop.Value;
        wireDoc["proof"] = proofDict;
        var wireBytes = canonicalizer.Canonicalize(wireDoc);

        wireBytes.Should().Equal(signTimeBytes,
            "the bytes signed by zcap-dotnet for a multi-controller capability must equal the bytes " +
            "a cross-language verifier JCS-canonicalizes over the array-shaped wire body (#47).");
    }

    [Fact(DisplayName = "Issue #47 — single controller still emits a bare string (no array collapse)")]
    public void CapabilityWithSingleController_StillEmitsBareString()
    {
        // Regression guard: introducing ControllerSet must NOT turn a single controller
        // into a one-element array — that would change every existing capability's JCS
        // bytes and break signatures produced before #47.
        var capability = new Capability
        {
            Id = "urn:zcap:root:single",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkAlice",
            InvocationTarget = "https://example.com/api/resource"
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:00.000000Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:z6MkAlice#z6MkAlice",
            CapabilityChain = new object[] { "urn:zcap:root:single" },
            ProofValue = "this-must-be-excluded"
        };

        var canonical = Encoding.UTF8.GetString(
            ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof));

        canonical.Should().Contain("\"controller\":\"did:key:z6MkAlice\"");
        canonical.Should().NotContain("\"controller\":[");
    }

    [Fact(DisplayName = "Issue #37 — root capability wire form omits absent optional fields")]
    public void RootCapabilityWireForm_OmitsAbsentOptionalFields()
    {
        // Per W3C ZCAP-LD, root capabilities have unbounded authority — allowedAction,
        // caveat, parentCapability, expires, and proof are optional. Strict cross-language
        // parsers (zcap-py and friends) reject empty arrays / null values when those
        // fields are present, but accept absence. The model must therefore omit them
        // entirely from the wire when unset.
        var rootCapability = new Capability
        {
            Id = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkfixedController",
            InvocationTarget = "https://example.com/api/resource",
            // AllowedAction, Caveat, Expires, ParentCapability, Proof intentionally unset
        };

        var serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var wireJson = JsonSerializer.Serialize(rootCapability, serializerOptions);

        wireJson.Should().NotContain("\"allowedAction\"",
            "empty allowedAction would crash zcap-py's _parse_optional_action_list (#37)");
        wireJson.Should().NotContain("\"caveat\"",
            "empty caveat array breaks strict spec-conformant parsers (#37)");
        wireJson.Should().NotContain("\"parentCapability\"",
            "null parentCapability has no spec meaning on root capabilities (#37)");
        wireJson.Should().NotContain("\"expires\"",
            "null expires has no spec meaning on root capabilities (#37)");
        wireJson.Should().NotContain("\"proof\"",
            "root capabilities are unsigned by definition (#37)");
    }

    [Fact(DisplayName = "Issue #37 — CreateRootCapabilityAsync emits only @context, id, controller, invocationTarget")]
    public async Task CreateRootCapabilityAsync_EmitsOnlyMandatoryFields()
    {
        // Lock the on-wire shape produced by the service entry point that 99% of
        // consumers use. If a future change re-introduces empty optionals, this
        // test catches it before zcap-py / cross-stack interop breaks again.
        var resolver = new ZcapLd.Core.Services.DidKeyResolver();
        var signer = new ZcapLd.Core.Tests.Helpers.InMemoryDidProvider();
        var signingService = new ZcapLd.Core.Services.SigningService(signer, resolver);
        var capabilityService = new ZcapLd.Core.Services.CapabilityService(signingService);

        var rootCap = await capabilityService.CreateRootCapabilityAsync(
            controller: "did:key:z6MkfixedController",
            invocationTarget: "https://example.com/api/resource");

        var serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var wireJson = JsonSerializer.Serialize(rootCap, serializerOptions);

        // Only the four mandatory fields must appear.
        var doc = JsonSerializer.Deserialize<JsonElement>(wireJson);
        var keys = doc.EnumerateObject().Select(p => p.Name).OrderBy(k => k).ToArray();
        keys.Should().BeEquivalentTo(new[] { "@context", "controller", "id", "invocationTarget" });
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
        // CapabilityChain intentionally unset — invocation proofs don't carry a chain,
        // and emitting `"capabilityChain": []` breaks strict cross-language parsers (#37).
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T12:00:00.000000Z",
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = "did:key:z6MkfixedInvoker#z6MkfixedInvoker",
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
                    "\"created\":\"2026-04-29T12:00:00.000000Z\"," +
                    "\"invocationTarget\":\"https://example.com/api/resource\"," +
                    "\"proofPurpose\":\"capabilityInvocation\"," +
                    "\"type\":\"Ed25519Signature2020\"," +
                    "\"verificationMethod\":\"did:key:z6MkfixedInvoker#z6MkfixedInvoker\"" +
                "}" +
            "}";

        canonical.Should().Be(Expected);
        canonical.Should().NotContain("\"invocation\":{", "wrapper-shape `{invocation:..., proof:...}` breaks W3C Data Integrity interop");
        canonical.Should().NotContain("\"capabilityChain\"", "invocation proofs do not carry a capability chain (#37)");
        canonical.Should().NotContain("\"proofValue\"");
    }

    [Theory(DisplayName = "Issue #36 reproduction A — proof.created is preserved verbatim across many shapes")]
    [InlineData("2026-04-29T00:00:00Z")]
    [InlineData("2026-04-29T00:00:00.000000Z")]
    [InlineData("2026-04-29T00:00:00.123Z")]
    [InlineData("2026-04-29T00:00:00.123456789Z")]
    [InlineData("2026-04-29T00:00:00+00:00")]
    public void Created_PreservedVerbatim_NoMatterTheShape(string onWireCreated)
    {
        // Verifier path: an on-wire proof carries a `created` timestamp in some shape.
        // Every other Data Integrity verifier JCS-canonicalizes that string verbatim.
        // Our canonicalizer must do the same — any normalization at this boundary
        // diverges the bytes the signer signed from the bytes we hash.
        var invocation = new Invocation
        {
            Id = "urn:uuid:invocation-created-preservation",
            Capability = "urn:zcap:root:test",
            CapabilityAction = "read",
            InvocationTarget = "https://example.com/r"
        };
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = onWireCreated,
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = "did:key:zX#zX",
            ProofValue = "z-discarded"
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(invocation, proof);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        canonical.Should().Contain($"\"created\":\"{onWireCreated}\"",
            $"on-wire `created` value '{onWireCreated}' must appear unmodified in the JCS canonical bytes");
    }

    [Fact(DisplayName = "Issue #36 reproduction B — unmodeled proof fields (`domain`, `nonce`) are preserved")]
    public void Proof_UnmodeledFields_PreservedInCanonicalBytes()
    {
        // Simulate a proof that arrived from the wire with extension fields
        // not declared on Proof.cs (domain, nonce, id, challenge). Every other
        // Data Integrity verifier JCS-canonicalizes them. We must too.
        const string OnWire = """
        {
          "id": "urn:uuid:invocation-with-extensions",
          "capability": "urn:zcap:root:test",
          "capabilityAction": "read",
          "invocationTarget": "https://example.com/r",
          "proof": {
            "type": "Ed25519Signature2020",
            "created": "2026-04-29T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "verificationMethod": "did:key:zX#zX",
            "domain": "https://resource.example/proof-fields",
            "nonce": "abc123",
            "challenge": "ch-xyz",
            "id": "urn:proof:42",
            "capability": "urn:zcap:root:test",
            "capabilityAction": "read",
            "invocationTarget": "https://example.com/r",
            "proofValue": "z-this-must-be-excluded"
          }
        }
        """;

        var invocation = JsonSerializer.Deserialize<Invocation>(OnWire)!;
        invocation.Proof.Should().NotBeNull();

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation),
            invocation.Proof!);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        canonical.Should().Contain("\"domain\":\"https://resource.example/proof-fields\"",
            "unmodeled proof field `domain` must round-trip verbatim — it's part of what was signed");
        canonical.Should().Contain("\"nonce\":\"abc123\"",
            "unmodeled proof field `nonce` must round-trip verbatim");
        canonical.Should().Contain("\"challenge\":\"ch-xyz\"");
        canonical.Should().Contain("\"id\":\"urn:proof:42\"");
        canonical.Should().NotContain("\"proofValue\"", "proofValue must still be excluded");
    }

    [Fact(DisplayName = "Issue #36 — unmodeled capability fields are preserved")]
    public void Capability_UnmodeledFields_PreservedInCanonicalBytes()
    {
        const string OnWire = """
        {
          "@context": "https://w3id.org/zcap/v1",
          "id": "urn:uuid:capability-with-extensions",
          "controller": "did:key:zC",
          "invocationTarget": "https://example.com/r",
          "allowedAction": ["read"],
          "caveat": [],
          "expires": "2027-01-01T00:00:00Z",
          "parentCapability": "urn:zcap:root:test",
          "delegator": "did:key:zDelegator",
          "purpose": "operational-test"
        }
        """;
        var capability = JsonSerializer.Deserialize<Capability>(OnWire)!;
        capability.AdditionalProperties.Should().NotBeNull();
        capability.AdditionalProperties!.Should().ContainKey("delegator");
        capability.AdditionalProperties.Should().ContainKey("purpose");

        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = "2026-04-29T00:00:00Z",
            ProofPurpose = "capabilityDelegation",
            VerificationMethod = "did:key:zX#zX",
            CapabilityChain = new object[] { "urn:zcap:root:test" },
            ProofValue = "z-discarded"
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capability, proof);
        var canonical = Encoding.UTF8.GetString(canonicalBytes);

        canonical.Should().Contain("\"delegator\":\"did:key:zDelegator\"",
            "unmodeled capability field `delegator` must round-trip verbatim");
        canonical.Should().Contain("\"purpose\":\"operational-test\"");
        canonical.Should().Contain("\"expires\":\"2027-01-01T00:00:00Z\"",
            "on-wire `expires` value must appear unmodified in JCS canonical bytes");
    }

    [Fact(DisplayName = "SigningService formats fresh Created with 6-digit microsecond ISO-8601 UTC")]
    public void ZcapTimestamps_Format_ProducesSixDigitMicrosecondUtc()
    {
        // Sanity check: when zcap-dotnet generates a fresh timestamp on the signer
        // path, it uses the canonical 6-digit microsecond format that aligns with
        // the broader Data Integrity ecosystem.
        var formatted = ZcapTimestamps.Format(new DateTime(638829918538521234L, DateTimeKind.Utc));

        formatted.Should().MatchRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$");
    }

    [Fact(DisplayName = "ZcapTimestamps.Format normalizes Local-kind DateTimes to UTC")]
    public void ZcapTimestamps_Format_NormalizesLocalToUtc()
    {
        var local = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Local);
        var expected = local.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ss.ffffffZ", System.Globalization.CultureInfo.InvariantCulture);

        ZcapTimestamps.Format(local).Should().Be(expected);
    }
}
