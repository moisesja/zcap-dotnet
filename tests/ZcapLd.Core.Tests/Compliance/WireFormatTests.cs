using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// Wire-format (serialization-shape) known-answer tests, independent of canonicalization.
/// These pin the JSON the model emits — field omission, no array-collapse of single
/// controllers/proofs, and timestamp formatting — so a serializer regression that breaks strict
/// cross-language parsers (zcap-py and friends) is caught regardless of which canonicalization is
/// used. (Recovered from the former CrossLanguageJcsInteropTests when JCS was removed in 4.0.0; the
/// JCS-payload-shape pins there were dropped because RDFC-1.0 is now the only canonicalization.)
/// </summary>
public class WireFormatTests
{
    [Fact(DisplayName = "Issue #48 — single proof still emits a bare object (no array wrap)")]
    public void CapabilityWithSingleProof_StillEmitsBareObject()
    {
        // Regression guard: introducing ProofSet must NOT wrap a single proof into a
        // one-element array — that would change every existing delegated zcap's wire shape.
        var capability = new Capability
        {
            Id = "urn:uuid:fixed-delegated-single",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkfixedController",
            InvocationTarget = "https://example.com/api/resource",
            ParentCapability = "urn:zcap:root:fixed",
            Proof = new Proof
            {
                Type = "Ed25519Signature2020",
                Created = "2026-04-29T12:00:00.000000Z",
                ProofPurpose = "capabilityDelegation",
                VerificationMethod = "did:key:z6MkfixedSigner#z6MkfixedSigner",
                CapabilityChain = new object[] { "urn:zcap:root:fixed" },
                ProofValue = "z-single"
            }
        };

        var json = JsonSerializer.Serialize(capability, ZcapJsonOptions.Default);

        json.Should().Contain("\"proof\":{");
        json.Should().NotContain("\"proof\":[");
    }

    [Fact(DisplayName = "Issue #47 — single controller still emits a bare string (no array collapse)")]
    public void CapabilityWithSingleController_StillEmitsBareString()
    {
        // Regression guard: ControllerSet must NOT turn a single controller into a one-element
        // array — that would change every existing capability's wire shape and break signatures
        // produced before #47.
        var capability = new Capability
        {
            Id = "urn:zcap:root:single",
            Context = "https://w3id.org/zcap/v1",
            Controller = "did:key:z6MkAlice",
            InvocationTarget = "https://example.com/api/resource"
        };

        var json = JsonSerializer.Serialize(capability, ZcapJsonOptions.Default);

        json.Should().Contain("\"controller\":\"did:key:z6MkAlice\"");
        json.Should().NotContain("\"controller\":[");
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
        var resolver = new DidKeyResolver();
        var signer = new InMemoryDidProvider();
        var signingService = new SigningService(signer, resolver);
        var capabilityService = new CapabilityService(signingService);

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
