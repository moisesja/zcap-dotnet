using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Reject unsupported vocabulary before trusting or signing authority. Without a caveat registry
/// every <c>caveat</c> is rejected; with one, registered caveats are admitted at capability level
/// only and checked by <see cref="CaveatCodec"/> (#157).
/// </summary>
internal static class CapabilityProfile
{
    internal const string RejectionMessage =
        "Unsupported caveat vocabulary or capability/proof context. Use expires, allowedAction and invocationTarget attenuation with the supported suite contexts, or register the caveat type.";
    // A maximum-length chain with array-form proofs uses more than 32 JSON levels.
    // These inspection limits allow that shape and substantial action lists, while still
    // bounding work on arbitrary extension data and programmatically constructed cycles.
    internal const int MaxInspectionDepth = 64;
    internal const int MaxInspectionValues = 65_536;
    internal const string KeywordKeyMessage =
        "Capability and proof JSON may not use JSON-LD keywords (other than @context) or IRIs as keys: they " +
        "can restate signed terms the verifier does not read.";
    internal const string InspectionLimitMessage =
        "Capability/proof inspection exceeds the depth (64) or visited-value (65536) limit.";

    // Expanded and prefixed forms of the zcap/v1 caveat term are never accepted: only the compact
    // key at capability level, checked against registered types, can carry a caveat.
    private static readonly HashSet<string> CaveatAliases = new(StringComparer.Ordinal)
    {
        "https://w3id.org/security#caveat", "sec:caveat"
    };

    internal static bool IsSupportedProof(Proof? proof, CaveatTypeRegistry? caveats = null)
        => GetProofRejectionReason(proof, caveats) is null;

    internal static string? GetProofRejectionReason(Proof? proof, CaveatTypeRegistry? caveats = null)
        => proof is null ? null : Validate(new Capability { Proof = proof }, caveats: caveats)?.Message;

    internal static void EnsureSupported(Capability? capability, object[]? chain = null, CaveatTypeRegistry? caveats = null)
    {
        if (Validate(capability, chain, caveats) is { } failure)
            throw new CapabilityValidationException(failure.Message ?? RejectionMessage);
    }

    // Inspect capability/proof JSON, including extension data: @nest/@graph or a nested object
    // with the capability's id can add RDF properties to that same capability. Application
    // document bodies are outside this scan. Restrict contexts to prevent alternate aliases.
    // Bounds also reject cycles in programmatically constructed capability graphs.
    internal static bool IsSupported(Capability? capability, object[]? chain = null, CaveatTypeRegistry? caveats = null)
        => Validate(capability, chain, caveats) is null;

    internal static string? GetRejectionReason(Capability? capability, object[]? chain = null, CaveatTypeRegistry? caveats = null)
        => Validate(capability, chain, caveats)?.Message;

    /// <summary>
    /// Returns <see langword="null"/> when the capability (and optional chain) uses only supported
    /// vocabulary, otherwise the failure: <see cref="VerificationOutcome.UnsupportedCaveat"/> for an
    /// unregistered caveat type, else <see cref="VerificationOutcome.MalformedCapability"/>.
    /// </summary>
    internal static VerificationResult? Validate(Capability? capability, object[]? chain = null, CaveatTypeRegistry? caveats = null)
    {
        var registry = caveats is { IsEmpty: false } ? caveats : null;
        var remaining = MaxInspectionValues;
        VerificationResult? failure = null;
        try
        {
            return Check(capability, 0, capabilityLevel: true) &&
                   (chain == null || chain.All(entry => Check(entry, 0, capabilityLevel: true)))
                ? null
                : failure ?? Malformed(RejectionMessage);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException)
        {
            return Malformed("Capability/proof JSON could not be inspected safely.");
        }

        // capabilityLevel: the value sits where a capability object belongs (the scanned capability,
        // a capabilityChain entry, an invocation's capability), the only place a caveat may appear.
        bool Check(object? value, int depth, bool capabilityLevel = false)
        {
            if (--remaining < 0 || depth > MaxInspectionDepth)
                return Fail(Malformed(InspectionLimitMessage));
            if (value is null or string) return true;
            if (value is Capability cap)
            {
                if (BindingFailure(cap) is { } binding)
                    return Fail(Malformed(binding));
                if (!CheckContext(cap.Context) ||
                    cap.AdditionalProperties?.ContainsKey("@context") == true ||
                    !CheckCapabilityProperties(cap.AdditionalProperties, cap.Context, depth)) return false;
                return cap.Proof == null || cap.Proof.Values.All(proof =>
                    (string.IsNullOrEmpty(proof.VerificationMethod) || CanonicalIri.IsBindable(proof.VerificationMethod) ||
                     Fail(Malformed($"verificationMethod {CanonicalIri.BindableMessage}."))) &&
                    CheckProperties(proof.AdditionalProperties, depth + 1) &&
                    (proof.CapabilityChain == null || proof.CapabilityChain.All(entry => Check(entry, depth + 1, capabilityLevel: true))) &&
                    Check(proof.Capability?.EmbeddedCapability, depth + 1, capabilityLevel: true));
            }

            var json = value is JsonElement element ? element :
                JsonSerializer.SerializeToElement(value, ZcapJsonOptions.Default);
            if (json.ValueKind == JsonValueKind.Array)
                return json.EnumerateArray().All(entry => Check(entry, depth + 1));
            if (json.ValueKind != JsonValueKind.Object)
                return true;

            JsonElement? caveat = null;
            JsonElement? context = null;
            foreach (var property in json.EnumerateObject())
            {
                if (capabilityLevel && property.Name == CaveatCodec.Property)
                    caveat = property.Value;
                else if (!CheckProperty(property.Name, property.Value, depth))
                    return false;
                if (property.Name == "@context")
                    context = property.Value;
            }

            return caveat is not { } caveatValue || CheckCaveat(caveatValue, context);
        }

        bool CheckCapabilityProperties(Dictionary<string, JsonElement>? properties, object? context, int depth)
        {
            if (properties is null) return true;
            foreach (var (name, value) in properties)
            {
                if (name == CaveatCodec.Property)
                {
                    if (!CheckCaveat(value, context)) return false;
                }
                else if (!CheckProperty(name, value, depth))
                {
                    return false;
                }
            }
            return true;
        }

        // Proof extensions. A revocation's metadata is a JSON literal under the revocation context:
        // its member names are data, not JSON-LD keys.
        bool CheckProperties(Dictionary<string, JsonElement>? properties, int depth)
            => properties == null || properties.All(property =>
                property.Key == Proof.RevocationMetadataField
                    ? property.Value.ValueKind == JsonValueKind.Object
                    : CheckProperty(property.Key, property.Value, depth));

        bool CheckProperty(string name, JsonElement value, int depth)
        {
            if (name == CaveatCodec.Property || CaveatAliases.Contains(name)) return false;
            // A JSON-LD keyword or an IRI used as a key restates a term the model does not read:
            // "@nest": {"allowedAction": …}, an "@included" node with the capability's id, or
            // "https://w3id.org/security#allowedAction" signs the same triples as allowedAction, so a
            // holder could hide a signed restriction (actions, expiry) from the verifier.
            if (name.Contains(':') || (name.StartsWith('@') && name != "@context"))
                return Fail(Malformed(KeywordKeyMessage));
            if (registry is not null && !IsAllowedUnderCaveatProfile(name, value)) return false;
            return name == "@context" ? CheckContext(value) : Check(value, depth + 1);
        }

        // With caveats enabled the scanned JSON may not reach caveat vocabulary any other way: no
        // property named after a caveat type, and no type naming a caveat type outside a caveat entry.
        bool IsAllowedUnderCaveatProfile(string name, JsonElement value)
        {
            if (registry!.Resolve(name) is not null)
                return false;
            if (name != "type") return true;
            return value.ValueKind switch
            {
                JsonValueKind.String => registry.Resolve(value.GetString()!) is null,
                JsonValueKind.Array => value.EnumerateArray().All(item =>
                    item.ValueKind != JsonValueKind.String || registry.Resolve(item.GetString()!) is null),
                _ => true,
            };
        }

        bool CheckCaveat(JsonElement value, object? context)
            => CaveatCodec.TryRead(value, CaveatCodec.ContextUrls(context), registry, materialize: false, out _) is not { } problem
               || Fail(problem);

        bool CheckContext(object? context)
        {
            bool Known(string? url) => url == "https://w3id.org/zcap/v1" || ZcapSuiteCatalog.IsSupportedContext(url) ||
                                       (registry is not null && url is not null && registry.TryGetByContextUrl(url, out _));
            if (context is string url) return Known(url);
            var json = context is JsonElement element ? element : JsonSerializer.SerializeToElement(context);
            if (json.ValueKind == JsonValueKind.String) return Known(json.GetString());
            // No inline definitions, scoped aliases, or unrelated offline vocabulary. This is
            // intentionally a supported-profile restriction, not a second JSON-LD expander.
            if (json.ValueKind == JsonValueKind.Array && json.GetArrayLength() is > 0 and <= 32 &&
                json.EnumerateArray().All(entry => entry.ValueKind == JsonValueKind.String && Known(entry.GetString())))
                return true;
            if (registry is not null && json.ValueKind == JsonValueKind.Array &&
                json.EnumerateArray().Any(entry => entry.ValueKind == JsonValueKind.String &&
                                                    entry.GetString()!.StartsWith(CaveatTypeRegistry.ContextUrlPrefix, StringComparison.Ordinal) &&
                                                    !registry.TryGetByContextUrl(entry.GetString()!, out _)))
                return Fail(VerificationResult.Fail(VerificationOutcome.UnsupportedCaveat,
                    "The capability uses a caveat context this verifier has not registered."));
            return false;
        }

        bool Fail(VerificationResult result)
        {
            failure ??= result;
            return false;
        }
    }

    // Fields RDFC would silently drop (or normalize) cannot be trusted: a malformed id removes the
    // whole capability from the signed graph, a malformed target or controller removes that triple.
    private static string? BindingFailure(Capability capability)
    {
        if (!string.IsNullOrEmpty(capability.Id) && !CanonicalIri.IsCanonical(capability.Id))
            return $"Capability id {CanonicalIri.RequirementMessage}.";
        if (!string.IsNullOrEmpty(capability.ParentCapability) && !CanonicalIri.IsCanonical(capability.ParentCapability))
            return $"parentCapability {CanonicalIri.RequirementMessage}.";
        if (!string.IsNullOrEmpty(capability.InvocationTarget) && !CanonicalIri.IsSignedTarget(capability.InvocationTarget))
            return $"invocationTarget {CanonicalIri.TargetMessage}.";
        if (capability.Controller?.Values.Any(controller => !CanonicalIri.IsBindable(controller)) == true)
            return $"Every controller {CanonicalIri.BindableMessage}.";
        return null;
    }

    private static VerificationResult Malformed(string message)
        => VerificationResult.Fail(VerificationOutcome.MalformedCapability, message);
}
