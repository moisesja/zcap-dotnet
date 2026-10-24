using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>Reject unsupported vocabulary caveats before trusting or signing authority.</summary>
internal static class CapabilityProfile
{
    internal const string RejectionMessage =
        "Unsupported caveat vocabulary or capability/proof context. Use expires, allowedAction and invocationTarget attenuation with the supported suite contexts.";

    private static readonly HashSet<string> CaveatKeys = new(StringComparer.Ordinal)
    {
        "caveat", "https://w3id.org/security#caveat", "sec:caveat"
    };

    internal static bool IsSupportedProof(Proof? proof)
        => proof is null || IsSupported(new Capability { Proof = proof });

    internal static void EnsureSupported(Capability? capability, object[]? chain = null)
    {
        if (!IsSupported(capability, chain))
            throw new CapabilityValidationException(RejectionMessage);
    }

    // Inspect capability/proof JSON, including extension data: @nest/@graph or a nested object
    // with the capability's id can add RDF properties to that same capability. Application
    // document bodies are outside this scan. Restrict contexts to prevent alternate aliases.
    // Bounds also reject cycles in programmatically constructed capability graphs.
    internal static bool IsSupported(Capability? capability, object[]? chain = null)
    {
        var remaining = 1024;
        try
        {
            return Check(capability, 0) && (chain == null || chain.All(entry => Check(entry, 0)));
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException)
        {
            return false;
        }

        bool Check(object? value, int depth)
        {
            if (--remaining < 0 || depth > 32) return false;
            if (value is null or string) return true;
            if (value is Capability cap)
            {
                if (!CheckContext(cap.Context) ||
                    cap.AdditionalProperties?.ContainsKey("@context") == true ||
                    !CheckProperties(cap.AdditionalProperties, depth)) return false;
                return cap.Proof == null || cap.Proof.Values.All(proof =>
                    CheckProperties(proof.AdditionalProperties, depth + 1) &&
                    (proof.CapabilityChain == null || proof.CapabilityChain.All(entry => Check(entry, depth + 1))) &&
                    Check(proof.Capability?.EmbeddedCapability, depth + 1));
            }

            var json = value is JsonElement element ? element :
                JsonSerializer.SerializeToElement(value, ZcapJsonOptions.Default);
            if (json.ValueKind == JsonValueKind.Array)
                return json.EnumerateArray().All(entry => Check(entry, depth + 1));
            return json.ValueKind != JsonValueKind.Object || json.EnumerateObject().All(property =>
                CheckProperty(property.Name, property.Value, depth));
        }

        bool CheckProperties(Dictionary<string, JsonElement>? properties, int depth)
            => properties == null || properties.All(property => CheckProperty(property.Key, property.Value, depth));

        bool CheckProperty(string name, JsonElement value, int depth)
        {
            if (CaveatKeys.Contains(name)) return false;
            return name == "@context" ? CheckContext(value) : Check(value, depth + 1);
        }

        bool CheckContext(object? context)
        {
            bool Known(string? url) => url == "https://w3id.org/zcap/v1" || ZcapSuiteCatalog.IsSupportedContext(url);
            if (context is string url) return Known(url);
            var json = context is JsonElement element ? element : JsonSerializer.SerializeToElement(context);
            if (json.ValueKind == JsonValueKind.String) return Known(json.GetString());
            // No inline definitions, scoped aliases, or unrelated offline vocabulary. This is
            // intentionally a supported-profile restriction, not a second JSON-LD expander.
            return json.ValueKind == JsonValueKind.Array && json.GetArrayLength() is > 0 and <= 32 &&
                json.EnumerateArray().All(entry => entry.ValueKind == JsonValueKind.String && Known(entry.GetString()));
        }
    }
}
