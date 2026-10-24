using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>Reject unsupported vocabulary caveats before trusting or signing authority.</summary>
internal static class CapabilityProfile
{
    internal const string RejectionMessage =
        "Vocabulary-based caveats are not supported. Use expires, allowedAction and invocationTarget attenuation.";

    internal static void EnsureSupported(Capability? capability, object[]? chain = null)
    {
        if (!IsSupported(capability, chain))
            throw new CapabilityValidationException(RejectionMessage);
    }

    // Walk only capability locations, not arbitrary application payload properties. All proof-set
    // members are inspected, including ancestors not selected by the cryptographic verifier.
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
                if (cap.AdditionalProperties?.ContainsKey("caveat") == true) return false;
                return cap.Proof == null || cap.Proof.Values.All(proof =>
                    (proof.CapabilityChain == null || proof.CapabilityChain.All(entry => Check(entry, depth + 1))) &&
                    Check(proof.Capability?.EmbeddedCapability, depth + 1));
            }

            var json = value is JsonElement element ? element :
                JsonSerializer.SerializeToElement(value, ZcapJsonOptions.Default);
            if (json.ValueKind != JsonValueKind.Object) return true;
            if (json.TryGetProperty("caveat", out _)) return false;
            if (!json.TryGetProperty("proof", out var proofs)) return true;
            return proofs.ValueKind == JsonValueKind.Array
                ? proofs.EnumerateArray().All(proof => CheckProof(proof, depth + 1))
                : CheckProof(proofs, depth + 1);
        }

        bool CheckProof(JsonElement proof, int depth)
        {
            if (--remaining < 0 || depth > 32) return false;
            if (proof.ValueKind != JsonValueKind.Object) return true;
            if (proof.TryGetProperty("capabilityChain", out var ancestors) &&
                ancestors.ValueKind == JsonValueKind.Array &&
                !ancestors.EnumerateArray().All(entry => Check(entry, depth + 1))) return false;
            return !proof.TryGetProperty("capability", out var embedded) || Check(embedded, depth + 1);
        }
    }
}
