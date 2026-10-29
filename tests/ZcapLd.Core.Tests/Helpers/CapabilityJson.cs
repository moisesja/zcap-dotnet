using System.Text.Json;
using System.Text.Json.Nodes;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>Edits a capability's wire JSON, as an attacker holding it could.</summary>
internal static class CapabilityJson
{
    public static string Serialize(Capability capability) => JsonSerializer.Serialize(capability, ZcapJsonOptions.Default);

    public static Capability Parse(string json) => JsonSerializer.Deserialize<Capability>(json, ZcapJsonOptions.Default)!;

    public static Capability Edit(Capability capability, Action<JsonObject> edit)
    {
        var node = JsonNode.Parse(Serialize(capability))!.AsObject();
        edit(node);
        return Parse(node.ToJsonString(ZcapJsonOptions.Default));
    }

    /// <summary>Replaces raw JSON text, for edits a JSON DOM cannot express (number spellings).</summary>
    public static Capability EditText(Capability capability, string find, string replace)
    {
        var json = Serialize(capability);
        if (!json.Contains(find, StringComparison.Ordinal))
            throw new InvalidOperationException($"'{find}' does not occur in the capability JSON.");
        return Parse(json.Replace(find, replace, StringComparison.Ordinal));
    }
}
