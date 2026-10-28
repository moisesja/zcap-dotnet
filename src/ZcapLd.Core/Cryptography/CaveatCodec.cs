using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Reads, checks and writes the <c>caveat</c> array of the caveat extension profile (#157).
/// <para>
/// RDFC-1.0 signs only what the active JSON-LD context defines, and JSON literal values are
/// serialized with lossy number formatting. The rules here make the signed form a faithful,
/// injective image of what the verifier reads: every key must be declared (an undeclared one would
/// be dropped from the signature), the carrying capability must list the type's context (else the
/// whole caveat is dropped), and every number must already be in its RFC 8785 form within a range
/// where dotNetRDF's JSON literal equals RFC 8785, so two different values never sign alike.
/// </para>
/// </summary>
internal static class CaveatCodec
{
    internal const string Property = "caveat";
    internal const int MaxCaveats = 16;
    internal const int MaxLiteralDepth = 8;
    internal const int MaxLiteralValues = 1024;
    internal const int MaxStringLength = 4096;
    internal const int MaxCaveatJsonLength = 64 * 1024;

    // Below 1e-4 or with an exponent, dotNetRDF writes JSON-literal numbers as 1E-05 rather than the
    // RFC 8785 0.00001; above 2^53 integers stop being exact doubles.
    private const double MinMagnitude = 1e-4;
    private const double MaxMagnitude = 9007199254740992d;

    /// <summary>Strict options for caveat parameters: no unknown members, no numbers in strings.</summary>
    internal static JsonSerializerOptions SerializerOptions { get; } = CreateOptions();

    /// <summary>One checked caveat entry: its raw signed JSON and, when materialized, the typed value.</summary>
    internal sealed record Entry(CaveatTypeRegistration Registration, JsonElement Json, Caveat? Value);

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(ZcapJsonOptions.Default)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            NumberHandling = JsonNumberHandling.Strict,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver
            {
                Modifiers =
                {
                    // The library writes "type" from the registration; an overriding Type property would
                    // otherwise serialize as a second, CLR-named member (System.Text.Json does not
                    // inherit [JsonIgnore] onto overrides).
                    static info =>
                    {
                        if (!typeof(Caveat).IsAssignableFrom(info.Type) || info.Kind != JsonTypeInfoKind.Object)
                            return;
                        for (var i = info.Properties.Count - 1; i >= 0; i--)
                        {
                            if (info.Properties[i].AttributeProvider is System.Reflection.PropertyInfo { Name: nameof(Caveat.Type) })
                                info.Properties.RemoveAt(i);
                        }
                    },
                },
            },
        };
        options.MakeReadOnly();
        return options;
    }

    /// <summary>
    /// Reads the caveats of a typed capability. Returns <see langword="null"/> on success or the
    /// failure to report. <paramref name="materialize"/> also deserializes and validates each value
    /// (the revocation path skips that consumer policy, keeping only signature integrity).
    /// </summary>
    internal static VerificationResult? TryRead(
        Capability capability, CaveatTypeRegistry? registry, bool materialize, out List<Entry> entries)
    {
        JsonElement? value = capability.AdditionalProperties is { } extra && extra.TryGetValue(Property, out var element)
            ? element
            : null;
        return TryRead(value, ContextUrls(capability.Context), registry, materialize, out entries);
    }

    /// <summary>Reads a capability-level <c>caveat</c> value checked against that object's own <c>@context</c>.</summary>
    internal static VerificationResult? TryRead(
        JsonElement? caveatValue, IReadOnlyList<string>? contexts, CaveatTypeRegistry? registry, bool materialize,
        out List<Entry> entries)
    {
        entries = new List<Entry>();
        if (caveatValue is not { } value)
            return null;

        if (registry is null || registry.IsEmpty)
            return Malformed(CapabilityProfile.RejectionMessage);
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is 0 or > MaxCaveats)
            return Malformed($"caveat must be an array of 1 to {MaxCaveats} caveat objects.");
        if (value.GetRawText().Length > MaxCaveatJsonLength)
            return Malformed($"caveat JSON exceeds {MaxCaveatJsonLength} characters.");

        var budget = MaxLiteralValues;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                return Malformed("Each caveat must be a JSON object.");
            if (!item.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String ||
                typeElement.GetString() is not { } type || !CaveatTypeRegistry.NamePattern.IsMatch(type))
                return Malformed("Each caveat needs a single type name.");
            if (!registry.TryGet(type, out var registration))
                return VerificationResult.Fail(VerificationOutcome.UnsupportedCaveat,
                    $"Caveat type '{type}' is not registered with this verifier.");
            if (!seen.Add(type))
                return Malformed($"Caveat type '{type}' appears more than once.");
            if (contexts is null || !contexts.Contains(registration.ContextUrl, StringComparer.Ordinal))
                return Malformed(
                    $"A capability carrying a '{type}' caveat must list '{registration.ContextUrl}' in its own @context, " +
                    "or its parameters would not be signed.");

            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in item.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    return Malformed($"Caveat '{type}' repeats '{property.Name}'.");
                if (property.Name == "type")
                    continue;
                if (!registration.Parameters.Contains(property.Name, StringComparer.Ordinal))
                    return Malformed($"Caveat '{type}' has undeclared parameter '{property.Name}', which would not be signed.");
                if (CheckLiteral(property.Value, 1, ref budget) is { } problem)
                    return Malformed($"Caveat '{type}' parameter '{property.Name}': {problem}");
            }

            Caveat? caveat = null;
            if (materialize && Materialize(registration, item, out caveat) is { } failure)
                return failure;
            entries.Add(new Entry(registration, item, caveat));
        }

        return null;
    }

    /// <summary>Serializes a caveat to its canonical wire object, refusing a value that would not
    /// read back identically.</summary>
    internal static JsonElement Write(Caveat caveat, CaveatTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(caveat);
        if (!registry.TryGet(caveat.Type, out var registration) || registration.ClrType != caveat.GetType())
            throw new CapabilityValidationException(
                $"Caveat type '{caveat.Type}' ({caveat.GetType().FullName}) is not registered.");
        caveat.Validate();

        var node = JsonSerializer.SerializeToNode(caveat, caveat.GetType(), SerializerOptions)!.AsObject();
        node["type"] = registration.Type;
        using var document = JsonDocument.Parse(NetCid.JcsCanonicalizer.Canonicalize(node));
        var element = document.RootElement.Clone();

        var wrapped = JsonSerializer.SerializeToElement(new[] { element });
        if (TryRead(wrapped, new[] { registration.ContextUrl }, registry, materialize: true, out var read) is { } failure)
            throw new CapabilityValidationException(failure.Message ?? "Caveat value is not supported.");
        if (!ParametersEqual(read[0].Value!, caveat))
            throw new CapabilityValidationException(
                $"Caveat '{caveat.Type}' does not read back identically from its JSON form (check numeric precision).");
        return element;
    }

    /// <summary>
    /// True when two caveats of the same class have the same parameter values. Numbers compare by
    /// exact value (<see cref="JsonElement.DeepEquals"/>), not by a lossy double rendering.
    /// </summary>
    internal static bool ParametersEqual(Caveat first, Caveat second)
        => first.GetType() == second.GetType()
           && JsonElement.DeepEquals(
               JsonSerializer.SerializeToElement(first, first.GetType(), SerializerOptions),
               JsonSerializer.SerializeToElement(second, second.GetType(), SerializerOptions));

    /// <summary>Lowercase hex SHA-256 of the RFC 8785 array of ids from the root to a link.</summary>
    internal static string GrantKey(IEnumerable<string> idsFromRoot)
        => Convert.ToHexStringLower(SHA256.HashData(
            NetCid.JcsCanonicalizer.Canonicalize(new JsonArray(idsFromRoot.Select(id => (JsonNode?)id).ToArray()))));

    /// <summary>The <c>@context</c> entries when it is an array of strings (model or JSON form), else null.</summary>
    internal static IReadOnlyList<string>? ContextUrls(object? context)
    {
        var json = context switch
        {
            null => default,
            JsonElement element => element,
            _ => JsonSerializer.SerializeToElement(context, ZcapJsonOptions.Default),
        };
        if (json.ValueKind != JsonValueKind.Array)
            return null;
        var urls = new List<string>();
        foreach (var item in json.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
                return null;
            urls.Add(item.GetString()!);
        }
        return urls;
    }

    private static VerificationResult? Materialize(CaveatTypeRegistration registration, JsonElement item, out Caveat? caveat)
    {
        caveat = null;
        try
        {
            var parameters = JsonObject.Create(item)!;
            parameters.Remove("type");
            caveat = (Caveat?)parameters.Deserialize(registration.ClrType, SerializerOptions);
            if (caveat is null || caveat.Type != registration.Type)
                return Malformed($"Caveat '{registration.Type}' does not deserialize to a matching {registration.ClrType.Name}.");
            caveat.Validate();
            return null;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException
                                       or ArgumentException or CapabilityValidationException)
        {
            return Malformed($"Caveat '{registration.Type}' is invalid: {ex.Message}");
        }
        catch (Exception ex)
        {
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify,
                $"Caveat '{registration.Type}' could not be read: {ex.Message}");
        }
    }

    // Returns null when the JSON literal is acceptable, otherwise the problem.
    private static string? CheckLiteral(JsonElement value, int depth, ref int budget)
    {
        if (--budget < 0)
            return $"caveats exceed {MaxLiteralValues} JSON values.";
        if (depth > MaxLiteralDepth)
            return $"nesting exceeds depth {MaxLiteralDepth}.";

        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                        return $"repeats member '{property.Name}'.";
                    if ((CheckString(property.Name) ?? CheckLiteral(property.Value, depth + 1, ref budget)) is { } problem)
                        return problem;
                }
                return null;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    if (CheckLiteral(item, depth + 1, ref budget) is { } problem)
                        return problem;
                }
                return null;
            case JsonValueKind.String:
                return CheckString(value.GetString()!);
            case JsonValueKind.Number:
                return CheckNumber(value);
            case JsonValueKind.True or JsonValueKind.False:
                return null;
            default:
                return "null is not allowed (it is indistinguishable from an absent member in some proof variants).";
        }
    }

    private static string? CheckNumber(JsonElement value)
    {
        var raw = value.GetRawText();
        if (raw.Contains('e') || raw.Contains('E') ||
            !double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ||
            !double.IsFinite(number))
            return $"number {raw} must be finite and written without an exponent.";

        var magnitude = Math.Abs(number);
        if (magnitude != 0 && (magnitude < MinMagnitude || magnitude > MaxMagnitude))
            return $"number {raw} must be 0 or have a magnitude between 0.0001 and 2^53.";
        if (!string.Equals(Encoding.UTF8.GetString(NetCid.JcsCanonicalizer.Canonicalize(value)), raw, StringComparison.Ordinal))
            return $"number {raw} must be written in its RFC 8785 form.";
        return null;
    }

    private static string? CheckString(string text)
    {
        if (text.Length > MaxStringLength)
            return $"strings are limited to {MaxStringLength} characters.";
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c < 0x20 || c is '\u2028' or '\u2029')
                return "strings may not contain control characters or U+2028/U+2029.";
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                i++;
            else if (char.IsSurrogate(c))
                return "strings may not contain unpaired surrogates.";
        }
        return null;
    }

    private static VerificationResult Malformed(string message)
        => VerificationResult.Fail(VerificationOutcome.MalformedCapability, message);
}
