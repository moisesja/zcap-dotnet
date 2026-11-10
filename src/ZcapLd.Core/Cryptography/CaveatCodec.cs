using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
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

    /// <summary>
    /// Serializer metadata per caveat class, filled by both <see cref="CaveatTypeRegistry"/> overloads
    /// (first registration wins; every registration of a class yields the same shape). It only lets
    /// <see cref="Caveat.IsAttenuationOf"/>, which has no registry in scope, compare parameters; it never
    /// decides which types a verifier accepts.
    /// </summary>
    private static readonly ConcurrentDictionary<Type, JsonTypeInfo> Metadata = new();

    /// <summary>One checked caveat entry: its raw signed JSON and, when materialized, the typed value.</summary>
    internal sealed record Entry(CaveatTypeRegistration Registration, JsonElement Json, Caveat? Value);

    /// <summary>
    /// Resolves the strict caveat metadata for <paramref name="clrType"/> (no unknown members, no numbers
    /// in strings, nullability and <c>required</c> honoured, the overriding <see cref="Caveat.Type"/>
    /// property dropped) through <paramref name="resolver"/>, and proves the resolver also covers every
    /// parameter type, so a context that omits a nested type fails here rather than at the first
    /// delegation. The result is cached for <see cref="ParametersEqual(Caveat, Caveat)"/>.
    /// <para>
    /// The resolver is backed by <see cref="ZcapJsonContext"/> for the JSON DOM and string collection
    /// types zcap itself serializes: an <c>object</c>-typed parameter reads back as a
    /// <see cref="JsonElement"/>, whose metadata a consumer context that lists only the caveat class does
    /// not generate. Every enum reachable from the class is probed to write as a JSON number, so the
    /// bytes do not depend on an options-level converter the context may bake into its metadata
    /// (<c>UseStringEnumConverter</c>), which the reflection overload would not apply.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentException">The resolver does not provide metadata for the class or one of its parameter types, or an enum parameter does not serialize as a number.</exception>
    internal static JsonTypeInfo ResolveTypeInfo(Type clrType, IJsonTypeInfoResolver resolver)
    {
        var options = new JsonSerializerOptions(ZcapJsonOptions.Default)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            NumberHandling = JsonNumberHandling.Strict,
            TypeInfoResolver = JsonTypeInfoResolver.Combine(resolver, ZcapJsonContext.Default)
                .WithAddedModifier(RemoveTypeOverride),
        };
        options.MakeReadOnly();

        JsonTypeInfo typeInfo;
        try
        {
            typeInfo = options.GetTypeInfo(clrType);
            EnsureCovered(typeInfo, options, clrType.Name, new HashSet<Type>());
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException)
        {
            throw new ArgumentException(
                $"{clrType.FullName} cannot be serialized with the supplied metadata: {ex.Message} " +
                "Pass a JsonTypeInfo from a JsonSerializerContext whose [JsonSerializable] types include the caveat " +
                "class (its parameter types are then generated with it).", ex);
        }

        Metadata.TryAdd(clrType, typeInfo);
        return typeInfo;
    }

    // The library writes "type" from the registration; an overriding Type property would otherwise
    // serialize as a second, CLR-named member. Neither resolver inherits the base [JsonIgnore] onto the
    // override: reflection and the source generator both emit it, and both expose the declaring
    // PropertyInfo as the AttributeProvider (the generator through a lazy factory that reads the
    // preserved member), so one rule serves both paths.
    private static void RemoveTypeOverride(JsonTypeInfo info)
    {
        if (!typeof(Caveat).IsAssignableFrom(info.Type) || info.Kind != JsonTypeInfoKind.Object)
            return;
        for (var i = info.Properties.Count - 1; i >= 0; i--)
        {
            if (IsTypeOverride(info.Properties[i]))
                info.Properties.RemoveAt(i);
        }
    }

    private static bool IsTypeOverride(JsonPropertyInfo property)
        => property.AttributeProvider is PropertyInfo { Name: nameof(Caveat.Type) } member
            ? typeof(Caveat).IsAssignableFrom(member.DeclaringType)
            : property.AttributeProvider is null && property.Name == nameof(Caveat.Type)
              && property.PropertyType == typeof(string) && property.Set is null;

    // Every parameter type reachable from the caveat class must resolve now: System.Text.Json resolves
    // nested metadata lazily, so a context missing one would otherwise surface on first use. The path
    // names the parameter in the registration error.
    private static void EnsureCovered(JsonTypeInfo typeInfo, JsonSerializerOptions options, string path, HashSet<Type> visited)
    {
        if (!visited.Add(typeInfo.Type))
            return;
        if ((Nullable.GetUnderlyingType(typeInfo.Type) ?? typeInfo.Type) is { IsEnum: true } enumType)
            EnsureEnumWritesNumbers(enumType, options, path);
        if (typeInfo.Type == typeof(object))
        {
            // The object converter reads any JSON value back as a JsonElement and writes that element
            // through its own metadata, so the registration must resolve it as well as object.
            EnsureCovered(options.GetTypeInfo(typeof(JsonElement)), options, path, visited);
        }
        foreach (var property in typeInfo.Properties)
            EnsureCovered(options.GetTypeInfo(property.PropertyType), options, $"{path}.{property.Name}", visited);
        if (typeInfo.ElementType is { } elementType)
            EnsureCovered(options.GetTypeInfo(elementType), options, $"{path}[]", visited);
        if (typeInfo.KeyType is { } keyType)
            EnsureCovered(options.GetTypeInfo(keyType), options, $"{path}{{key}}", visited);
    }

    // Both overloads must write the same bytes, and the only serializer setting a consumer's generated
    // context carries into its metadata that changes them is an options-level enum converter
    // (UseStringEnumConverter, Converters = …): the resulting converter is not distinguishable through
    // the public metadata, so a defined member is written and must come out as a JSON number. Member-level
    // [JsonConverter] attributes sit on the property, not the enum's own metadata, and both overloads honour
    // them alike, so they are not what this probes. Enum.GetValuesAsUnderlyingType and Enum.ToObject are
    // the AOT-safe way to obtain a boxed member without creating an array of the enum type.
    private static void EnsureEnumWritesNumbers(Type enumType, JsonSerializerOptions options, string path)
    {
        var values = Enum.GetValuesAsUnderlyingType(enumType);
        if (values.Length == 0)
            return; // every value of a member-less enum is undefined and written as a number by any converter
        var sample = Enum.ToObject(enumType, values.GetValue(0)!);
        var written = JsonSerializer.SerializeToElement(sample, options.GetTypeInfo(enumType));
        // A [JsonConverter] on the enum type itself is read by reflection and the generator alike, so a
        // string form that comes from it is the same under both overloads (6.0.0 behaviour kept).
        if (written.ValueKind != JsonValueKind.Number && !enumType.IsDefined(typeof(JsonConverterAttribute), inherit: false))
            throw new ArgumentException(
                $"Caveat parameter {path} ({enumType.FullName}) serializes as {written.ValueKind}, not as a number. " +
                "The JsonSerializerContext must not use UseStringEnumConverter or any options-level converter, " +
                "because Register<TCaveat>(string) and Register<TCaveat>(string, JsonTypeInfo<TCaveat>) must write the " +
                "same bytes; declare the converter on the member with [JsonConverter] instead, which both overloads honour.");
    }

    /// <summary>
    /// The cached metadata of a caveat class, for the paths that have no registration in scope. A class
    /// that was never registered is resolved by reflection when the application allows it; otherwise it
    /// must have been registered through the <see cref="JsonTypeInfo{T}"/> overload first.
    /// </summary>
    private static JsonTypeInfo MetadataFor(Type clrType)
    {
        if (Metadata.TryGetValue(clrType, out var typeInfo))
            return typeInfo;
        if (!JsonSerializer.IsReflectionEnabledByDefault)
            throw new InvalidOperationException(
                $"Caveat class {clrType.FullName} has no serializer metadata and reflection-based serialization is " +
                "disabled in this application. Register it with CaveatTypeRegistry.Register<TCaveat>(string, " +
                "JsonTypeInfo<TCaveat>) from a JsonSerializerContext before comparing its instances.");
        return ResolveByReflection(clrType);
    }

    // Only reached when the reflection feature switch is on, so the trimmer removes this branch (and
    // its warnings' subject) from a trimmed or AOT application; the same pattern guards the runtime's
    // own JsonSerializerOptions.Default and ZcapJsonOptions.CombineWithReflection.
    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "Guarded by JsonSerializer.IsReflectionEnabledByDefault, a feature switch the trimmer evaluates; the branch is dead when reflection-based serialization is disabled.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "Guarded by JsonSerializer.IsReflectionEnabledByDefault, a feature switch the trimmer evaluates; the branch is dead when reflection-based serialization is disabled.")]
    private static JsonTypeInfo ResolveByReflection(Type clrType)
        => ResolveTypeInfo(clrType, new DefaultJsonTypeInfoResolver());

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

        var node = JsonSerializer.SerializeToNode(caveat, registration.TypeInfo)!.AsObject();
        node["type"] = registration.Type;
        using var document = JsonDocument.Parse(Jcs.Canonicalize(node));
        var element = document.RootElement.Clone();

        var wrapped = JsonSerializer.SerializeToElement(new[] { element }, ZcapJsonOptions.TypeInfo<JsonElement[]>());
        if (TryRead(wrapped, new[] { registration.ContextUrl }, registry, materialize: true, out var read) is { } failure)
            throw new CapabilityValidationException(failure.Message ?? "Caveat value is not supported.");
        if (!ParametersEqual(read[0].Value!, caveat, registration.TypeInfo))
            throw new CapabilityValidationException(
                $"Caveat '{caveat.Type}' does not read back identically from its JSON form (check numeric precision).");
        return element;
    }

    /// <summary>
    /// True when two caveats of the same class have the same parameter values. Numbers compare by
    /// exact value (<see cref="JsonElement.DeepEquals"/>), not by a lossy double rendering.
    /// </summary>
    internal static bool ParametersEqual(Caveat first, Caveat second)
        => first.GetType() == second.GetType() && ParametersEqual(first, second, MetadataFor(first.GetType()));

    private static bool ParametersEqual(Caveat first, Caveat second, JsonTypeInfo typeInfo)
        => JsonElement.DeepEquals(
            JsonSerializer.SerializeToElement(first, typeInfo),
            JsonSerializer.SerializeToElement(second, typeInfo));

    /// <summary>Lowercase hex SHA-256 of the RFC 8785 array of ids from the root to a link.</summary>
    internal static string GrantKey(IEnumerable<string> idsFromRoot)
        => Convert.ToHexStringLower(SHA256.HashData(
            Jcs.Canonicalize(new JsonArray(idsFromRoot.Select(id => (JsonNode?)id).ToArray()))));

    /// <summary>The <c>@context</c> entries when it is an array of strings (model or JSON form), else null.</summary>
    internal static IReadOnlyList<string>? ContextUrls(object? context)
    {
        var json = context switch
        {
            null => default,
            JsonElement element => element,
            _ => JsonSerializer.SerializeToElement(context, ZcapJsonOptions.TypeInfo<object>()),
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
            caveat = (Caveat?)JsonSerializer.Deserialize(parameters, registration.TypeInfo);
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
        if (!string.Equals(Encoding.UTF8.GetString(Jcs.Canonicalize(value)), raw, StringComparison.Ordinal))
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
