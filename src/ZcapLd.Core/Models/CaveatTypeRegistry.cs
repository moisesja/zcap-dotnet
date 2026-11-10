using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Text.RegularExpressions;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// The custom caveat types a deployment issues and accepts (#157). Supplying a registry to
/// <see cref="Services.SigningService"/>, <see cref="Services.CapabilityService"/> and
/// <see cref="Services.VerificationService"/> enables the caveat extension profile; without one,
/// any <c>caveat</c> is rejected as before.
/// <para>
/// For each registered type the registry generates a pinned JSON-LD context,
/// <c>urn:zcap-dotnet:caveat-context:v1:&lt;type&gt;</c>, that defines the type and every declared
/// parameter as a JSON literal. Capabilities that carry the caveat list that context, so the type
/// and all parameter values are covered by the RDFC-1.0 delegation proof. The context is served from
/// memory and never fetched. Issuer and verifier must register the same class shape under the same
/// type name; a mismatch fails verification closed.
/// </para>
/// </summary>
/// <remarks>
/// There is no process-wide registry: each service is configured explicitly. A registry is frozen
/// when it is handed to a service, so the accepted types cannot change underneath a verifier.
/// </remarks>
public sealed class CaveatTypeRegistry
{
    /// <summary>The prefix of every generated caveat context URL; the type name follows it.</summary>
    public const string ContextUrlPrefix = "urn:zcap-dotnet:caveat-context:v1:";

    /// <summary>The prefix of every generated caveat type IRI; parameters are <c>&lt;typeIri&gt;#&lt;name&gt;</c>.</summary>
    public const string TypeIriPrefix = "urn:zcap-dotnet:caveat:v1:";

    internal static readonly Regex NamePattern = new("^[A-Za-z][A-Za-z0-9_]{0,63}$", RegexOptions.CultureInvariant);

    private readonly ConcurrentDictionary<string, CaveatTypeRegistration> _byType = new(StringComparer.Ordinal);
    private volatile bool _frozen;

    /// <summary>
    /// Registers <typeparamref name="TCaveat"/> under its wire <paramref name="type"/>, reading and
    /// writing it with reflection-based serializer metadata. Idempotent for the same pair. Throws when
    /// the name or a parameter name is invalid, when a parameter collides with a ZCAP/suite context
    /// term, when the class captures extension data, when the type or class is already registered
    /// differently, or when the registry has been handed to a service.
    /// <para>
    /// Reflection-based serialization is unavailable under native AOT, trimming and .NET 10 file-based
    /// apps (<c>dotnet run app.cs</c>); there this overload throws, and
    /// <see cref="Register{TCaveat}(string, JsonTypeInfo{TCaveat})"/> with a
    /// <see cref="System.Text.Json.Serialization.JsonSerializerContext"/> is the supported path (#154).
    /// </para>
    /// </summary>
    /// <param name="type">The caveat type name: an ASCII letter followed by up to 63 letters, digits
    /// or underscores. It must equal <see cref="Caveat.Type"/> for instances of the class.</param>
    /// <returns>This registry, for chaining.</returns>
    [RequiresUnreferencedCode(ReflectionMessage)]
    [RequiresDynamicCode(ReflectionMessage)]
    public CaveatTypeRegistry Register<TCaveat>(string type) where TCaveat : Caveat
    {
        if (!JsonSerializer.IsReflectionEnabledByDefault)
            throw new InvalidOperationException(
                "Reflection-based serialization is disabled in this application (native AOT, trimming or a file-based app), " +
                $"so caveat class {typeof(TCaveat).FullName} cannot be registered by reflection. Use " +
                "Register<TCaveat>(string, JsonTypeInfo<TCaveat>) with a [JsonSerializable(typeof(TCaveat))] JsonSerializerContext.");
        return Register(type, typeof(TCaveat), new DefaultJsonTypeInfoResolver());
    }

    /// <summary>
    /// Registers <typeparamref name="TCaveat"/> under its wire <paramref name="type"/> with
    /// source-generated serializer metadata, the overload for native AOT, trimmed and file-based
    /// applications (#154). <paramref name="typeInfo"/> is a property of a
    /// <see cref="System.Text.Json.Serialization.JsonSerializerContext"/> that lists the class with
    /// <c>[JsonSerializable(typeof(TCaveat))]</c>; its resolver must also cover every parameter type
    /// (the generator includes them automatically). The registry applies its own strict settings
    /// through that resolver, so the context's options do not matter, and the generated context
    /// document and wire bytes are identical to those of <see cref="Register{TCaveat}(string)"/>.
    /// Same rules and exceptions as that overload otherwise.
    /// </summary>
    /// <param name="type">The caveat type name; see <see cref="Register{TCaveat}(string)"/>.</param>
    /// <param name="typeInfo">Generated metadata for <typeparamref name="TCaveat"/>, for example
    /// <c>MyCaveatContext.Default.MyCaveat</c>.</param>
    /// <returns>This registry, for chaining.</returns>
    /// <exception cref="ArgumentException">The metadata has no resolver, or its resolver does not cover the class or one of its parameter types.</exception>
    public CaveatTypeRegistry Register<TCaveat>(string type, JsonTypeInfo<TCaveat> typeInfo) where TCaveat : Caveat
    {
        ArgumentNullException.ThrowIfNull(typeInfo);
        var resolver = typeInfo.OriginatingResolver ?? typeInfo.Options.TypeInfoResolver
            ?? throw new ArgumentException(
                "The JsonTypeInfo has no originating resolver; pass a property of a JsonSerializerContext.", nameof(typeInfo));
        return Register(type, typeof(TCaveat), resolver);
    }

    private const string ReflectionMessage =
        "Reflection-based caveat registration is unavailable under native AOT, trimming and file-based apps. " +
        "Use Register<TCaveat>(string, JsonTypeInfo<TCaveat>) with a JsonSerializerContext.";

    private CaveatTypeRegistry Register(string type, Type clrType, IJsonTypeInfoResolver resolver)
    {
        if (_frozen)
            throw new InvalidOperationException("The caveat type registry is in use by a service and can no longer change.");

        var registration = CaveatTypeRegistration.Create(type, clrType, resolver);
        if (_byType.Values.FirstOrDefault(r => r.ClrType == clrType && r.Type != type) is { } other)
            throw new InvalidOperationException(
                $"{clrType.FullName} is already registered as caveat type '{other.Type}'.");

        var existing = _byType.GetOrAdd(type, registration);
        if (existing.ClrType != clrType)
            throw new InvalidOperationException(
                $"Caveat type '{type}' is already registered to {existing.ClrType.FullName}.");
        return this;
    }

    /// <summary>The registered caveat type names.</summary>
    public IReadOnlyCollection<string> Types => _byType.Keys.Order(StringComparer.Ordinal).ToArray();

    /// <summary>The CLR type registered for <paramref name="type"/>, or <see langword="null"/>.</summary>
    public Type? Resolve(string type)
    {
        ArgumentNullException.ThrowIfNull(type);
        return _byType.TryGetValue(type, out var registration) ? registration.ClrType : null;
    }

    /// <summary>The generated context URL for <paramref name="type"/>.</summary>
    public static string GetContextUrl(string type) => ContextUrlPrefix + type;

    /// <summary>The generated JSON-LD context document (RFC 8785 JSON) for a registered type.</summary>
    public string GetContextDocument(string type)
        => TryGet(type, out var registration)
            ? registration.ContextDocument
            : throw new KeyNotFoundException($"Caveat type '{type}' is not registered.");

    internal bool IsEmpty => _byType.IsEmpty;

    internal void Freeze() => _frozen = true;

    internal bool TryGet(string type, [NotNullWhen(true)] out CaveatTypeRegistration? registration)
        => _byType.TryGetValue(type, out registration);

    internal bool TryGetByContextUrl(string url, [NotNullWhen(true)] out CaveatTypeRegistration? registration)
    {
        registration = null;
        return url.StartsWith(ContextUrlPrefix, StringComparison.Ordinal)
               && _byType.TryGetValue(url[ContextUrlPrefix.Length..], out registration);
    }
}
