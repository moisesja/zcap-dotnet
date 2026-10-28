using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
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
    /// Registers <typeparamref name="TCaveat"/> under its wire <paramref name="type"/>. Idempotent for
    /// the same pair. Throws when the name or a parameter name is invalid, when a parameter collides
    /// with a ZCAP/suite context term, when the class captures extension data, when the type or class
    /// is already registered differently, or when the registry has been handed to a service.
    /// </summary>
    /// <param name="type">The caveat type name: an ASCII letter followed by up to 63 letters, digits
    /// or underscores. It must equal <see cref="Caveat.Type"/> for instances of the class.</param>
    /// <returns>This registry, for chaining.</returns>
    public CaveatTypeRegistry Register<TCaveat>(string type) where TCaveat : Caveat
    {
        if (_frozen)
            throw new InvalidOperationException("The caveat type registry is in use by a service and can no longer change.");

        var registration = CaveatTypeRegistration.Create(type, typeof(TCaveat));
        if (_byType.Values.FirstOrDefault(r => r.ClrType == typeof(TCaveat) && r.Type != type) is { } other)
            throw new InvalidOperationException(
                $"{typeof(TCaveat).FullName} is already registered as caveat type '{other.Type}'.");

        var existing = _byType.GetOrAdd(type, registration);
        if (existing.ClrType != typeof(TCaveat))
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
