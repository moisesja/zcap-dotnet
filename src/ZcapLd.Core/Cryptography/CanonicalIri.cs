using System.Diagnostics.CodeAnalysis;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Identifies ids that are bound byte-for-byte by an RDFC-1.0 signature. JSON-LD expansion (via
/// dotNetRDF's <see cref="Uri"/>) normalizes an IRI before it is signed: it lowercases the scheme
/// and host, drops a default port, resolves dot segments, decodes unreserved percent-escapes and
/// trims whitespace, and a relative id produces no IRI at all. A variant id therefore verifies as
/// if it were the signed one. Revocation, replay and caveat budgets are keyed by the id string, so
/// the verifier accepts such an id only when it is already in normalized absolute form (#157).
/// <para>
/// dotNetRDF also silently drops an IRI that .NET does not consider well formed (for example one
/// containing <c>[</c>, <c>]</c> or a second <c>#</c>): as a subject it removes the whole node, as a
/// value the triple. Every IRI the verifier relies on must therefore be <see cref="IsBindable"/>.
/// </para>
/// </summary>
internal static class CanonicalIri
{
    internal const string RequirementMessage =
        "must be a well-formed absolute IRI in normalized form (lowercase scheme and host, no default " +
        "port, dot segments or escaped unreserved characters), because the signature binds only that form";

    internal const string BindableMessage =
        "must be a well-formed absolute IRI (for example, percent-encode [ and ]), because the signature " +
        "silently omits any other value";

    /// <summary>True when RDFC keeps <paramref name="value"/> in the signed graph.</summary>
    internal static bool IsBindable([NotNullWhen(true)] string? value)
        => !string.IsNullOrEmpty(value)
           && Uri.IsWellFormedUriString(value, UriKind.Absolute)
           && Uri.TryCreate(value, UriKind.Absolute, out var uri)
           && uri.IsWellFormedOriginalString();

    /// <summary>True when <paramref name="value"/> is bindable and already in its signed (normalized) form.</summary>
    internal static bool IsCanonical([NotNullWhen(true)] string? value)
        => IsBindable(value)
           && string.Equals(new Uri(value, UriKind.Absolute).AbsoluteUri, value, StringComparison.Ordinal);
}
