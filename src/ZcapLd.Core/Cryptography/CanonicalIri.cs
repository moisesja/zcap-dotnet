using System.Diagnostics.CodeAnalysis;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Identifies ids that are bound byte-for-byte by an RDFC-1.0 signature. JSON-LD expansion (via
/// dotNetRDF's <see cref="Uri"/>) normalizes an IRI before it is signed: it lowercases the scheme
/// and host, drops a default port, resolves dot segments, decodes unreserved percent-escapes and
/// trims whitespace, and a relative id produces no IRI at all. A variant id therefore verifies as
/// if it were the signed one. Revocation, replay and caveat budgets are keyed by the id string, so
/// the verifier accepts such an id only when it is already in normalized absolute form (#157).
/// </summary>
internal static class CanonicalIri
{
    internal const string RequirementMessage =
        "must be an absolute IRI in normalized form (lowercase scheme and host, no default port, " +
        "dot segments or escaped unreserved characters), because the signature binds only that form";

    internal static bool IsCanonical([NotNullWhen(true)] string? value)
        => !string.IsNullOrEmpty(value)
           && Uri.TryCreate(value, UriKind.Absolute, out var uri)
           && string.Equals(uri.AbsoluteUri, value, StringComparison.Ordinal);
}
