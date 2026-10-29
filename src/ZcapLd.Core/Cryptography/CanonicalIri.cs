using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.Rdfc;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Identifies IRIs that an RDFC-1.0 signature binds exactly as written (#157). JSON-LD expansion in
/// dotNetRDF rewrites IRIs: it lowercases the scheme and host, drops a default port, decodes some
/// percent-escapes, removes dot segments (including encoded ones and trailing segments of invisible
/// characters) and trims whitespace. It drops an IRI .NET does not consider well formed (for example
/// one containing <c>[</c>, <c>]</c> or a second <c>#</c>). DataProofs 1.5.0 refuses to canonicalize
/// either case, so a signature never covers a respelled IRI. This check runs first, so a string the
/// verifier compares or keys on is refused with a specific outcome before any cryptography. Rather than
/// predict the canonicalizer, it asks it, and caches the answer per string.
/// </summary>
internal static class CanonicalIri
{
    internal const string RequirementMessage =
        "must be a well-formed absolute IRI exactly as the signature binds it (lowercase scheme and host, " +
        "no default port, dot segments, escaped unreserved or invisible characters)";

    internal const string BindableMessage =
        "must be a well-formed absolute IRI (for example, percent-encode [ and ]), because the signature " +
        "cannot bind any other value";

    internal const string TargetMessage =
        "must be a well-formed absolute IRI exactly as the signature binds it (no dot segments, encoded or " +
        "not; lowercase scheme and host; a path before any query; percent-encode [ and ])";

    private const string ProbePredicate = "urn:zcap-dotnet:iri-probe#value";
    private const int MaxCachedForms = 8192;

    private static readonly DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer Probe = new(RdfcContextDocumentLoader.Instance);
    private static readonly ConcurrentDictionary<string, string?> SignedForms = new(StringComparer.Ordinal);

    /// <summary>True when RDFC keeps <paramref name="value"/> in the signed graph (in some form).</summary>
    internal static bool IsBindable([NotNullWhen(true)] string? value)
        => !string.IsNullOrEmpty(value)
           && Uri.IsWellFormedUriString(value, UriKind.Absolute)
           && Uri.TryCreate(value, UriKind.Absolute, out var uri)
           && uri.IsWellFormedOriginalString();

    /// <summary>
    /// True for an id (revocation, replay and budget key) the signature binds exactly as written,
    /// both as a node and as a reference to one.
    /// </summary>
    internal static bool IsCanonical([NotNullWhen(true)] string? value)
        => IsBindable(value)
           && string.Equals(new Uri(value, UriKind.Absolute).AbsoluteUri, value, StringComparison.Ordinal)
           && string.Equals(SignedForm(value), value, StringComparison.Ordinal);

    /// <summary>
    /// True for an invocation target the signature binds as written. Unlike an id it need not equal
    /// <see cref="Uri.AbsoluteUri"/>: a bare authority (<c>https://example.com</c>) is signed as written.
    /// </summary>
    internal static bool IsSignedTarget([NotNullWhen(true)] string? value)
        => IsBindable(value) && string.Equals(SignedForm(value), value, StringComparison.Ordinal);

    /// <summary>The IRI RDFC signs for <paramref name="value"/> as subject and object, or null if those differ or it is refused.</summary>
    private static string? SignedForm(string value)
    {
        if (SignedForms.TryGetValue(value, out var cached))
            return cached;

        string? form = null;
        try
        {
            var document = JsonSerializer.SerializeToElement(new Dictionary<string, object>
            {
                ["@id"] = value,
                [ProbePredicate] = new Dictionary<string, string> { ["@id"] = value },
            });
            var nquads = Encoding.UTF8.GetString(Probe.CanonicalizeJsonLd(document));
            // Exactly one triple "<s> <p> <o> ." when the IRI survives in both positions.
            var middle = $"> <{ProbePredicate}> <";
            var split = nquads.IndexOf(middle, StringComparison.Ordinal);
            if (nquads.StartsWith('<') && nquads.EndsWith("> .\n", StringComparison.Ordinal) && split > 0 &&
                nquads.IndexOf('\n') == nquads.Length - 1 && !nquads.Contains('\\'))
            {
                var subject = nquads[1..split];
                var obj = nquads[(split + middle.Length)..^4];
                form = string.Equals(subject, obj, StringComparison.Ordinal) ? subject : null;
            }
        }
        catch (RdfCanonicalizationException)
        {
            form = null;
        }

        if (SignedForms.Count >= MaxCachedForms)
            SignedForms.Clear();
        SignedForms[value] = form;
        return form;
    }
}
