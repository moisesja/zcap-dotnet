using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.Rdfc;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Identifies IRIs that an RDFC-1.0 signature binds exactly as written (#157). JSON-LD expansion in
/// dotNetRDF rewrites IRIs before they are signed: it lowercases the scheme and host, drops a default
/// port, decodes some percent-escapes, removes dot segments (including encoded ones and trailing
/// segments of invisible characters) and trims whitespace. It silently drops an IRI .NET does not
/// consider well formed (for example one containing <c>[</c>, <c>]</c> or a second <c>#</c>): as a
/// subject the whole node, as a value the triple. A string the verifier compares or keys on is
/// therefore trusted only when it is exactly the form the signature binds. Rather than predict that
/// form, this asks the same canonicalizer and caches the answer per string.
/// </summary>
internal static class CanonicalIri
{
    internal const string RequirementMessage =
        "must be a well-formed absolute IRI exactly as the signature binds it (lowercase scheme and host, " +
        "no default port, dot segments, escaped unreserved or invisible characters)";

    internal const string BindableMessage =
        "must be a well-formed absolute IRI (for example, percent-encode [ and ]), because the signature " +
        "silently omits any other value";

    internal const string TargetMessage =
        "must be a well-formed absolute IRI exactly as the signature binds it (no dot segments, encoded or " +
        "not; lowercase scheme and host; percent-encode [ and ])";

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
    /// True for an invocation target the signature binds as written. The one tolerated rewrite is the
    /// root <c>/</c> RDF adds to a bare authority (<c>https://example.com</c>), which names the same resource.
    /// </summary>
    internal static bool IsSignedTarget([NotNullWhen(true)] string? value)
    {
        if (!IsBindable(value) || SignedForm(value) is not { } signed)
            return false;
        if (string.Equals(signed, value, StringComparison.Ordinal))
            return true;

        var authority = value.IndexOf("://", StringComparison.Ordinal);
        if (authority < 0)
            return false;
        var pathStart = value.IndexOfAny(new[] { '/', '?', '#' }, authority + 3);
        if (pathStart >= 0 && value[pathStart] == '/')
            return false;
        var withRoot = pathStart < 0 ? value + "/" : value.Insert(pathStart, "/");
        return string.Equals(signed, withRoot, StringComparison.Ordinal);
    }

    /// <summary>The IRI RDFC signs for <paramref name="value"/> as subject and object, or null if those differ or it is dropped.</summary>
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
