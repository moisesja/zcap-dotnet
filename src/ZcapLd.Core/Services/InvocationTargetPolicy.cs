namespace ZcapLd.Core.Services;

/// <summary>Shared lexical target attenuation; endpoint semantics remain application-owned.</summary>
internal static class InvocationTargetPolicy
{
    internal static bool IsValid(string invocationTarget, string capabilityTarget, bool allowAttenuation)
    {
        if (string.IsNullOrEmpty(invocationTarget) || string.IsNullOrEmpty(capabilityTarget))
            return false;

        // Exact match is always valid
        if (invocationTarget == capabilityTarget)
            return true;

        if (!allowAttenuation) return false;

        // Check if invocationTarget is a valid prefix extension.
        // Ordinal comparison keeps this consistent with the ordinal Substring index math
        // below (and the ordinal `==`/char checks around it); a culture-sensitive overload
        // can treat ignorable Unicode code points as zero-width, disagreeing on length and
        // throwing ArgumentOutOfRangeException in the subsequent Substring (Issue #74).
        if (invocationTarget.StartsWith(capabilityTarget, StringComparison.Ordinal))
        {
            var suffix = invocationTarget.Substring(capabilityTarget.Length);

            // Suffix must start with appropriate delimiter
            if (suffix.Length == 0)
                return true; // Exact match (edge case)

            // Reject a path-traversal ("..") segment in the extension. Lexical prefix matching is
            // spec-correct, but if a downstream resource server resolves/normalizes dot-segments
            // (or normalizes differently than this verifier) a target like ".../a/../../secret" could
            // escape the capability's intended subtree. Safer-by-default at the authorization boundary
            // (Issue #74 follow-up); only the path portion is inspected, so ".." inside a query is fine.
            if (SuffixHasDotSegment(suffix))
                return false;

            // If capability target has no query string, suffix must start with / or ?
            if (!capabilityTarget.Contains('?'))
            {
                return suffix.StartsWith('/') || suffix.StartsWith('?');
            }

            // If capability target has query string, suffix must start with &
            return suffix.StartsWith('&');
        }

        return false;
    }

    private static readonly char[] QueryOrFragmentChars = { '?', '#' };

    /// <summary>
    /// True if the path portion of a target suffix contains a <c>..</c> path segment (a complete
    /// segment, not a substring like <c>a..b</c>). Anything from the first <c>?</c> or <c>#</c>
    /// onward is treated as query/fragment and ignored.
    /// </summary>
    private static bool SuffixHasDotSegment(string suffix)
    {
        var queryStart = suffix.IndexOfAny(QueryOrFragmentChars);
        var path = queryStart >= 0 ? suffix.Substring(0, queryStart) : suffix;
        foreach (var segment in path.Split('/'))
        {
            if (segment == "..")
                return true;
        }

        return false;
    }

}
