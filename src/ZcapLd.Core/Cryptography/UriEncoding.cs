namespace ZcapLd.Core.Cryptography;

/// <summary>
/// URI helpers for ZCAP-LD wire interop. The root capability id is
/// <c>urn:zcap:root:{encodeURIComponent(invocationTarget)}</c> per spec, and the reference
/// implementation (<c>@digitalbazaar/zcap</c>) derives it with JavaScript <c>encodeURIComponent</c>,
/// which leaves <c>! ' ( ) *</c> unescaped. .NET's <see cref="Uri.EscapeDataString"/> escapes those
/// five (to <c>%21 %27 %28 %29 %2A</c>), so a target containing them would yield a root id the
/// reference impl never produces — breaking <c>capabilityChain[0]</c> / root-dereference string
/// equality. <see cref="EncodeUriComponent"/> matches <c>encodeURIComponent</c> exactly.
/// </summary>
internal static class UriEncoding
{
    /// <summary>
    /// Percent-encodes <paramref name="value"/> identically to JavaScript <c>encodeURIComponent</c>:
    /// run <see cref="Uri.EscapeDataString"/>, then un-escape the five sequences .NET over-escapes
    /// (<c>%21 %27 %28 %29 %2A</c> → <c>! ' ( ) *</c>). <c>~</c> is already left literal by both, and
    /// <see cref="Uri.EscapeDataString"/> always emits uppercase hex, so the ordinal replacements are
    /// exhaustive.
    /// </summary>
    public static string EncodeUriComponent(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Uri.EscapeDataString(value)
            .Replace("%21", "!", StringComparison.Ordinal)
            .Replace("%27", "'", StringComparison.Ordinal)
            .Replace("%28", "(", StringComparison.Ordinal)
            .Replace("%29", ")", StringComparison.Ordinal)
            .Replace("%2A", "*", StringComparison.Ordinal);
    }
}
