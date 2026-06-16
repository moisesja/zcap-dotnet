using System.Globalization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Helpers for formatting and parsing ZCAP-LD timestamp strings (`Proof.Created`, `Capability.Expires`).
///
/// Timestamps are stored as opaque on-the-wire strings to preserve byte equivalence with whatever
/// language signed the document. Cross-stack JCS verification depends on this — every other Data
/// Integrity verifier (zcap-py, JS, Rust) JCS-canonicalizes the timestamp string verbatim, so any
/// re-serialization at canonicalization time would diverge.
///
/// `Format` writes 6-digit microsecond ISO-8601 UTC (`yyyy-MM-ddTHH:mm:ss.ffffffZ`); `Parse` accepts
/// any ISO-8601-shaped value and returns a UTC `DateTime`.
/// </summary>
public static class ZcapTimestamps
{
    /// <summary>
    /// Canonical format used when zcap-dotnet generates a fresh timestamp.
    /// 6-digit microsecond precision aligns with the broader Data Integrity ecosystem.
    /// </summary>
    public const string CanonicalFormat = "yyyy-MM-ddTHH:mm:ss.ffffffZ";

    /// <summary>
    /// Formats a DateTime as a canonical ISO-8601 UTC string with microsecond precision.
    /// Local-kind values are first converted to UTC.
    /// </summary>
    public static string Format(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return utc.ToString(CanonicalFormat, CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Same as <see cref="Format"/> but returns null when the input is null.
    /// </summary>
    public static string? FormatOrNull(DateTime? value) => value.HasValue ? Format(value.Value) : null;

    /// <summary>
    /// Parses any ISO-8601-shaped timestamp into a UTC <see cref="DateTime"/>.
    /// Strings with a timezone offset are converted to UTC; strings <em>without</em> an offset are
    /// treated as UTC (<see cref="DateTimeStyles.AssumeUniversal"/>) — NOT in the verifier's local
    /// timezone. Without this, an offsetless <c>expires</c>/<c>created</c> from a cross-stack signer
    /// (zcap-py/JS/Rust may emit one — ISO-8601 permits omitting the offset) would be read in the
    /// host timezone, so two verifiers in different zones would disagree on expiry/freshness by up to
    /// ~26 hours. Throws <see cref="FormatException"/> on an unparseable value (callers that must not
    /// throw use <see cref="ParseOrNull"/>).
    /// </summary>
    public static DateTime Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, AssumeUtcStyles).UtcDateTime;

    /// <summary>
    /// Total counterpart of <see cref="Parse"/>: returns null when the input is null/empty
    /// <em>or unparseable</em> (never throws), so the parsed <c>expires</c>/<c>created</c> views on
    /// the models are total functions. Offsetless values are still treated as UTC.
    /// </summary>
    public static DateTime? ParseOrNull(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return null;

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, AssumeUtcStyles, out var parsed)
            ? parsed.UtcDateTime
            : null;
    }

    /// <summary>
    /// Treat an offsetless timestamp as UTC (not local) and normalize any present offset to UTC.
    /// </summary>
    private const DateTimeStyles AssumeUtcStyles =
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
}
