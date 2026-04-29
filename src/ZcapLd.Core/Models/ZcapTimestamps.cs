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
    /// Strings with a timezone offset are converted to UTC; strings without are treated as UTC.
    /// </summary>
    public static DateTime Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture).UtcDateTime;

    /// <summary>
    /// Same as <see cref="Parse"/> but returns null when the input is null/empty.
    /// </summary>
    public static DateTime? ParseOrNull(string? value) =>
        string.IsNullOrEmpty(value) ? null : Parse(value);
}
