using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Single source of truth for the <see cref="JsonSerializerOptions"/> that
/// governs both sign-time JCS canonicalization and verifier-time chain
/// deserialization. Sharing one options instance means the bytes signed equal
/// the bytes seen by any other Data Integrity verifier that re-canonicalizes
/// the wire body — that is the contract Issues #34, #37, and #39 collectively
/// pin down.
///
/// Settings rationale:
/// - <c>WriteIndented = false</c>: JCS is whitespace-free.
/// - <c>DefaultIgnoreCondition = WhenWritingNull</c>: drops absent optional
///   fields so strict cross-language parsers (zcap-py and friends) accept the
///   wire body. See #37.
    /// - <c>UnsafeRelaxedJsonEscaping</c>: RFC 8785 §3.2.2.2 mandates only
    ///   quotation marks, backslashes, and control characters be escaped. The
    ///   default <c>JavaScriptEncoder</c> escapes plus signs, angle brackets,
    ///   ampersands, and apostrophes to Unicode escape sequences, which diverges from peer
///   canonicalizers. See #36.
/// - <see cref="CaveatJsonConverter"/>: makes <see cref="Caveat"/> arrays
///   round-trip through their derived classes' fields. See #39.
/// </summary>
public static class ZcapJsonOptions
{
    /// <summary>
    /// Pre-configured options used everywhere capabilities, invocations, or
    /// proofs cross the signing boundary. The caveat converter resolves
    /// against <see cref="CaveatTypeRegistry.Default"/>, so consumers can
    /// register custom caveat types at startup without rebuilding options.
    /// </summary>
    public static JsonSerializerOptions Default { get; } = CreateDefault();

    private static JsonSerializerOptions CreateDefault()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        options.Converters.Add(new CaveatJsonConverter(CaveatTypeRegistry.Default));
        return options;
    }
}
