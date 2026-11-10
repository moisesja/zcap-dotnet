using System.Diagnostics.CodeAnalysis;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
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
/// - <c>TypeInfoResolver</c>: zcap's own types resolve through source-generated metadata
///   (<c>ZcapJsonContext</c>), so the library serializes identical bytes under native AOT, trimming
///   and .NET 10 file-based apps, where reflection-based serialization is disabled (#154). When
///   <see cref="JsonSerializer.IsReflectionEnabledByDefault"/> is true (every JIT application that has
///   not opted out) a reflection resolver is combined after it, so a consumer who serializes its own
///   types with these options sees no change; otherwise the generated context is the only resolver and
///   an unlisted type fails with <see cref="NotSupportedException"/>.
/// </summary>
public static class ZcapJsonOptions
{
    /// <summary>
    /// Pre-configured options used everywhere capabilities, invocations, or
    /// proofs cross the signing boundary.
    /// </summary>
    public static JsonSerializerOptions Default { get; } = CreateDefault();

    /// <summary>
    /// Metadata for <typeparamref name="T"/> bound to <see cref="Default"/>, for the
    /// <see cref="JsonTypeInfo{T}"/> serializer overloads (#154). Always resolve through here rather
    /// than through <c>ZcapJsonContext.Default</c>'s own properties: those bind to the context's options,
    /// whose default encoder escapes <c>+&lt;&gt;&amp;'</c> and would change the signed bytes.
    /// </summary>
    internal static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Default.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions CreateDefault()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            // Fail closed on a duplicate object key rather than silently taking the last value. A
            // last-wins parse lets a hostile or buggy producer ship a body that zcap and a
            // strict-RFC-8785 / first-wins peer canonicalize or authorize differently. Rejecting the
            // ambiguous body removes that cross-stack disagreement surface entirely.
            AllowDuplicateProperties = false,
            TypeInfoResolver = JsonSerializer.IsReflectionEnabledByDefault
                ? CombineWithReflection()
                : ZcapJsonContext.Default
        };
        return options;
    }

    // Only reached when the reflection feature switch is on, so the trimmer removes this branch (and
    // its warnings' subject) from a trimmed or AOT application; the same pattern guards the runtime's
    // own JsonSerializerOptions.Default. Generated metadata wins for zcap's types; reflection serves
    // the consumer's own types only.
    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "Guarded by JsonSerializer.IsReflectionEnabledByDefault, a feature switch the trimmer evaluates; the branch is dead when reflection-based serialization is disabled.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "Guarded by JsonSerializer.IsReflectionEnabledByDefault, a feature switch the trimmer evaluates; the branch is dead when reflection-based serialization is disabled.")]
    private static IJsonTypeInfoResolver CombineWithReflection()
        => JsonTypeInfoResolver.Combine(ZcapJsonContext.Default, new DefaultJsonTypeInfoResolver());
}
