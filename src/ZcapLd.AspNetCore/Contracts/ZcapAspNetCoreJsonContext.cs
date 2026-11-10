using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.AspNetCore.Contracts;

/// <summary>
/// Source-generated serializer metadata for the adapter's two HTTP contract types (#154), so the
/// revocation endpoint reads its request body and writes its response without reflection under native
/// AOT, trimming and .NET 10 file-based apps. The generation options mirror
/// <see cref="ZcapJsonOptions.Default"/>; the encoder cannot be declared here and lives on
/// <see cref="ZcapAspNetCoreJsonOptions.Default"/>.
/// <para>
/// The contract types embed <c>Capability</c> and <c>Invocation</c>, so the generator also emits
/// metadata for those here; it is never used. <see cref="ZcapAspNetCoreJsonOptions.Default"/> places
/// Core's context first, so every Core model resolves through Core's generated context (the single
/// source of truth for the signed wire shape) and this context only ever serves the two contract types.
/// </para>
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    AllowDuplicateProperties = false,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(SignedRevocationHttpRequest))]
[JsonSerializable(typeof(RevocationStatusHttpResponse))]
internal sealed partial class ZcapAspNetCoreJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The <see cref="JsonSerializerOptions"/> the revocation endpoint deserializes and responds with:
/// <see cref="ZcapJsonOptions.Default"/>'s settings (encoder, null omission, duplicate-key rejection)
/// with the resolver chain Core's generated context, then <see cref="ZcapAspNetCoreJsonContext"/>,
/// then the reflection resolver only where <see cref="JsonSerializer.IsReflectionEnabledByDefault"/>.
/// Core's context therefore owns every Core model, and the adapter's context serves
/// <see cref="SignedRevocationHttpRequest"/> and <see cref="RevocationStatusHttpResponse"/> in a JIT
/// and a native AOT application alike.
/// </summary>
internal static class ZcapAspNetCoreJsonOptions
{
    /// <summary>Read-only options for the adapter's HTTP boundary.</summary>
    public static JsonSerializerOptions Default { get; } = Create();

    /// <summary>Metadata for the request body, bound to <see cref="Default"/>.</summary>
    public static JsonTypeInfo<SignedRevocationHttpRequest> Request { get; } =
        (JsonTypeInfo<SignedRevocationHttpRequest>)Default.GetTypeInfo(typeof(SignedRevocationHttpRequest));

    /// <summary>Metadata for the response body, bound to <see cref="Default"/>.</summary>
    public static JsonTypeInfo<RevocationStatusHttpResponse> Response { get; } =
        (JsonTypeInfo<RevocationStatusHttpResponse>)Default.GetTypeInfo(typeof(RevocationStatusHttpResponse));

    /// <summary>Metadata for a <c>string</c> body (the 400 messages), bound to <see cref="Default"/>.</summary>
    public static JsonTypeInfo<string> Text { get; } = (JsonTypeInfo<string>)Default.GetTypeInfo(typeof(string));

    private static JsonSerializerOptions Create()
    {
        // The copy carries Core's chain: its generated context, followed by the reflection resolver
        // when JsonSerializer.IsReflectionEnabledByDefault. The adapter's context goes right after Core's
        // context, not at the end: the reflection resolver answers for every type, so appended last the
        // adapter's context would only ever be consulted under native AOT.
        var options = new JsonSerializerOptions(ZcapJsonOptions.Default);
        var chain = options.TypeInfoResolverChain;
        chain.Insert(chain.IndexOf(ZcapJsonContext.Default) + 1, ZcapAspNetCoreJsonContext.Default);
        options.MakeReadOnly();
        return options;
    }
}
