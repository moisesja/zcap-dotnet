using System.Reflection;
using DataProofsDotnet.Rdfc;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// A DataProofs.Rdfc <see cref="IDocumentLoader"/> that serves ZCAP-LD's JSON-LD contexts
/// (<c>zcap/v1</c>, <c>ed25519-2020/v1</c>) from embedded assembly resources, delegating any
/// other context to DataProofs' <see cref="OfflineDocumentLoader"/>. Offline and fail-closed:
/// no ambient network I/O during signing or verification.
/// </summary>
/// <remarks>
/// Serving zcap's own embedded context bytes — the exact resources the canonicalizer used before
/// it was delegated to DataProofs.Rdfc — guarantees the RDFC-1.0 N-Quads remain byte-identical,
/// so previously-issued capabilities still verify. DataProofs' offline loader supplies the core
/// W3C contexts and fails closed on anything unknown.
/// </remarks>
internal sealed class RdfcContextDocumentLoader : IDocumentLoader
{
    /// <summary>A shared, immutable instance (loading is stateless).</summary>
    public static RdfcContextDocumentLoader Instance { get; } = new();

    // Context URL → embedded resource name. Ordinal keying so URL matching is exact.
    private static readonly IReadOnlyDictionary<string, string> ResourceByUrl =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["https://w3id.org/zcap/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.zcap-v1.jsonld",
            ["https://w3id.org/security/suites/ed25519-2020/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.ed25519-2020-v1.jsonld",
        };

    private static readonly Assembly ResourceAssembly = typeof(RdfcContextDocumentLoader).Assembly;

    /// <inheritdoc />
    public LoadedContextDocument Load(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);

        if (ResourceByUrl.TryGetValue(url.AbsoluteUri, out var resourceName))
        {
            using var stream = ResourceAssembly.GetManifestResourceStream(resourceName)
                ?? throw new RdfCanonicalizationException(
                    $"The embedded ZCAP context resource for '{url.AbsoluteUri}' is missing from the assembly.");
            using var reader = new StreamReader(stream);
            return new LoadedContextDocument(url, reader.ReadToEnd());
        }

        // Core W3C contexts (and fail-closed on anything unknown) via DataProofs' offline loader.
        return OfflineDocumentLoader.Instance.Load(url);
    }
}
