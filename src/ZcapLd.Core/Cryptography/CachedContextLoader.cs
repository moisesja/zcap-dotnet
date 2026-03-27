using System.Reflection;
using VDS.RDF.JsonLd;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Serves known W3C JSON-LD contexts from embedded assembly resources,
/// avoiding HTTP fetches in restricted/offline environments.
/// Falls back to the default HTTP loader for unknown context URIs.
/// </summary>
internal static class CachedContextLoader
{
    private static readonly Dictionary<string, string> EmbeddedContexts;

    static CachedContextLoader()
    {
        var assembly = typeof(CachedContextLoader).Assembly;

        // Map: context URL → embedded resource name
        var mapping = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["https://w3id.org/zcap/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.zcap-v1.jsonld",
            ["https://w3id.org/security/suites/ed25519-2020/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.ed25519-2020-v1.jsonld",
        };

        EmbeddedContexts = new Dictionary<string, string>(mapping.Count, StringComparer.Ordinal);

        foreach (var (url, resourceName) in mapping)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException(
                    $"Embedded JSON-LD context resource '{resourceName}' not found in assembly.");

            using var reader = new StreamReader(stream);
            EmbeddedContexts[url] = reader.ReadToEnd();
        }
    }

    /// <summary>
    /// Document loader callback for <see cref="JsonLdProcessorOptions.DocumentLoader"/>.
    /// Returns cached embedded contexts for known URLs, falls back to HTTP for others.
    /// </summary>
    public static RemoteDocument LoadDocument(Uri uri, JsonLdLoaderOptions options)
    {
        if (EmbeddedContexts.TryGetValue(uri.AbsoluteUri, out var cachedJson))
        {
            return new RemoteDocument
            {
                Document = Newtonsoft.Json.Linq.JToken.Parse(cachedJson),
                DocumentUrl = uri
            };
        }

        // Fallback: HTTP fetch for unknown contexts
        return DefaultDocumentLoader.LoadJson(uri, options);
    }
}
