using System.Reflection;
using DataProofsDotnet.Rdfc;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// A DataProofs.Rdfc <see cref="IDocumentLoader"/> that serves ZCAP-LD's JSON-LD contexts
/// (<c>zcap/v1</c>, <c>ed25519-2020/v1</c>, zcap-dotnet's P-256 suite context (#159) and its
/// revocation context) from embedded assembly resources, delegating any other context to
/// DataProofs' <see cref="OfflineDocumentLoader"/>. Offline and fail-closed: no ambient network I/O
/// during signing or verification.
/// </summary>
/// <remarks>
/// Serving zcap's own embedded context bytes — the exact resources the canonicalizer used before
/// it was delegated to DataProofs.Rdfc — guarantees the RDFC-1.0 N-Quads remain byte-identical,
/// so previously-issued capabilities still verify. DataProofs' offline loader supplies the core
/// W3C contexts and fails closed on anything unknown.
/// </remarks>
internal sealed class RdfcContextDocumentLoader : IDocumentLoader
{
    /// <summary>A shared, immutable instance serving no caveat contexts.</summary>
    public static RdfcContextDocumentLoader Instance { get; } = new(null);

    private readonly CaveatTypeRegistry? _caveats;

    /// <summary>A loader that also serves the generated context of every registered caveat type (#157).</summary>
    public RdfcContextDocumentLoader(CaveatTypeRegistry? caveats) => _caveats = caveats;

    /// <summary>
    /// zcap-dotnet's own context for signed revocation requests. It defines the
    /// <c>capabilityRevocation</c> proof purpose and the <c>revocationReason</c> /
    /// <c>revocationMetadata</c> proof extensions, which no published context defines, so that RDFC
    /// signs them instead of refusing (DataProofs 1.5.0) or dropping (earlier) them. It is never on the
    /// wire: <see cref="LegacyProofCrypto.EnvelopeContext"/> adds it to a revocation request.
    /// </summary>
    internal const string RevocationContextUrl = "urn:zcap-dotnet:revocation-context:v1";

    // Context URL → embedded resource name, keyed ordinally on Uri.AbsoluteUri. System.Uri has already
    // normalized the lookup key (scheme case, surrounding whitespace, percent-encoded unreserved
    // characters), so a few spellings of a URL map to one resource; the bytes served are the same, and
    // the profile admits only the exact spelling on a capability. The suite entries come from the
    // catalog (#159), so a suite the catalog advertises is always one this loader serves.
    private static readonly IReadOnlyDictionary<string, string> ResourceByUrl = BuildResourceMap();

    private static Dictionary<string, string> BuildResourceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ZcapSuiteCatalog.ZcapContextUrl] = "ZcapLd.Core.Cryptography.Contexts.zcap-v1.jsonld",
            [RevocationContextUrl] = "ZcapLd.Core.Cryptography.Contexts.zcap-dotnet-revocation-v1.jsonld",
        };
        foreach (var suite in ZcapSuiteCatalog.Suites)
            map.Add(suite.ContextUrl, suite.ContextResource);
        return map;
    }

    private static readonly Assembly ResourceAssembly = typeof(RdfcContextDocumentLoader).Assembly;

    /// <inheritdoc />
    public LoadedContextDocument Load(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);

        if (_caveats is not null && _caveats.TryGetByContextUrl(url.AbsoluteUri, out var caveat))
        {
            return new LoadedContextDocument(url, caveat.ContextDocument);
        }

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
