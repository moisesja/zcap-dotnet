using NetDid.Core.Model;
using NetDid.Core.Resolution;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Minimal NetDid <see cref="NetDid.Core.IDidResolver"/> backed by a fixed map of DID → document,
/// so the real <see cref="DefaultVerificationRelationshipResolver"/> can be exercised over hand-built
/// controller documents without any network access.
/// </summary>
internal sealed class StaticDidDocumentResolver : NetDid.Core.IDidResolver
{
    private readonly Dictionary<string, DidDocument> _docs;

    public StaticDidDocumentResolver(params (string Did, DidDocument Document)[] docs) =>
        _docs = docs.ToDictionary(d => d.Did, d => d.Document, StringComparer.Ordinal);

    public bool CanResolve(string did) => _docs.ContainsKey(did);

    public Task<DidResolutionResult> ResolveAsync(
        string did, DidResolutionOptions? options = null, CancellationToken ct = default) =>
        Task.FromResult(_docs.TryGetValue(did, out var doc)
            ? new DidResolutionResult { DidDocument = doc, ResolutionMetadata = new DidResolutionMetadata() }
            : DidResolutionResult.NotFound(did));
}
