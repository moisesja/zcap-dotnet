using System.Collections.Concurrent;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// In-memory <see cref="IRootCapabilityResolver"/> for development and testing: registered root
/// capabilities are held in a process-local dictionary keyed by id. Mirrors
/// <see cref="InMemoryRevocationStore"/> — convenient for a single node, but NOT durable or shared
/// across processes. For production, implement <see cref="IRootCapabilityResolver"/> over your own
/// root-capability store (the resource owner inherently knows the roots it issues).
/// </summary>
public sealed class InMemoryRootCapabilityResolver : IRootCapabilityResolver
{
    private readonly ConcurrentDictionary<string, Capability> _roots = new(StringComparer.Ordinal);

    /// <summary>
    /// Registers (or replaces) a root capability so it can later be resolved by its id. Returns the
    /// same capability for fluent use.
    /// </summary>
    public Capability Register(Capability root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (string.IsNullOrEmpty(root.Id))
            throw new ArgumentException("Root capability must have a non-empty id.", nameof(root));
        _roots[root.Id] = root;
        return root;
    }

    /// <inheritdoc />
    public Task<Capability?> ResolveRootAsync(string rootCapabilityId)
    {
        if (string.IsNullOrEmpty(rootCapabilityId))
            return Task.FromResult<Capability?>(null);

        return Task.FromResult(_roots.TryGetValue(rootCapabilityId, out var root) ? root : null);
    }
}
