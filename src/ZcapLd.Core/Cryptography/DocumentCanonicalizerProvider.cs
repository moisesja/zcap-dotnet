using System.Collections.Concurrent;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Default implementation of <see cref="IDocumentCanonicalizerProvider"/>.
/// Thread-safe dictionary-backed registry.
/// </summary>
public class DocumentCanonicalizerProvider : IDocumentCanonicalizerProvider
{
    private readonly ConcurrentDictionary<string, IDocumentCanonicalizer> _byMethod = new(StringComparer.Ordinal);

    /// <summary>
    /// Registers a canonicalizer. Replaces any existing entry with the same method.
    /// </summary>
    public void Register(IDocumentCanonicalizer canonicalizer)
    {
        ArgumentNullException.ThrowIfNull(canonicalizer);
        _byMethod[canonicalizer.Method] = canonicalizer;
    }

    public IDocumentCanonicalizer? GetByMethod(string method)
    {
        if (string.IsNullOrEmpty(method))
            return null;

        _byMethod.TryGetValue(method, out var canonicalizer);
        return canonicalizer;
    }
}
