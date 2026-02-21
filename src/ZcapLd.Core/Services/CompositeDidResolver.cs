using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Routes DID resolution operations to the appropriate sub-resolver based on registration.
/// Use this when different DID methods are resolved by different backends (e.g. did:key locally,
/// did:web via a universal resolver endpoint).
/// </summary>
public class CompositeDidResolver : IDidResolver
{
    private readonly List<(Func<string, bool> CanHandle, IDidResolver Resolver)> _resolvers = new();

    /// <summary>
    /// Registers a resolver for DIDs matching a method prefix (e.g. "did:key:", "did:web:").
    /// Resolvers are evaluated in registration order; first match wins.
    /// </summary>
    public void Register(string didMethodPrefix, IDidResolver resolver)
    {
        if (string.IsNullOrEmpty(didMethodPrefix))
            throw new ArgumentException("DID method prefix cannot be null or empty", nameof(didMethodPrefix));
        ArgumentNullException.ThrowIfNull(resolver);

        _resolvers.Add((did => did.StartsWith(didMethodPrefix, StringComparison.Ordinal), resolver));
    }

    /// <summary>
    /// Registers a resolver with a custom predicate for matching DIDs.
    /// Resolvers are evaluated in registration order; first match wins.
    /// </summary>
    public void Register(Func<string, bool> canHandle, IDidResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(canHandle);
        ArgumentNullException.ThrowIfNull(resolver);

        _resolvers.Add((canHandle, resolver));
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        return Resolve(baseDid).ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        return Resolve(did).GetVerificationMethodAsync(did);
    }

    private IDidResolver Resolve(string did)
    {
        foreach (var (canHandle, resolver) in _resolvers)
        {
            if (canHandle(did))
                return resolver;
        }

        throw new InvalidOperationException(
            $"No IDidResolver registered that can handle DID: {did}. " +
            $"Register a resolver using Register(prefix, resolver) or Register(predicate, resolver).");
    }
}
