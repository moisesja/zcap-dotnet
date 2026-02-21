using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Routes DID operations to the appropriate sub-provider based on registration.
/// Use this when different DIDs are managed by different backends (e.g. did:key in-memory,
/// did:web via Azure Key Vault).
/// </summary>
public class CompositeDidProvider : IDidProvider
{
    private readonly List<(Func<string, bool> CanHandle, IDidProvider Provider)> _providers = new();

    /// <summary>
    /// Registers a provider for DIDs matching a method prefix (e.g. "did:key:", "did:web:").
    /// Providers are evaluated in registration order; first match wins.
    /// </summary>
    public void Register(string didMethodPrefix, IDidProvider provider)
    {
        if (string.IsNullOrEmpty(didMethodPrefix))
            throw new ArgumentException("DID method prefix cannot be null or empty", nameof(didMethodPrefix));
        ArgumentNullException.ThrowIfNull(provider);

        _providers.Add((did => did.StartsWith(didMethodPrefix, StringComparison.Ordinal), provider));
    }

    /// <summary>
    /// Registers a provider with a custom predicate for matching DIDs.
    /// Providers are evaluated in registration order; first match wins.
    /// </summary>
    public void Register(Func<string, bool> canHandle, IDidProvider provider)
    {
        ArgumentNullException.ThrowIfNull(canHandle);
        ArgumentNullException.ThrowIfNull(provider);

        _providers.Add((canHandle, provider));
    }

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        return Resolve(did).SignAsync(did, data);
    }

    public Task<byte[]> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        return Resolve(baseDid).ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        return Resolve(did).GetVerificationMethodAsync(did);
    }

    private IDidProvider Resolve(string did)
    {
        foreach (var (canHandle, provider) in _providers)
        {
            if (canHandle(did))
                return provider;
        }

        throw new InvalidOperationException(
            $"No IDidProvider registered that can handle DID: {did}. " +
            $"Register a provider using Register(prefix, provider) or Register(predicate, provider).");
    }
}
