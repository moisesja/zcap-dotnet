using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Resolves did:key DIDs to their public keys and verification method URIs.
/// Stateless and secret-free — the public key is encoded directly in the DID string.
///
/// Supports any key type registered in the <see cref="ICryptoSuiteProvider"/>
/// (e.g. Ed25519, P-256, secp256k1) via multicodec prefix matching.
/// </summary>
public class DidKeyResolver : IDidResolver
{
    private readonly ICryptoSuiteProvider _suiteProvider;

    /// <summary>
    /// Creates a DidKeyResolver that can decode any key type registered in the suite provider.
    /// </summary>
    public DidKeyResolver(ICryptoSuiteProvider suiteProvider)
    {
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
    }

    /// <summary>
    /// Creates a DidKeyResolver with Ed25519 support only (backward-compatible default).
    /// </summary>
    public DidKeyResolver() : this(CreateDefaultProvider()) { }

    /// <summary>
    /// Resolves a did:key DID or verification method URI to its public key material.
    /// </summary>
    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        if (!didOrVerificationMethod.StartsWith("did:key:"))
        {
            throw new CapabilityValidationException(
                $"DidKeyResolver only handles did:key DIDs, got: {didOrVerificationMethod}");
        }

        var keyPart = didOrVerificationMethod.Replace("did:key:", "").Split('#')[0];

        if (!keyPart.StartsWith('z'))
        {
            throw new CapabilityValidationException(
                $"Invalid did:key format (must start with 'z'): {didOrVerificationMethod}");
        }

        try
        {
            var decoded = Ed25519Signer.DecodeSignature(keyPart);

            // Look up suite by multicodec prefix
            var suite = _suiteProvider.GetByMulticodecPrefix(decoded);
            if (suite != null)
            {
                var prefixLength = suite.MulticodecPrefix.Length;
                var expectedTotal = prefixLength + suite.PublicKeyLength;

                if (decoded.Length >= expectedTotal)
                {
                    var publicKeyBytes = decoded.AsSpan(prefixLength, suite.PublicKeyLength).ToArray();
                    return Task.FromResult(new ResolvedKey(publicKeyBytes, suite.KeyType));
                }
            }

            throw new CapabilityValidationException(
                $"Unrecognized multicodec prefix or invalid key length in: {didOrVerificationMethod}");
        }
        catch (CapabilityValidationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new CapabilityValidationException(
                $"Failed to decode did:key public key: {didOrVerificationMethod}", ex);
        }
    }

    /// <summary>
    /// Gets the verification method URI for a did:key DID.
    /// Format: did:key:{multibase-key}#{multibase-key}
    /// </summary>
    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        if (!did.StartsWith("did:key:"))
        {
            throw new CapabilityValidationException(
                $"DidKeyResolver only handles did:key DIDs, got: {did}");
        }

        var keyId = did["did:key:".Length..];
        return Task.FromResult($"{did}#{keyId}");
    }

    private static ICryptoSuiteProvider CreateDefaultProvider()
    {
        var provider = new CryptoSuiteProvider();
        provider.Register(new Ed25519CryptoSuite());
        return provider;
    }
}
