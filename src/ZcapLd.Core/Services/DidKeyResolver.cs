using NetCid;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Key;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Resolves did:key DIDs to their public keys and verification method URIs.
/// Delegates to NetDid's <see cref="DidKeyMethod"/> for DID document resolution
/// and adapts the result to ZcapLd's <see cref="IDidResolver"/> interface.
///
/// Also implements <see cref="IVerificationRelationshipResolver"/> so the verifier can authorize
/// a controller's verification method against the controller's resolved did:key document
/// (capabilityInvocation / capabilityDelegation) without separate wiring — Issue #65.
/// </summary>
public class DidKeyResolver : IDidResolver, IVerificationRelationshipResolver
{
    private readonly DidKeyMethod _didKeyMethod;
    private readonly IVerificationRelationshipResolver _relationshipResolver;

    /// <summary>
    /// Creates a DidKeyResolver with default NetDid key generator support.
    /// </summary>
    public DidKeyResolver()
        : this(new DidKeyMethod(new DefaultKeyGenerator()))
    {
    }

    /// <summary>
    /// Creates a DidKeyResolver wrapping an existing <see cref="DidKeyMethod"/> instance.
    /// </summary>
    public DidKeyResolver(DidKeyMethod didKeyMethod)
    {
        _didKeyMethod = didKeyMethod ?? throw new ArgumentNullException(nameof(didKeyMethod));
        _relationshipResolver = new DefaultVerificationRelationshipResolver(_didKeyMethod);
    }

    /// <inheritdoc />
    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default) =>
        _relationshipResolver.IsAuthorizedForRelationshipAsync(
            controllerDid, verificationMethodDidUrl, relationship, ct);

    /// <summary>
    /// Resolves a did:key DID or verification method URI to its public key material.
    /// </summary>
    public async Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        if (!didOrVerificationMethod.StartsWith("did:key:"))
        {
            throw new CapabilityValidationException(
                $"DidKeyResolver only handles did:key DIDs, got: {didOrVerificationMethod}");
        }

        var baseDid = didOrVerificationMethod.Split('#')[0];

        try
        {
            var result = await _didKeyMethod.ResolveAsync(baseDid);

            if (result.DidDocument == null || result.ResolutionMetadata.Error != null)
            {
                throw new CapabilityValidationException(
                    $"Failed to resolve did:key: {didOrVerificationMethod}");
            }

            var verificationMethods = result.DidDocument.VerificationMethod;
            if (verificationMethods == null || !verificationMethods.Any())
            {
                throw new CapabilityValidationException(
                    $"No verification method found in resolved DID document: {didOrVerificationMethod}");
            }

            // If the caller named a specific verification method by #fragment, honour it: select
            // the method whose Id equals the full URI, then fall back to a fragment match — rather
            // than always returning the first method (Issue #67). An Ed25519 did:key resolves to
            // two methods (the Ed25519 signing key at index 0 and a derived X25519 key-agreement
            // key at index 1), so FirstOrDefault() returned the wrong key for a non-index-0
            // fragment. Throw if the named fragment matches no method, rather than silently
            // substituting the first.
            var hashIndex = didOrVerificationMethod.IndexOf('#');
            var vm = hashIndex < 0
                ? verificationMethods.First()
                : verificationMethods.FirstOrDefault(m =>
                      string.Equals(m.Id, didOrVerificationMethod, StringComparison.Ordinal))
                  ?? verificationMethods.FirstOrDefault(m =>
                      string.Equals(FragmentOf(m.Id), didOrVerificationMethod[(hashIndex + 1)..], StringComparison.Ordinal));

            if (vm == null)
            {
                throw new CapabilityValidationException(
                    $"No verification method matching '{didOrVerificationMethod}' in resolved DID document.");
            }

            if (vm.PublicKeyMultibase == null)
            {
                throw new CapabilityValidationException(
                    $"Verification method has no PublicKeyMultibase: {didOrVerificationMethod}");
            }

            var decoded = Multibase.Decode(vm.PublicKeyMultibase);
            var (codec, rawKey) = Multicodec.Decode(decoded);
            var keyType = KeyTypeExtensions.ToKeyType(codec);

            return new ResolvedKey(rawKey, MapKeyType(keyType));
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

    /// <summary>
    /// Returns the fragment of a verification method id (the part after '#'), or the id
    /// unchanged when it has no fragment. Null-safe.
    /// </summary>
    private static string FragmentOf(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return string.Empty;
        }

        var i = id.IndexOf('#');
        return i < 0 ? id : id[(i + 1)..];
    }

    /// <summary>
    /// Maps NetDid's <see cref="KeyType"/> enum to ZcapLd key type strings
    /// used by <see cref="Cryptography.ICryptoSuite"/>.
    /// </summary>
    internal static string MapKeyType(KeyType keyType) => keyType switch
    {
        KeyType.Ed25519 => "Ed25519VerificationKey2020",
        KeyType.P256 => "EcdsaSecp256r1VerificationKey2019",
        KeyType.P384 => "EcdsaSecp384r1VerificationKey2019",
        KeyType.Secp256k1 => "EcdsaSecp256k1VerificationKey2019",
        KeyType.X25519 => "X25519KeyAgreementKey2020",
        _ => throw new CapabilityValidationException($"Unsupported key type: {keyType}")
    };
}
