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

            var vm = result.DidDocument.VerificationMethod?.FirstOrDefault()
                ?? throw new CapabilityValidationException(
                    $"No verification method found in resolved DID document: {didOrVerificationMethod}");

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
