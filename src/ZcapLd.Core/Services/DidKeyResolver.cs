using NetCid;
using NetCrypto;
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
    /// <remarks>
    /// When the argument carries a <c>#fragment</c>, the verification method whose id equals the
    /// full URI is returned; an unmatched fragment throws rather than silently substituting the
    /// primary method (Issue #67). A bare DID returns the primary verification method.
    /// <para>
    /// This resolves key material only — it applies no verification-relationship
    /// (<c>capabilityInvocation</c> / <c>capabilityDelegation</c>) authorization gate. Callers that
    /// use the returned key to make their own authorization decisions therefore depend on this
    /// method returning the key for the <em>named</em> method; the ZCAP verifier separately enforces
    /// the relationship via <see cref="IsAuthorizedForRelationshipAsync"/>.
    /// </para>
    /// </remarks>
    public async Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        if (!didOrVerificationMethod.StartsWith("did:key:"))
        {
            throw new CapabilityValidationException(
                $"DidKeyResolver only handles did:key DIDs, got: {didOrVerificationMethod}");
        }

        // Parse the fragment boundary once: everything before '#' is the DID we resolve, and the
        // index marks where the optional verification-method fragment begins. Single source of
        // truth so the document lookup and the fragment selection below cannot drift apart.
        var hashIndex = didOrVerificationMethod.IndexOf('#');
        var baseDid = hashIndex < 0
            ? didOrVerificationMethod
            : didOrVerificationMethod[..hashIndex];

        try
        {
            var result = await _didKeyMethod.ResolveAsync(baseDid);

            if (result.DidDocument == null || result.ResolutionMetadata.Error != null)
            {
                throw new CapabilityValidationException(
                    $"Failed to resolve did:key: {didOrVerificationMethod}");
            }

            var verificationMethods = result.DidDocument.VerificationMethod;
            if (verificationMethods == null || verificationMethods.Count == 0)
            {
                throw new CapabilityValidationException(
                    $"No verification method found in resolved DID document: {didOrVerificationMethod}");
            }

            // If the caller named a specific verification method by #fragment, honour it: select the
            // method whose Id equals the full URI — rather than always returning the first method
            // (Issue #67). An Ed25519 did:key resolves to two methods (the Ed25519 signing key at
            // index 0 and a derived X25519 key-agreement key at index 1), so FirstOrDefault()
            // returned the wrong key for a non-index-0 fragment. did:key documents always carry
            // absolute verification-method ids, so an exact id match is exhaustive; an unmatched
            // fragment throws (below) rather than silently substituting the first method.
            var vm = hashIndex < 0
                ? verificationMethods[0]
                : verificationMethods.FirstOrDefault(m =>
                      string.Equals(m.Id, didOrVerificationMethod, StringComparison.Ordinal));

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
            var keyType = KeyTypeExtensions.FromMulticodec(codec);

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
    /// Maps NetCrypto's <see cref="KeyType"/> enum to ZcapLd key type strings
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
