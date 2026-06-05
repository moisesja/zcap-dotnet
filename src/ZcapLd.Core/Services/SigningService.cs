using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Assembles ZCAP-LD cryptographic proofs by canonicalizing documents,
/// delegating signing to an <see cref="IDidSigner"/> and DID resolution
/// to an <see cref="IDidResolver"/>.
/// </summary>
public class SigningService : ISigningService
{
    private readonly IDidSigner _signer;
    private readonly IDidResolver _resolver;
    private readonly ICryptoSuiteProvider _suiteProvider;
    private readonly IDocumentCanonicalizerProvider _canonicalizerProvider;

    /// <summary>
    /// Backward-compatible constructor (Ed25519 only, JCS canonicalization).
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver)
        : this(signer, resolver, CreateDefaultSuiteProvider())
    {
    }

    /// <summary>
    /// Constructor with explicit crypto suite provider (JCS canonicalization).
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver, ICryptoSuiteProvider suiteProvider)
        : this(signer, resolver, suiteProvider, CreateDefaultCanonicalizerProvider())
    {
    }

    /// <summary>
    /// Full constructor with all dependencies.
    /// </summary>
    public SigningService(
        IDidSigner signer,
        IDidResolver resolver,
        ICryptoSuiteProvider suiteProvider,
        IDocumentCanonicalizerProvider canonicalizerProvider)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
        _canonicalizerProvider = canonicalizerProvider ?? throw new ArgumentNullException(nameof(canonicalizerProvider));
    }

    private static ICryptoSuiteProvider CreateDefaultSuiteProvider()
    {
        var provider = new CryptoSuiteProvider();
        provider.Register(CryptoSuite.Ed25519());
        provider.Register(CryptoSuite.P256());
        return provider;
    }

    internal static IDocumentCanonicalizerProvider CreateDefaultCanonicalizerProvider()
    {
        var provider = new DocumentCanonicalizerProvider();
        provider.Register(new JcsDocumentCanonicalizer());
        return provider;
    }

    /// <summary>
    /// Signs a capability with the specified signing key
    /// SECURITY FIX S-03: Binds proof metadata cryptographically per Data Integrity spec
    /// </summary>
    public async Task<Proof> SignCapabilityAsync(
        Capability capability,
        string signerDid,
        string proofPurpose,
        object[]? capabilityChain = null)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));

        if (string.IsNullOrWhiteSpace(proofPurpose))
            throw new ArgumentException("Proof purpose cannot be null or empty", nameof(proofPurpose));

        var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
        var suite = await ResolveSuiteForDidAsync(signerDid);
        var canonicalizer = ResolveCanonicalizer(suite);
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = ZcapTimestamps.Format(DateTime.UtcNow);
        var proofType = suite.ProofType;
        var normalizedChain = capabilityChain ?? Array.Empty<object>();

        var proof = new Proof
        {
            Type = proofType,
            Created = created,
            ProofPurpose = proofPurpose,
            VerificationMethod = verificationMethod,
            CapabilityChain = normalizedChain,
            ProofValue = string.Empty
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            capabilityWithoutProof, proof, canonicalizer);
        var result = await _signer.SignAsync(signerDid, canonicalBytes);
        ValidateSignatureType(result.SignatureType, proofType);
        proof.ProofValue = MultibaseCodec.Encode(result.Signature);

        return proof;
    }

    /// <summary>
    /// Signs an invocation request
    /// COMPLIANCE FIX C-05: Populates required invocation proof fields per W3C ZCAP-LD spec
    /// </summary>
    public Task<Proof> SignInvocationAsync(Invocation invocation, string signerDid)
        => SignInvocationAsync(invocation, signerDid, createdOverride: null);

    /// <summary>
    /// Determinism overload of <see cref="SignInvocationAsync(Invocation, string)"/> that stamps an
    /// explicit proof <c>created</c> instant instead of the current UTC time. Provided for deterministic
    /// signing (test vectors, freshness tests). Not on <see cref="ISigningService"/>; production callers
    /// should use the two-argument overload.
    /// </summary>
    public async Task<Proof> SignInvocationAsync(Invocation invocation, string signerDid, DateTime? createdOverride)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));

        return await SignInvocationProofAsync(invocation, signerDid, Proof.CapabilityInvocationPurpose,
            createdOverride: createdOverride);
    }

    /// <summary>
    /// Produces a signed capability revocation request (proof-of-possession). The returned
    /// <see cref="Invocation"/> carries a <see cref="Proof.CapabilityRevocationPurpose"/> proof
    /// over <c>{id, capability, capabilityAction="revoke", invocationTarget}</c> plus any signed
    /// <paramref name="reason"/>/<paramref name="metadata"/>. Present it (with the full capability
    /// being revoked) to <c>IVerificationService.RevokeCapabilityAsync(Capability, Invocation)</c>.
    /// Possession of <paramref name="signerDid"/>'s private key is what authenticates the revoker.
    /// </summary>
    /// <param name="capabilityId">The id of the capability to revoke (bound into the signed payload).</param>
    /// <param name="signerDid">The DID whose key signs the request — must control the capability or an ancestor.</param>
    /// <param name="invocationTarget">The capability's invocation target (bound into the signed payload; informational for revocation).</param>
    /// <param name="reason">Optional human-readable reason, signed and recorded on the revocation.</param>
    /// <param name="metadata">Optional audit metadata, signed and recorded on the revocation.</param>
    public Task<Invocation> SignRevocationAsync(
        string capabilityId,
        string signerDid,
        string invocationTarget,
        string? reason = null,
        IDictionary<string, string>? metadata = null)
        => SignRevocationAsync(capabilityId, signerDid, invocationTarget, reason, metadata, createdOverride: null);

    /// <summary>
    /// Determinism overload of
    /// <see cref="SignRevocationAsync(string, string, string, string?, IDictionary{string, string}?)"/>
    /// that stamps an explicit proof <c>created</c> instant instead of the current UTC time. Provided for
    /// deterministic signing (test vectors, freshness tests). Not on <see cref="ISigningService"/>;
    /// production callers should use the five-argument overload.
    /// </summary>
    public async Task<Invocation> SignRevocationAsync(
        string capabilityId,
        string signerDid,
        string invocationTarget,
        string? reason,
        IDictionary<string, string>? metadata,
        DateTime? createdOverride)
    {
        if (string.IsNullOrEmpty(capabilityId))
            throw new ArgumentException("Capability ID cannot be null or empty", nameof(capabilityId));
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));
        if (string.IsNullOrEmpty(invocationTarget))
            throw new ArgumentException("Invocation target cannot be null or empty", nameof(invocationTarget));

        var revocation = new Invocation
        {
            Capability = capabilityId,
            CapabilityAction = Invocation.RevokeAction,
            InvocationTarget = invocationTarget
        };

        revocation.Proof = await SignInvocationProofAsync(
            revocation, signerDid, Proof.CapabilityRevocationPurpose,
            BuildRevocationExtensionData(reason, metadata), createdOverride);

        return revocation;
    }

    /// <summary>
    /// Shared invocation-proof assembly. The <paramref name="proofPurpose"/> and any
    /// <paramref name="additionalProperties"/> are part of the canonical bytes that get signed,
    /// so a revocation proof (purpose <c>capabilityRevocation</c>, carrying a signed reason) is
    /// byte-disjoint from a normal <c>capabilityInvocation</c> proof.
    /// </summary>
    private async Task<Proof> SignInvocationProofAsync(
        Invocation invocation,
        string signerDid,
        string proofPurpose,
        IReadOnlyDictionary<string, JsonElement>? additionalProperties = null,
        DateTime? createdOverride = null)
    {
        var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
        var suite = await ResolveSuiteForDidAsync(signerDid);
        var canonicalizer = ResolveCanonicalizer(suite);
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = ZcapTimestamps.Format(createdOverride ?? DateTime.UtcNow);
        var proofType = suite.ProofType;

        // COMPLIANCE FIX C-05: Create the invocation proof with required fields.
        // Per spec, invocation proofs MUST include capability, invocationTarget, and capabilityAction.
        // CapabilityChain is intentionally unset — invocation proofs don't carry one,
        // and emitting `"capabilityChain": []` breaks strict cross-language parsers (#37).
        var proof = new Proof
        {
            Type = proofType,
            Created = created,
            ProofPurpose = proofPurpose,
            VerificationMethod = verificationMethod,
            ProofValue = string.Empty,
            // Required invocation proof fields:
            Capability = invocation.Capability,
            InvocationTarget = invocation.InvocationTarget,
            CapabilityAction = invocation.CapabilityAction
        };

        // Signed extension fields (e.g. revocation reason/metadata) ride in the proof's
        // [JsonExtensionData] and are included in the canonical bytes, so they are tamper-evident.
        if (additionalProperties is { Count: > 0 })
        {
            proof.AdditionalProperties = new Dictionary<string, JsonElement>(additionalProperties, StringComparer.Ordinal);
        }

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            invocationWithoutProof, proof, canonicalizer);
        var result = await _signer.SignAsync(signerDid, canonicalBytes);
        ValidateSignatureType(result.SignatureType, proofType);
        proof.ProofValue = MultibaseCodec.Encode(result.Signature);

        return proof;
    }

    /// <summary>
    /// Builds the signed proof extension fields that carry a revocation's reason/metadata.
    /// Returns <c>null</c> when there is nothing to carry.
    /// </summary>
    private static IReadOnlyDictionary<string, JsonElement>? BuildRevocationExtensionData(
        string? reason, IDictionary<string, string>? metadata)
    {
        var hasReason = !string.IsNullOrEmpty(reason);
        var hasMetadata = metadata is { Count: > 0 };
        if (!hasReason && !hasMetadata)
            return null;

        var data = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (hasReason)
            data[Proof.RevocationReasonField] = JsonSerializer.SerializeToElement(reason, ZcapJsonOptions.Default);
        if (hasMetadata)
            data[Proof.RevocationMetadataField] = JsonSerializer.SerializeToElement(metadata, ZcapJsonOptions.Default);
        return data;
    }

    /// <summary>
    /// Resolves the JSON-LD security suite context URL for a signer's key type.
    /// </summary>
    public async Task<string> ResolveSuiteContextUrlAsync(string signerDid)
    {
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));

        var suite = await ResolveSuiteForDidAsync(signerDid);

        return suite.ContextUrl;
    }

    private async Task<ICryptoSuite> ResolveSuiteForDidAsync(string signerDid)
    {
        var resolvedKey = await _resolver.ResolvePublicKeyAsync(signerDid);
        return _suiteProvider.GetByKeyType(resolvedKey.KeyType)
            ?? throw new CryptographicException(
                $"No crypto suite registered for key type: {resolvedKey.KeyType}");
    }

    private IDocumentCanonicalizer ResolveCanonicalizer(ICryptoSuite suite)
    {
        return _canonicalizerProvider.GetByMethod(suite.CanonicalizationMethod)
            ?? throw new CryptographicException(
                $"No canonicalizer registered for method: {suite.CanonicalizationMethod}");
    }

    private static void ValidateSignatureType(string actualType, string expectedType)
    {
        if (!string.Equals(actualType, expectedType, StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Signer returned signature type '{actualType}' but expected '{expectedType}'.");
        }
    }
}
