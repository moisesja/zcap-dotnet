using System.Security.Cryptography;
using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Assembles ZCAP-LD cryptographic proofs: it builds the proof metadata, delegates DID resolution
/// to an <see cref="IDidResolver"/>, and delegates the actual canonicalization + signing to
/// DataProofs' legacy cryptosuites via <see cref="LegacyProofCrypto"/> (which signs through the
/// consumer's <see cref="IDidSigner"/>).
/// </summary>
public class SigningService : ISigningService
{
    private readonly IDidSigner _signer;
    private readonly IDidResolver _resolver;
    private readonly string _canonicalizationMethod;
    private readonly LegacyProofCrypto _legacyProofCrypto = new();

    /// <summary>
    /// Creates a signing service using JCS canonicalization (the default).
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver)
        : this(signer, resolver, "JCS")
    {
    }

    /// <summary>
    /// Creates a signing service with an explicit canonicalization method (<c>"JCS"</c> or
    /// <c>"RDFC-1.0"</c>) applied to all proofs it produces.
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver, string canonicalizationMethod)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _canonicalizationMethod = canonicalizationMethod ?? throw new ArgumentNullException(nameof(canonicalizationMethod));
    }

    /// <summary>
    /// Signs a capability with the specified signing key.
    /// SECURITY FIX S-03: Binds proof metadata cryptographically per Data Integrity spec.
    /// </summary>
    public Task<Proof> SignCapabilityAsync(
        Capability capability,
        string signerDid,
        string proofPurpose,
        object[]? capabilityChain = null)
        => SignCapabilityAsync(capability, signerDid, proofPurpose, capabilityChain, createdOverride: null);

    /// <summary>
    /// Determinism overload of
    /// <see cref="SignCapabilityAsync(Capability, string, string, object[])"/> that stamps an explicit
    /// proof <c>created</c> instant instead of the current UTC time. Provided for deterministic signing
    /// (test vectors, delegation-proof freshness tests — Issue #99). Not on
    /// <see cref="ISigningService"/>; production callers should use the four-argument overload.
    /// </summary>
    public async Task<Proof> SignCapabilityAsync(
        Capability capability,
        string signerDid,
        string proofPurpose,
        object[]? capabilityChain,
        DateTime? createdOverride)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));
        if (string.IsNullOrWhiteSpace(proofPurpose))
            throw new ArgumentException("Proof purpose cannot be null or empty", nameof(proofPurpose));

        var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
        var resolvedKey = await _resolver.ResolvePublicKeyAsync(signerDid);
        var suite = ZcapSuiteCatalog.GetByKeyType(resolvedKey.KeyType)
            ?? throw new CryptographicException($"No signature suite for key type: {resolvedKey.KeyType}");
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = ZcapTimestamps.Format(createdOverride ?? DateTime.UtcNow);
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

        var didSigner = CreateLegacySigner(signerDid, resolvedKey, proofType);
        proof.ProofValue = await _legacyProofCrypto.CreateProofValueAsync(
            capabilityWithoutProof, proof, didSigner, _canonicalizationMethod);

        return proof;
    }

    /// <summary>
    /// Signs an invocation request.
    /// COMPLIANCE FIX C-05: Populates required invocation proof fields per W3C ZCAP-LD spec.
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
        var resolvedKey = await _resolver.ResolvePublicKeyAsync(signerDid);
        var suite = ZcapSuiteCatalog.GetByKeyType(resolvedKey.KeyType)
            ?? throw new CryptographicException($"No signature suite for key type: {resolvedKey.KeyType}");
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = ZcapTimestamps.Format(createdOverride ?? DateTime.UtcNow);
        var proofType = suite.ProofType;

        // COMPLIANCE FIX C-05: invocation proofs MUST include capability, invocationTarget, and
        // capabilityAction. CapabilityChain is intentionally unset — invocation proofs don't carry one,
        // and emitting `"capabilityChain": []` breaks strict cross-language parsers (#37).
        var proof = new Proof
        {
            Type = proofType,
            Created = created,
            ProofPurpose = proofPurpose,
            VerificationMethod = verificationMethod,
            ProofValue = string.Empty,
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

        var didSigner = CreateLegacySigner(signerDid, resolvedKey, proofType);
        proof.ProofValue = await _legacyProofCrypto.CreateProofValueAsync(
            invocationWithoutProof, proof, didSigner, _canonicalizationMethod);

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

        var resolvedKey = await _resolver.ResolvePublicKeyAsync(signerDid);
        var suite = ZcapSuiteCatalog.GetByKeyType(resolvedKey.KeyType)
            ?? throw new CryptographicException($"No signature suite for key type: {resolvedKey.KeyType}");

        return suite.ContextUrl;
    }

    private DidSignerAdapter CreateLegacySigner(string signerDid, ResolvedKey resolvedKey, string expectedProofType)
        => new(
            _signer,
            signerDid,
            ResolvedKeyTypeMap.ToNetCryptoKeyType(resolvedKey.KeyType),
            expectedProofType,
            resolvedKey.PublicKeyBytes);
}
