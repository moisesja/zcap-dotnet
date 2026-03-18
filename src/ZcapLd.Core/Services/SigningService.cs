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

    /// <summary>
    /// Backward-compatible constructor (Ed25519 only).
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver)
        : this(signer, resolver, CreateDefaultSuiteProvider())
    {
    }

    /// <summary>
    /// Full constructor with explicit crypto suite provider.
    /// </summary>
    public SigningService(IDidSigner signer, IDidResolver resolver, ICryptoSuiteProvider suiteProvider)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
    }

    private static ICryptoSuiteProvider CreateDefaultSuiteProvider()
    {
        var provider = new CryptoSuiteProvider();
        provider.Register(CryptoSuite.Ed25519());
        provider.Register(CryptoSuite.P256());
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
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = DateTime.UtcNow;
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

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(capabilityWithoutProof, proof);
        var result = await _signer.SignAsync(signerDid, canonicalBytes);
        ValidateSignatureType(result.SignatureType, proofType);
        proof.ProofValue = MultibaseCodec.Encode(result.Signature);

        return proof;
    }

    /// <summary>
    /// Signs an invocation request
    /// COMPLIANCE FIX C-05: Populates required invocation proof fields per W3C ZCAP-LD spec
    /// </summary>
    public async Task<Proof> SignInvocationAsync(Invocation invocation, string signerDid)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (string.IsNullOrEmpty(signerDid))
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));

        var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
        var suite = await ResolveSuiteForDidAsync(signerDid);
        var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
        var created = DateTime.UtcNow;
        var proofType = suite.ProofType;

        // COMPLIANCE FIX C-05: Create the invocation proof with required fields
        // Per spec, invocation proofs MUST include capability, invocationTarget, and capabilityAction
        var proof = new Proof
        {
            Type = proofType,
            Created = created,
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = verificationMethod,
            CapabilityChain = Array.Empty<object>(), // Invocation proofs don't have chains
            ProofValue = string.Empty,
            // Required invocation proof fields:
            Capability = invocation.Capability,
            InvocationTarget = invocation.InvocationTarget,
            CapabilityAction = invocation.CapabilityAction
        };

        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(invocationWithoutProof, proof);
        var result = await _signer.SignAsync(signerDid, canonicalBytes);
        ValidateSignatureType(result.SignatureType, proofType);
        proof.ProofValue = MultibaseCodec.Encode(result.Signature);

        return proof;
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

    private static void ValidateSignatureType(string actualType, string expectedType)
    {
        if (!string.Equals(actualType, expectedType, StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Signer returned signature type '{actualType}' but expected '{expectedType}'.");
        }
    }
}
