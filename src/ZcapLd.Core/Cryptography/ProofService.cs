using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Serialization;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Default implementation of <see cref="IProofService"/>.
/// Provides Data Integrity proof generation and verification for ZCAP-LD.
/// Thread-safe.
/// </summary>
public sealed class ProofService : IProofService
{
    private readonly ICryptographicService _cryptoService;
    private readonly IJsonLdCanonicalizationService _canonicalizationService;
    private readonly IMultibaseService _multibaseService;
    private readonly IZcapSerializationService _serializationService;
    private readonly ILogger<ProofService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ProofService"/> class.
    /// </summary>
    /// <param name="cryptoService">The cryptographic service.</param>
    /// <param name="canonicalizationService">The JSON-LD canonicalization service.</param>
    /// <param name="multibaseService">The multibase encoding service.</param>
    /// <param name="serializationService">The ZCAP serialization service.</param>
    /// <param name="logger">The logger instance.</param>
    public ProofService(
        ICryptographicService cryptoService,
        IJsonLdCanonicalizationService canonicalizationService,
        IMultibaseService multibaseService,
        IZcapSerializationService serializationService,
        ILogger<ProofService> logger)
    {
        _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
        _canonicalizationService = canonicalizationService ?? throw new ArgumentNullException(nameof(canonicalizationService));
        _multibaseService = multibaseService ?? throw new ArgumentNullException(nameof(multibaseService));
        _serializationService = serializationService ?? throw new ArgumentNullException(nameof(serializationService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<Proof> CreateDelegationProofAsync(
        DelegatedCapability capability,
        KeyPair keyPair,
        object[] capabilityChain,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }

        if (capabilityChain == null || capabilityChain.Length == 0)
        {
            throw new ArgumentException(
                "Capability chain cannot be null or empty for delegation proofs.",
                nameof(capabilityChain));
        }

        _logger.LogDebug(
            "Creating delegation proof for capability {CapabilityId} using key {KeyId}",
            capability.Id,
            keyPair.KeyId);

        return await CreateProofAsync(
            capability,
            keyPair,
            Proof.CapabilityDelegationPurpose,
            capabilityChain,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<Proof> CreateInvocationProofAsync(
        Invocation invocation,
        KeyPair keyPair,
        string capabilityId,
        CancellationToken cancellationToken = default)
    {
        if (invocation == null)
        {
            throw new ArgumentNullException(nameof(invocation));
        }

        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }

        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId));
        }

        _logger.LogDebug(
            "Creating invocation proof for invocation {InvocationId} using key {KeyId}",
            invocation.Id,
            keyPair.KeyId);

        // For invocation proofs, the capability chain contains just the capability ID
        var capabilityChain = new object[] { capabilityId };

        return await CreateProofAsync(
            invocation,
            keyPair,
            Proof.CapabilityInvocationPurpose,
            capabilityChain,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyDelegationProofAsync(
        DelegatedCapability capability,
        PublicKey parentPublicKey,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (capability.Proof == null)
        {
            throw new ArgumentException(
                "Capability must have a proof to verify.",
                nameof(capability));
        }

        if (parentPublicKey == null)
        {
            throw new ArgumentNullException(nameof(parentPublicKey));
        }

        _logger.LogDebug(
            "Verifying delegation proof for capability {CapabilityId}",
            capability.Id);

        return await VerifyProofAsync(
            capability,
            capability.Proof,
            parentPublicKey,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyInvocationProofAsync(
        Invocation invocation,
        PublicKey invokerPublicKey,
        CancellationToken cancellationToken = default)
    {
        if (invocation == null)
        {
            throw new ArgumentNullException(nameof(invocation));
        }

        if (invocation.Proof == null)
        {
            throw new ArgumentException(
                "Invocation must have a proof to verify.",
                nameof(invocation));
        }

        if (invokerPublicKey == null)
        {
            throw new ArgumentNullException(nameof(invokerPublicKey));
        }

        _logger.LogDebug(
            "Verifying invocation proof for invocation {InvocationId}",
            invocation.Id);

        return await VerifyProofAsync(
            invocation,
            invocation.Proof,
            invokerPublicKey,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<Proof> CreateProofAsync(
        object document,
        KeyPair keyPair,
        string proofPurpose,
        object[]? capabilityChain = null,
        CancellationToken cancellationToken = default)
    {
        if (document == null)
        {
            throw new ArgumentNullException(nameof(document));
        }

        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }

        if (string.IsNullOrWhiteSpace(proofPurpose))
        {
            throw new ArgumentNullException(nameof(proofPurpose));
        }

        try
        {
            // Step 1: Create a document copy without proof for canonicalization
            var documentWithoutProof = CreateDocumentWithoutProof(document);

            // Step 2: Canonicalize the document
            var canonicalBytes = await _canonicalizationService
                .CanonicalizeObjectToBytesAsync(documentWithoutProof, cancellationToken)
                .ConfigureAwait(false);

            _logger.LogDebug(
                "Canonicalized document to {ByteCount} bytes for signing",
                canonicalBytes.Length);

            // Step 3: Sign the canonical representation
            var signatureBytes = await _cryptoService
                .SignAsync(canonicalBytes, keyPair, cancellationToken)
                .ConfigureAwait(false);

            // Step 4: Encode signature in multibase (Base58-BTC)
            var proofValue = await _multibaseService
                .EncodeAsync(signatureBytes, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            _logger.LogDebug(
                "Generated signature and encoded to multibase: {ProofValue}",
                proofValue.Substring(0, Math.Min(20, proofValue.Length)) + "...");

            // Step 5: Create the proof object
            Proof proof;
            if (proofPurpose == Proof.CapabilityDelegationPurpose && capabilityChain != null)
            {
                proof = Proof.CreateDelegationProof(
                    keyPair.VerificationMethod,
                    proofValue,
                    capabilityChain,
                    _cryptoService.SignatureAlgorithm);
            }
            else if (proofPurpose == Proof.CapabilityInvocationPurpose && capabilityChain != null)
            {
                var capabilityId = capabilityChain.FirstOrDefault()?.ToString()
                    ?? throw new ArgumentException("Capability ID must be provided in capability chain for invocation proofs.");

                proof = Proof.CreateInvocationProof(
                    keyPair.VerificationMethod,
                    proofValue,
                    capabilityId,
                    _cryptoService.SignatureAlgorithm);
            }
            else
            {
                throw new ArgumentException(
                    $"Unsupported proof purpose: {proofPurpose}. Expected '{Proof.CapabilityDelegationPurpose}' or '{Proof.CapabilityInvocationPurpose}'.",
                    nameof(proofPurpose));
            }

            _logger.LogInformation(
                "Successfully created {ProofPurpose} proof for document",
                proofPurpose);

            return proof;
        }
        catch (Exception ex) when (ex is not CryptographicException && ex is not ArgumentException)
        {
            _logger.LogError(ex, "Failed to create proof for document");
            throw new CryptographicException("Failed to create proof for document.", ex);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyProofAsync(
        object document,
        Proof proof,
        PublicKey publicKey,
        CancellationToken cancellationToken = default)
    {
        if (document == null)
        {
            throw new ArgumentNullException(nameof(document));
        }

        if (proof == null)
        {
            throw new ArgumentNullException(nameof(proof));
        }

        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        try
        {
            // Step 1: Validate proof structure
            var validationError = proof.Validate();
            if (validationError != null)
            {
                _logger.LogWarning(
                    "Proof validation failed: {ValidationError}",
                    validationError);
                return false;
            }

            // Step 2: Check signature algorithm
            if (proof.Type != _cryptoService.SignatureAlgorithm)
            {
                _logger.LogWarning(
                    "Proof signature algorithm mismatch. Expected {Expected}, got {Actual}",
                    _cryptoService.SignatureAlgorithm,
                    proof.Type);
                return false;
            }

            // Step 3: Create document without proof for canonicalization
            var documentWithoutProof = CreateDocumentWithoutProof(document);

            // Step 4: Canonicalize the document
            var canonicalBytes = await _canonicalizationService
                .CanonicalizeObjectToBytesAsync(documentWithoutProof, cancellationToken)
                .ConfigureAwait(false);

            _logger.LogDebug(
                "Canonicalized document to {ByteCount} bytes for verification",
                canonicalBytes.Length);

            // Step 5: Decode the signature from multibase
            var signatureBytes = await _multibaseService
                .DecodeAsync(proof.ProofValue, cancellationToken)
                .ConfigureAwait(false);

            // Step 6: Verify the signature
            var isValid = await _cryptoService
                .VerifyAsync(canonicalBytes, signatureBytes, publicKey, cancellationToken)
                .ConfigureAwait(false);

            _logger.LogInformation(
                "Proof verification result: {IsValid}",
                isValid);

            return isValid;
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            _logger.LogError(ex, "Failed to verify proof");
            throw new CryptographicException("Failed to verify proof.", ex);
        }
    }

    /// <summary>
    /// Creates a copy of the document with the proof field removed.
    /// This is required for canonicalization before signing/verification.
    /// </summary>
    private object CreateDocumentWithoutProof(object document)
    {
        return document switch
        {
            DelegatedCapability cap => new DelegatedCapability
            {
                Context = cap.Context,
                Id = cap.Id,
                ParentCapability = cap.ParentCapability,
                InvocationTarget = cap.InvocationTarget,
                Controller = cap.Controller,
                Invoker = cap.Invoker,
                Expires = cap.Expires,
                AllowedAction = cap.AllowedAction,
                Caveats = cap.Caveats,
                // Proof is intentionally omitted
            },
            Invocation inv => new Invocation
            {
                Context = inv.Context,
                Id = inv.Id,
                Capability = inv.Capability,
                CapabilityAction = inv.CapabilityAction,
                InvocationTarget = inv.InvocationTarget,
                Invoker = inv.Invoker,
                Arguments = inv.Arguments,
                // Proof is intentionally omitted
            },
            _ => throw new ArgumentException(
                $"Unsupported document type for proof creation: {document.GetType().Name}",
                nameof(document))
        };
    }
}
