using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Default implementation of <see cref="ICapabilityChainValidator"/>.
/// Validates capability chains for structural integrity and cryptographic validity.
/// Thread-safe.
/// </summary>
public sealed class CapabilityChainValidator : ICapabilityChainValidator
{
    private readonly DelegationOptions _options;
    private readonly IAttenuationValidator _attenuationValidator;
    private readonly IProofService? _proofService;
    private readonly IKeyProvider? _keyProvider;
    private readonly ILogger<CapabilityChainValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CapabilityChainValidator"/> class.
    /// </summary>
    /// <param name="options">The delegation options.</param>
    /// <param name="attenuationValidator">The attenuation validator.</param>
    /// <param name="proofService">Optional proof service for signature verification.</param>
    /// <param name="keyProvider">Optional key provider for public key resolution.</param>
    /// <param name="logger">The logger instance.</param>
    public CapabilityChainValidator(
        IOptions<DelegationOptions> options,
        IAttenuationValidator attenuationValidator,
        IProofService? proofService,
        IKeyProvider? keyProvider,
        ILogger<CapabilityChainValidator> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _attenuationValidator = attenuationValidator ?? throw new ArgumentNullException(nameof(attenuationValidator));
        _proofService = proofService;
        _keyProvider = keyProvider;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateChainAsync(
        CapabilityBase capability,
        object[] chain,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        _logger.LogDebug(
            "Validating capability chain for {CapabilityId} with {ChainLength} elements",
            capability.Id,
            chain.Length);

        // Validate chain structure
        var structureResult = ValidateChainStructure(chain);
        if (!structureResult.IsValid)
        {
            return structureResult;
        }

        // Validate chain depth
        var depthResult = ValidateChainDepth(chain);
        if (!depthResult.IsValid)
        {
            return depthResult;
        }

        // Validate chain continuity
        var continuityResult = ValidateChainContinuity(capability, chain);
        if (!continuityResult.IsValid)
        {
            return continuityResult;
        }

        // If it's a delegated capability, validate the full chain
        if (capability is DelegatedCapability delegated)
        {
            // Extract parent capability
            var parent = ExtractParentCapability(chain);
            if (parent == null)
            {
                return ValidationResult.Failure(
                    "INVALID_PARENT_CAPABILITY",
                    "Failed to extract parent capability from chain.",
                    new Dictionary<string, object>
                    {
                        ["ChainLength"] = chain.Length
                    });
            }

            // Validate proof if proof service is available
            if (_options.ValidateProofSignatures && _proofService != null)
            {
                var proofResult = await ValidateProofAsync(
                    delegated,
                    parent,
                    cancellationToken).ConfigureAwait(false);

                if (!proofResult.IsValid)
                {
                    return proofResult;
                }
            }

            // Validate attenuation
            var attenuationResult = await _attenuationValidator
                .ValidateAttenuationAsync(parent, delegated, cancellationToken)
                .ConfigureAwait(false);

            if (!attenuationResult.IsValid)
            {
                return attenuationResult;
            }

            // Recursively validate parent chain if parent is also delegated
            if (parent is DelegatedCapability parentDelegated && chain.Length > 2)
            {
                // Build parent chain (all elements except the last, which is the current parent object)
                var parentChain = chain.Take(chain.Length - 1).ToArray();

                var parentValidationResult = await ValidateChainAsync(
                    parentDelegated,
                    parentChain,
                    cancellationToken).ConfigureAwait(false);

                if (!parentValidationResult.IsValid)
                {
                    return parentValidationResult;
                }
            }
        }

        _logger.LogInformation(
            "Capability chain validation successful for {CapabilityId}",
            capability.Id);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public ValidationResult ValidateChainStructure(object[] chain)
    {
        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        if (chain.Length == 0)
        {
            return ValidationResult.Failure(
                "EMPTY_CHAIN",
                "Capability chain cannot be empty.");
        }

        // First element must be a string (root capability ID)
        if (chain[0] is not string rootId)
        {
            return ValidationResult.Failure(
                "INVALID_CHAIN_ROOT",
                $"First element of capability chain must be a string (root capability ID). Got: {chain[0]?.GetType().Name ?? "null"}",
                new Dictionary<string, object>
                {
                    ["FirstElementType"] = chain[0]?.GetType().Name ?? "null"
                });
        }

        // For chains with more than one element, intermediate elements should be strings
        for (int i = 1; i < chain.Length - 1; i++)
        {
            if (chain[i] is not string)
            {
                return ValidationResult.Failure(
                    "INVALID_CHAIN_ELEMENT",
                    $"Intermediate chain elements (index {i}) must be strings (capability IDs). Got: {chain[i]?.GetType().Name ?? "null"}",
                    new Dictionary<string, object>
                    {
                        ["ElementIndex"] = i,
                        ["ElementType"] = chain[i]?.GetType().Name ?? "null"
                    });
            }
        }

        // Last element should be an object (the parent capability) if chain length > 1
        if (chain.Length > 1)
        {
            var lastElement = chain[^1];
            if (lastElement is not CapabilityBase && lastElement is not Dictionary<string, object>)
            {
                // Allow for JSON objects that haven't been deserialized yet
                if (lastElement is string)
                {
                    return ValidationResult.Failure(
                        "INVALID_CHAIN_PARENT",
                        "Last element of capability chain must be the parent capability object, not a string ID.",
                        new Dictionary<string, object>
                        {
                            ["LastElementType"] = "string"
                        });
                }
            }
        }

        _logger.LogDebug(
            "Chain structure valid: {ChainLength} elements, root ID: {RootId}",
            chain.Length,
            rootId);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public ValidationResult ValidateChainDepth(object[] chain)
    {
        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        // Chain depth is the number of delegations (chain length - 1 for root)
        var depth = chain.Length - 1;

        if (depth > _options.MaxChainDepth)
        {
            return ValidationResult.Failure(
                "CHAIN_DEPTH_EXCEEDED",
                $"Capability chain depth ({depth}) exceeds maximum allowed depth ({_options.MaxChainDepth}).",
                new Dictionary<string, object>
                {
                    ["ChainDepth"] = depth,
                    ["MaxChainDepth"] = _options.MaxChainDepth
                });
        }

        _logger.LogDebug(
            "Chain depth valid: {ChainDepth} (max: {MaxChainDepth})",
            depth,
            _options.MaxChainDepth);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateProofAsync(
        DelegatedCapability capability,
        CapabilityBase parentCapability,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (parentCapability == null)
        {
            throw new ArgumentNullException(nameof(parentCapability));
        }

        if (capability.Proof == null)
        {
            return ValidationResult.Failure(
                "MISSING_PROOF",
                $"Delegated capability '{capability.Id}' is missing a proof.",
                new Dictionary<string, object>
                {
                    ["CapabilityId"] = capability.Id
                });
        }

        // Validate proof structure
        var proofValidationError = capability.Proof.Validate();
        if (proofValidationError != null)
        {
            return ValidationResult.Failure(
                "INVALID_PROOF_STRUCTURE",
                $"Proof validation failed: {proofValidationError}",
                new Dictionary<string, object>
                {
                    ["CapabilityId"] = capability.Id,
                    ["ValidationError"] = proofValidationError
                });
        }

        // If proof service is available, verify the signature
        if (_proofService != null && _keyProvider != null)
        {
            try
            {
                // Resolve the public key from the verification method
                var verificationMethod = capability.Proof.VerificationMethod;
                var publicKey = await _keyProvider
                    .ResolvePublicKeyAsync(verificationMethod, cancellationToken)
                    .ConfigureAwait(false);

                if (publicKey == null)
                {
                    _logger.LogWarning(
                        "Could not resolve public key for verification method: {VerificationMethod}",
                        verificationMethod);

                    return ValidationResult.Failure(
                        "PUBLIC_KEY_NOT_FOUND",
                        $"Could not resolve public key for verification method '{verificationMethod}'.",
                        new Dictionary<string, object>
                        {
                            ["VerificationMethod"] = verificationMethod,
                            ["CapabilityId"] = capability.Id
                        });
                }

                // Verify the proof signature
                var isValid = await _proofService
                    .VerifyDelegationProofAsync(capability, publicKey, cancellationToken)
                    .ConfigureAwait(false);

                if (!isValid)
                {
                    return ValidationResult.Failure(
                        "INVALID_PROOF_SIGNATURE",
                        $"Proof signature verification failed for capability '{capability.Id}'.",
                        new Dictionary<string, object>
                        {
                            ["CapabilityId"] = capability.Id,
                            ["VerificationMethod"] = verificationMethod
                        });
                }

                _logger.LogDebug(
                    "Proof signature verified successfully for capability {CapabilityId}",
                    capability.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error verifying proof for capability {CapabilityId}",
                    capability.Id);

                return ValidationResult.Failure(
                    "PROOF_VERIFICATION_ERROR",
                    $"Error verifying proof: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        ["CapabilityId"] = capability.Id,
                        ["Error"] = ex.Message
                    });
            }
        }

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public ValidationResult ValidateChainContinuity(CapabilityBase capability, object[] chain)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        // For root capabilities, chain should just contain the root ID
        if (capability is RootCapability root)
        {
            if (chain.Length != 1)
            {
                return ValidationResult.Failure(
                    "INVALID_ROOT_CHAIN",
                    $"Root capability chain should contain only the root ID. Chain length: {chain.Length}",
                    new Dictionary<string, object>
                    {
                        ["ChainLength"] = chain.Length,
                        ["CapabilityId"] = root.Id
                    });
            }

            if (chain[0] is not string rootId || !rootId.Equals(root.Id, StringComparison.Ordinal))
            {
                return ValidationResult.Failure(
                    "ROOT_ID_MISMATCH",
                    $"Root capability ID '{root.Id}' does not match chain root ID '{chain[0]}'.",
                    new Dictionary<string, object>
                    {
                        ["CapabilityId"] = root.Id,
                        ["ChainRootId"] = chain[0]
                    });
            }

            return ValidationResult.Success();
        }

        // For delegated capabilities, verify parentCapability reference
        if (capability is DelegatedCapability delegated)
        {
            if (chain.Length < 2)
            {
                return ValidationResult.Failure(
                    "INVALID_DELEGATED_CHAIN",
                    $"Delegated capability chain must have at least 2 elements (root ID + parent). Chain length: {chain.Length}",
                    new Dictionary<string, object>
                    {
                        ["ChainLength"] = chain.Length,
                        ["CapabilityId"] = delegated.Id
                    });
            }

            // Extract parent capability
            var parent = ExtractParentCapability(chain);
            if (parent == null)
            {
                return ValidationResult.Failure(
                    "INVALID_PARENT_CAPABILITY",
                    "Failed to extract parent capability from chain.");
            }

            // Verify parentCapability field matches the parent in the chain
            if (!delegated.ParentCapability.Equals(parent.Id, StringComparison.Ordinal))
            {
                return ValidationResult.Failure(
                    "PARENT_CAPABILITY_MISMATCH",
                    $"Delegated capability's parentCapability field '{delegated.ParentCapability}' does not match chain parent ID '{parent.Id}'.",
                    new Dictionary<string, object>
                    {
                        ["CapabilityId"] = delegated.Id,
                        ["ParentCapabilityField"] = delegated.ParentCapability,
                        ["ChainParentId"] = parent.Id
                    });
            }

            return ValidationResult.Success();
        }

        return ValidationResult.Failure(
            "UNKNOWN_CAPABILITY_TYPE",
            $"Unknown capability type: {capability.GetType().Name}");
    }

    /// <inheritdoc/>
    public CapabilityBase? ExtractRootCapability(object[] chain)
    {
        if (chain == null || chain.Length == 0)
        {
            return null;
        }

        // For chains with just the root ID, we can't extract a full capability object
        // This method is intended for chains where the root is embedded
        // In most cases, only the ID is present, so this may return null

        // Check if first element is a capability object (unusual)
        if (chain[0] is CapabilityBase rootCapability)
        {
            return rootCapability;
        }

        // Typically, root is just an ID string, so we can't extract the full object
        return null;
    }

    /// <inheritdoc/>
    public CapabilityBase? ExtractParentCapability(object[] chain)
    {
        if (chain == null || chain.Length < 2)
        {
            return null;
        }

        // Parent capability is the last element in the chain
        var lastElement = chain[^1];

        if (lastElement is CapabilityBase capability)
        {
            return capability;
        }

        // If it's a dictionary, it might be a deserialized JSON object
        // We can't convert it here without serialization service
        // Caller should handle conversion

        return null;
    }
}
