using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Default implementation of <see cref="IDelegationService"/>.
/// Orchestrates capability delegation with chain building, validation, and proof generation.
/// Thread-safe.
/// </summary>
public sealed class DelegationService : IDelegationService
{
    private readonly DelegationOptions _options;
    private readonly ICapabilityChainValidator _chainValidator;
    private readonly IAttenuationValidator _attenuationValidator;
    private readonly IProofService _proofService;
    private readonly ILogger<DelegationService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegationService"/> class.
    /// </summary>
    /// <param name="options">The delegation options.</param>
    /// <param name="chainValidator">The capability chain validator.</param>
    /// <param name="attenuationValidator">The attenuation validator.</param>
    /// <param name="proofService">The proof service for signature generation.</param>
    /// <param name="logger">The logger instance.</param>
    public DelegationService(
        IOptions<DelegationOptions> options,
        ICapabilityChainValidator chainValidator,
        IAttenuationValidator attenuationValidator,
        IProofService proofService,
        ILogger<DelegationService> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _chainValidator = chainValidator ?? throw new ArgumentNullException(nameof(chainValidator));
        _attenuationValidator = attenuationValidator ?? throw new ArgumentNullException(nameof(attenuationValidator));
        _proofService = proofService ?? throw new ArgumentNullException(nameof(proofService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Validate options
        _options.Validate();
    }

    /// <inheritdoc/>
    public async Task<DelegatedCapability> DelegateCapabilityAsync(
        CapabilityBase parentCapability,
        string delegateeController,
        KeyPair delegatorKeyPair,
        string? attenuatedTarget = null,
        object? allowedAction = null,
        DateTime? expires = null,
        Caveat[]? caveats = null,
        object? invoker = null,
        CancellationToken cancellationToken = default)
    {
        if (parentCapability == null)
        {
            throw new ArgumentNullException(nameof(parentCapability));
        }

        if (string.IsNullOrWhiteSpace(delegateeController))
        {
            throw new ArgumentNullException(nameof(delegateeController));
        }

        if (delegatorKeyPair == null)
        {
            throw new ArgumentNullException(nameof(delegatorKeyPair));
        }

        _logger.LogDebug(
            "Creating delegation from {ParentId} to {DelegateeController}",
            parentCapability.Id,
            delegateeController);

        // Determine invocation target (default to parent's if not attenuated)
        var invocationTarget = attenuatedTarget ?? parentCapability.InvocationTarget;

        // Determine expiration (default if not specified)
        var expirationTime = expires ?? DateTime.UtcNow.Add(_options.DefaultExpirationDuration);

        // Create the delegated capability
        var delegated = DelegatedCapability.Create(
            parentCapability.Id,
            delegateeController,
            invocationTarget,
            expirationTime,
            allowedAction,
            caveats,
            invoker);

        // Validate attenuation
        var attenuationResult = await _attenuationValidator
            .ValidateAttenuationAsync(parentCapability, delegated, cancellationToken)
            .ConfigureAwait(false);

        if (!attenuationResult.IsValid)
        {
            throw new CapabilityValidationException(
                delegated.Id,
                "ATTENUATION_VIOLATION",
                $"Delegation violates attenuation rules: {attenuationResult.ErrorMessage}");
        }

        // Build capability chain
        var capabilityChain = await BuildCapabilityChainAsync(parentCapability, cancellationToken)
            .ConfigureAwait(false);

        // Add parent capability to the chain
        var fullChain = capabilityChain.Append(parentCapability).ToArray();

        // Create delegation proof
        var proof = await _proofService
            .CreateDelegationProofAsync(delegated, delegatorKeyPair, fullChain, cancellationToken)
            .ConfigureAwait(false);

        delegated.Proof = proof;

        _logger.LogInformation(
            "Successfully created delegated capability {CapabilityId} from {ParentId} to {DelegateeController}",
            delegated.Id,
            parentCapability.Id,
            delegateeController);

        return delegated;
    }

    /// <inheritdoc/>
    public Task<object[]> BuildCapabilityChainAsync(
        CapabilityBase capability,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        var chain = new List<object>();

        // For root capabilities, chain is just the root ID
        if (capability is RootCapability root)
        {
            chain.Add(root.Id);
            return Task.FromResult(chain.ToArray());
        }

        // For delegated capabilities, recursively build the chain
        if (capability is DelegatedCapability delegated)
        {
            // Check if proof has capability chain
            if (delegated.Proof?.CapabilityChain != null && delegated.Proof.CapabilityChain.Length > 0)
            {
                // Extract chain from proof (excluding the last element which is the parent)
                // The proof's capability chain already has the full chain up to this capability's parent
                var proofChain = delegated.Proof.CapabilityChain;

                // Return all elements except the last (which is the parent capability object)
                // We want just the IDs for the chain
                for (int i = 0; i < proofChain.Length - 1; i++)
                {
                    if (proofChain[i] is string id)
                    {
                        chain.Add(id);
                    }
                }

                return Task.FromResult(chain.ToArray());
            }

            // Fallback: build chain from parent ID
            // Note: This won't include intermediate delegations, just root → parent
            // For a complete implementation, you'd need to resolve the full chain

            // Start with parent ID
            chain.Add(delegated.ParentCapability);

            _logger.LogWarning(
                "Building chain for delegated capability {CapabilityId} without proof chain. Chain may be incomplete.",
                delegated.Id);
        }

        return Task.FromResult(chain.ToArray());
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateCapabilityAsync(
        CapabilityBase capability,
        CancellationToken cancellationToken = default)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        _logger.LogDebug("Validating capability {CapabilityId}", capability.Id);

        // Build the capability chain
        var chain = await BuildCapabilityChainAsync(capability, cancellationToken)
            .ConfigureAwait(false);

        // Add the capability itself if it's delegated
        if (capability is DelegatedCapability)
        {
            // For delegated capabilities, we need the parent in the chain
            // The chain should already have the parent from BuildCapabilityChainAsync
            // or from the proof's capability chain
        }

        // Validate the chain
        return await _chainValidator
            .ValidateChainAsync(capability, chain, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateCapabilityChainAsync(
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

        return _chainValidator.ValidateChainAsync(capability, chain, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<bool> IsRevokedAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId));
        }

        // Revocation checking is not yet implemented
        // This would require:
        // - A revocation list or revocation registry
        // - Integration with DID document revocation lists
        // - Or a blockchain-based revocation system

        if (!_options.CheckRevocation)
        {
            _logger.LogDebug(
                "Revocation checking is disabled. Capability {CapabilityId} is not revoked.",
                capabilityId);
            return Task.FromResult(false);
        }

        _logger.LogWarning(
            "Revocation checking is enabled but not implemented. Capability {CapabilityId} assumed not revoked.",
            capabilityId);

        // TODO: Implement revocation checking
        // For now, always return false (not revoked)
        return Task.FromResult(false);
    }

    /// <inheritdoc/>
    public Task RevokeCapabilityAsync(
        string capabilityId,
        KeyPair revokerKeyPair,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            throw new ArgumentNullException(nameof(capabilityId));
        }

        if (revokerKeyPair == null)
        {
            throw new ArgumentNullException(nameof(revokerKeyPair));
        }

        // Revocation is not yet implemented
        // This would require:
        // - Publishing revocation to a revocation list
        // - Signing the revocation with the revoker's key
        // - Verifying the revoker has authority to revoke

        _logger.LogWarning(
            "Capability revocation is not implemented. Capability {CapabilityId} cannot be revoked.",
            capabilityId);

        // TODO: Implement revocation
        throw new NotImplementedException(
            "Capability revocation is not yet implemented. This feature requires a revocation registry or list.");
    }
}
