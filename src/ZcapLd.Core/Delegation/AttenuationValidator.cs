using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Default implementation of <see cref="IAttenuationValidator"/>.
/// Validates that delegated capabilities have equal or lesser authority than their parents.
/// Thread-safe.
/// </summary>
public sealed class AttenuationValidator : IAttenuationValidator
{
    private readonly DelegationOptions _options;
    private readonly ILogger<AttenuationValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AttenuationValidator"/> class.
    /// </summary>
    /// <param name="options">The delegation options.</param>
    /// <param name="logger">The logger instance.</param>
    public AttenuationValidator(
        IOptions<DelegationOptions> options,
        ILogger<AttenuationValidator> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateAttenuationAsync(
        CapabilityBase parent,
        DelegatedCapability delegated,
        CancellationToken cancellationToken = default)
    {
        if (parent == null)
        {
            throw new ArgumentNullException(nameof(parent));
        }

        if (delegated == null)
        {
            throw new ArgumentNullException(nameof(delegated));
        }

        _logger.LogDebug(
            "Validating attenuation from parent {ParentId} to delegated {DelegatedId}",
            parent.Id,
            delegated.Id);

        // Validate URL-based attenuation
        if (_options.EnforceUrlAttenuation)
        {
            var urlResult = ValidateUrlAttenuation(parent.InvocationTarget, delegated.InvocationTarget);
            if (!urlResult.IsValid)
            {
                _logger.LogWarning(
                    "URL attenuation validation failed: {ErrorMessage}",
                    urlResult.ErrorMessage);
                return urlResult;
            }
        }

        // Validate expiration attenuation
        var expirationResult = ValidateExpirationAttenuation(parent, delegated);
        if (!expirationResult.IsValid)
        {
            _logger.LogWarning(
                "Expiration attenuation validation failed: {ErrorMessage}",
                expirationResult.ErrorMessage);
            return expirationResult;
        }

        // Validate action attenuation
        var actionResult = ValidateActionAttenuation(parent, delegated);
        if (!actionResult.IsValid)
        {
            _logger.LogWarning(
                "Action attenuation validation failed: {ErrorMessage}",
                actionResult.ErrorMessage);
            return actionResult;
        }

        // Validate caveat inheritance
        if (_options.EnforceCaveatInheritance)
        {
            var caveatResult = await ValidateCaveatInheritanceAsync(
                parent,
                delegated,
                null,
                cancellationToken).ConfigureAwait(false);

            if (!caveatResult.IsValid)
            {
                _logger.LogWarning(
                    "Caveat inheritance validation failed: {ErrorMessage}",
                    caveatResult.ErrorMessage);
                return caveatResult;
            }
        }

        _logger.LogInformation(
            "Attenuation validation successful for delegation from {ParentId} to {DelegatedId}",
            parent.Id,
            delegated.Id);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public ValidationResult ValidateUrlAttenuation(string parentTarget, string delegatedTarget)
    {
        if (string.IsNullOrWhiteSpace(parentTarget))
        {
            throw new ArgumentNullException(nameof(parentTarget));
        }

        if (string.IsNullOrWhiteSpace(delegatedTarget))
        {
            throw new ArgumentNullException(nameof(delegatedTarget));
        }

        // Normalize URLs for comparison (remove trailing slashes)
        var normalizedParent = NormalizeUrl(parentTarget);
        var normalizedDelegated = NormalizeUrl(delegatedTarget);

        // The delegated target must be equal to or a path suffix of the parent target
        // Example: parent="https://api.example.com" allows child="https://api.example.com/users"
        if (normalizedDelegated.Equals(normalizedParent, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug(
                "URL attenuation valid: delegated target equals parent target ({Target})",
                normalizedDelegated);
            return ValidationResult.Success();
        }

        if (normalizedDelegated.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase))
        {
            // Ensure the suffix starts with a path separator to avoid prefix matching issues
            // e.g., parent="/api" should not allow child="/api-v2"
            var suffix = normalizedDelegated[normalizedParent.Length..];
            if (suffix.StartsWith('/') || normalizedParent.EndsWith('/'))
            {
                _logger.LogDebug(
                    "URL attenuation valid: delegated target {DelegatedTarget} is a path suffix of parent {ParentTarget}",
                    normalizedDelegated,
                    normalizedParent);
                return ValidationResult.Success();
            }
        }

        return ValidationResult.Failure(
            "URL_ATTENUATION_VIOLATION",
            $"Delegated capability invocation target '{delegatedTarget}' is not equal to or a path suffix of parent target '{parentTarget}'.",
            new Dictionary<string, object>
            {
                ["ParentTarget"] = parentTarget,
                ["DelegatedTarget"] = delegatedTarget
            });
    }

    /// <inheritdoc/>
    public ValidationResult ValidateExpirationAttenuation(
        CapabilityBase parent,
        DelegatedCapability delegated)
    {
        if (parent == null)
        {
            throw new ArgumentNullException(nameof(parent));
        }

        if (delegated == null)
        {
            throw new ArgumentNullException(nameof(delegated));
        }

        // Check if delegated capability has expired
        if (delegated.IsExpired())
        {
            return ValidationResult.Failure(
                "CAPABILITY_EXPIRED",
                $"Delegated capability '{delegated.Id}' has expired at {delegated.Expires:O}.",
                new Dictionary<string, object>
                {
                    ["CapabilityId"] = delegated.Id,
                    ["Expires"] = delegated.Expires,
                    ["CurrentTime"] = DateTime.UtcNow
                });
        }

        // For root capabilities, there's no parent expiration to check
        if (parent is RootCapability)
        {
            _logger.LogDebug(
                "Expiration attenuation valid: parent is root capability (no expiration constraint)");
            return ValidationResult.Success();
        }

        // For delegated parents, check that child expires before or at parent expiration
        if (parent is DelegatedCapability parentDelegated)
        {
            // Allow for clock skew
            var adjustedParentExpiration = parentDelegated.Expires.Add(_options.MaxClockSkew);

            if (delegated.Expires > adjustedParentExpiration)
            {
                return ValidationResult.Failure(
                    "EXPIRATION_ATTENUATION_VIOLATION",
                    $"Delegated capability expires at {delegated.Expires:O}, which is after parent expiration at {parentDelegated.Expires:O}.",
                    new Dictionary<string, object>
                    {
                        ["ParentExpires"] = parentDelegated.Expires,
                        ["DelegatedExpires"] = delegated.Expires,
                        ["MaxClockSkew"] = _options.MaxClockSkew
                    });
            }

            // Check if parent has expired
            if (parentDelegated.IsExpired())
            {
                return ValidationResult.Failure(
                    "PARENT_CAPABILITY_EXPIRED",
                    $"Parent capability '{parent.Id}' has expired at {parentDelegated.Expires:O}.",
                    new Dictionary<string, object>
                    {
                        ["ParentId"] = parent.Id,
                        ["ParentExpires"] = parentDelegated.Expires,
                        ["CurrentTime"] = DateTime.UtcNow
                    });
            }
        }

        _logger.LogDebug(
            "Expiration attenuation valid: delegated expires at {DelegatedExpires}",
            delegated.Expires);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public ValidationResult ValidateActionAttenuation(
        CapabilityBase parent,
        DelegatedCapability delegated)
    {
        if (parent == null)
        {
            throw new ArgumentNullException(nameof(parent));
        }

        if (delegated == null)
        {
            throw new ArgumentNullException(nameof(delegated));
        }

        // Get parent allowed actions
        object? parentAllowedAction = null;
        if (parent is DelegatedCapability parentDelegated)
        {
            parentAllowedAction = parentDelegated.AllowedAction;
        }

        // If parent has no action restrictions, any child actions are allowed
        if (parentAllowedAction == null)
        {
            _logger.LogDebug(
                "Action attenuation valid: parent has no action restrictions");
            return ValidationResult.Success();
        }

        // If child has no actions specified, it inherits all parent actions
        if (delegated.AllowedAction == null)
        {
            _logger.LogDebug(
                "Action attenuation valid: delegated has no specific actions (inherits parent)");
            return ValidationResult.Success();
        }

        // Get action sets
        var parentActions = GetActionSet(parentAllowedAction);
        var delegatedActions = GetActionSet(delegated.AllowedAction);

        // Child actions must be a subset of parent actions
        var unauthorizedActions = delegatedActions.Except(parentActions, StringComparer.OrdinalIgnoreCase).ToList();

        if (unauthorizedActions.Any())
        {
            return ValidationResult.Failure(
                "ACTION_ATTENUATION_VIOLATION",
                $"Delegated capability has actions not allowed by parent: {string.Join(", ", unauthorizedActions)}",
                new Dictionary<string, object>
                {
                    ["ParentActions"] = parentActions,
                    ["DelegatedActions"] = delegatedActions,
                    ["UnauthorizedActions"] = unauthorizedActions
                });
        }

        _logger.LogDebug(
            "Action attenuation valid: delegated actions {DelegatedActions} are subset of parent actions {ParentActions}",
            delegatedActions,
            parentActions);

        return ValidationResult.Success();
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateCaveatInheritanceAsync(
        CapabilityBase parent,
        DelegatedCapability delegated,
        InvocationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        if (parent == null)
        {
            throw new ArgumentNullException(nameof(parent));
        }

        if (delegated == null)
        {
            throw new ArgumentNullException(nameof(delegated));
        }

        // Get parent caveats
        Caveat[]? parentCaveats = null;
        if (parent is DelegatedCapability parentDelegated)
        {
            parentCaveats = parentDelegated.Caveats;
        }

        // If parent has no caveats, inheritance is valid
        if (parentCaveats == null || parentCaveats.Length == 0)
        {
            _logger.LogDebug(
                "Caveat inheritance valid: parent has no caveats to inherit");
            return Task.FromResult(ValidationResult.Success());
        }

        // Get delegated caveats
        var delegatedCaveats = delegated.Caveats ?? Array.Empty<Caveat>();

        // For now, we validate that child has at least as restrictive caveats as parent
        // A more sophisticated implementation would check semantic equivalence
        // Current implementation: child must have all parent caveat types

        var parentCaveatTypes = parentCaveats.Select(c => c.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var delegatedCaveatTypes = delegatedCaveats.Select(c => c.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missingCaveatTypes = parentCaveatTypes.Except(delegatedCaveatTypes, StringComparer.OrdinalIgnoreCase).ToList();

        if (missingCaveatTypes.Any())
        {
            _logger.LogWarning(
                "Caveat inheritance check: delegated capability missing parent caveat types: {MissingTypes}",
                missingCaveatTypes);

            // Note: This is a basic check. A production implementation should check that
            // child caveats are at least as restrictive as parent caveats, not just the same type.
            return Task.FromResult(ValidationResult.Failure(
                "CAVEAT_INHERITANCE_VIOLATION",
                $"Delegated capability missing required parent caveat types: {string.Join(", ", missingCaveatTypes)}",
                new Dictionary<string, object>
                {
                    ["ParentCaveatTypes"] = parentCaveatTypes,
                    ["DelegatedCaveatTypes"] = delegatedCaveatTypes,
                    ["MissingCaveatTypes"] = missingCaveatTypes
                }));
        }

        _logger.LogDebug(
            "Caveat inheritance valid: delegated has all parent caveat types");

        return Task.FromResult(ValidationResult.Success());
    }

    /// <summary>
    /// Normalizes a URL for comparison by removing trailing slashes.
    /// </summary>
    private static string NormalizeUrl(string url)
    {
        return url.TrimEnd('/');
    }

    /// <summary>
    /// Converts an allowed action (string or array) to a set of action strings.
    /// </summary>
    private static HashSet<string> GetActionSet(object allowedAction)
    {
        return allowedAction switch
        {
            string single => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { single },
            string[] array => new HashSet<string>(array, StringComparer.OrdinalIgnoreCase),
            IEnumerable<string> enumerable => new HashSet<string>(enumerable, StringComparer.OrdinalIgnoreCase),
            _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        };
    }
}
