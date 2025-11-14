using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a delegated ZCAP-LD capability according to W3C specification.
/// Delegated capabilities represent authority transferred through a chain,
/// with restrictions possible via caveats or URL-based attenuation.
/// </summary>
public sealed class DelegatedCapability : CapabilityBase
{
    private const string ZcapV1Context = "https://w3id.org/zcap/v1";
    private static readonly TimeSpan MaxRecommendedExpirationDuration = TimeSpan.FromDays(90); // 3 months

    /// <summary>
    /// Gets or sets the ID of the parent capability (root or delegated).
    /// This field is REQUIRED for delegated capabilities.
    /// </summary>
    [JsonPropertyName("parentCapability")]
    public string ParentCapability { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expiration timestamp for this capability.
    /// This field is REQUIRED for delegated capabilities.
    /// Per spec, verifiers SHOULD reject expiration dates exceeding three months.
    /// </summary>
    [JsonPropertyName("expires")]
    public DateTime Expires { get; set; }

    /// <summary>
    /// Gets or sets the actions allowed by this capability.
    /// Can be a single string or an array of strings (e.g., "read", "write").
    /// This field is optional but recommended.
    /// </summary>
    [JsonPropertyName("allowedAction")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? AllowedAction { get; set; }

    /// <summary>
    /// Gets or sets the list of caveats (restrictions) for this capability.
    /// Child capabilities inherit all caveats from parent capabilities.
    /// </summary>
    [JsonPropertyName("caveat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Caveat[]? Caveats { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic proof for this capability.
    /// This field is REQUIRED for delegated capabilities and MUST contain
    /// a capability delegation proof.
    /// </summary>
    [JsonPropertyName("proof")]
    public Proof? Proof { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegatedCapability"/> class.
    /// </summary>
    public DelegatedCapability()
    {
        // Delegated capabilities must have an array context starting with zcap/v1
        Context = new[] { ZcapV1Context };
    }

    /// <summary>
    /// Creates a new delegated capability with the specified parameters.
    /// </summary>
    /// <param name="parentCapabilityId">The ID of the parent capability.</param>
    /// <param name="invocationTarget">The target resource URI.</param>
    /// <param name="controller">The DID of the new controller.</param>
    /// <param name="expires">The expiration timestamp.</param>
    /// <param name="allowedAction">Optional allowed actions.</param>
    /// <returns>A new delegated capability.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    public static DelegatedCapability Create(
        string parentCapabilityId,
        string invocationTarget,
        object controller,
        DateTime expires,
        object? allowedAction = null)
    {
        if (string.IsNullOrWhiteSpace(parentCapabilityId))
        {
            throw new ArgumentNullException(nameof(parentCapabilityId), "Parent capability ID is required.");
        }

        if (string.IsNullOrWhiteSpace(invocationTarget))
        {
            throw new ArgumentNullException(nameof(invocationTarget), "InvocationTarget is required.");
        }

        if (controller == null)
        {
            throw new ArgumentNullException(nameof(controller), "Controller is required.");
        }

        return new DelegatedCapability
        {
            Id = $"urn:uuid:{Guid.NewGuid()}",
            ParentCapability = parentCapabilityId,
            InvocationTarget = invocationTarget,
            Controller = controller,
            Expires = expires,
            AllowedAction = allowedAction,
            Context = new[] { ZcapV1Context }
        };
    }

    /// <summary>
    /// Validates the @context field for delegated capabilities.
    /// Delegated capabilities MUST have @context as an array starting with "https://w3id.org/zcap/v1".
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when context is invalid.</exception>
    protected override void ValidateContext()
    {
        if (Context is not string[] contextArray)
        {
            throw new CapabilityValidationException(
                "Delegated capability @context must be an array.",
                "INVALID_DELEGATED_CONTEXT_TYPE",
                Id);
        }

        if (contextArray.Length == 0)
        {
            throw new CapabilityValidationException(
                "Delegated capability @context array cannot be empty.",
                "EMPTY_CONTEXT_ARRAY",
                Id);
        }

        if (!string.Equals(contextArray[0], ZcapV1Context, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Delegated capability @context array must start with '{ZcapV1Context}'.",
                "INVALID_DELEGATED_CONTEXT_VALUE",
                Id);
        }
    }

    /// <summary>
    /// Validates the parentCapability field.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when parent capability is invalid.</exception>
    private void ValidateParentCapability()
    {
        if (string.IsNullOrWhiteSpace(ParentCapability))
        {
            throw new CapabilityValidationException(
                "Delegated capability must have a parentCapability.",
                "MISSING_PARENT_CAPABILITY",
                Id);
        }

        if (!Uri.TryCreate(ParentCapability, UriKind.Absolute, out _))
        {
            throw new CapabilityValidationException(
                $"ParentCapability must be a valid URI: {ParentCapability}",
                "INVALID_PARENT_CAPABILITY_URI",
                Id);
        }
    }

    /// <summary>
    /// Validates the expires field.
    /// Per spec, verifiers SHOULD reject expiration dates exceeding three months.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when expiration is invalid.</exception>
    private void ValidateExpiration()
    {
        if (Expires == default)
        {
            throw new CapabilityValidationException(
                "Delegated capability must have an expiration date.",
                "MISSING_EXPIRATION",
                Id);
        }

        if (Expires <= DateTime.UtcNow)
        {
            throw new CapabilityValidationException(
                $"Capability has expired. Expiration: {Expires:O}, Current: {DateTime.UtcNow:O}",
                "CAPABILITY_EXPIRED",
                Id);
        }

        var duration = Expires - DateTime.UtcNow;
        if (duration > MaxRecommendedExpirationDuration)
        {
            // This is a warning-level issue per spec (SHOULD, not MUST)
            // We'll allow it but could log a warning in production
        }
    }

    /// <summary>
    /// Validates the allowedAction field if present.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when allowedAction is invalid.</exception>
    private void ValidateAllowedAction()
    {
        if (AllowedAction == null)
        {
            return; // Optional field
        }

        if (AllowedAction is string actionStr)
        {
            if (string.IsNullOrWhiteSpace(actionStr))
            {
                throw new CapabilityValidationException(
                    "AllowedAction string cannot be empty.",
                    "EMPTY_ALLOWED_ACTION",
                    Id);
            }
        }
        else if (AllowedAction is string[] actionArray)
        {
            if (actionArray.Length == 0)
            {
                throw new CapabilityValidationException(
                    "AllowedAction array cannot be empty.",
                    "EMPTY_ALLOWED_ACTION_ARRAY",
                    Id);
            }

            foreach (var action in actionArray)
            {
                if (string.IsNullOrWhiteSpace(action))
                {
                    throw new CapabilityValidationException(
                        "AllowedAction array contains empty or null value.",
                        "INVALID_ALLOWED_ACTION_IN_ARRAY",
                        Id);
                }
            }
        }
        else
        {
            throw new CapabilityValidationException(
                "AllowedAction must be either a string or an array of strings.",
                "INVALID_ALLOWED_ACTION_TYPE",
                Id);
        }
    }

    /// <summary>
    /// Validates that the invocationTarget is properly attenuated from the parent.
    /// Per spec, the invocationTarget either matches parent's value or uses parent as prefix.
    /// </summary>
    /// <param name="parentTarget">The parent capability's invocationTarget.</param>
    /// <exception cref="CapabilityValidationException">Thrown when attenuation is invalid.</exception>
    public void ValidateAttenuation(string parentTarget)
    {
        if (string.IsNullOrWhiteSpace(parentTarget))
        {
            throw new ArgumentNullException(nameof(parentTarget), "Parent invocationTarget is required.");
        }

        // Exact match is always valid
        if (string.Equals(InvocationTarget, parentTarget, StringComparison.Ordinal))
        {
            return;
        }

        // Check if this is a valid suffix (URL-based attenuation)
        if (!InvocationTarget.StartsWith(parentTarget, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"InvocationTarget must match parent or use parent as prefix. Parent: {parentTarget}, Child: {InvocationTarget}",
                "INVALID_INVOCATION_TARGET_ATTENUATION",
                Id);
        }

        // Validate suffix rules per spec
        var suffix = InvocationTarget.Substring(parentTarget.Length);
        var parentHasQuery = parentTarget.Contains('?');

        if (parentHasQuery)
        {
            // If parent has '?', suffix must start with '&'
            if (!suffix.StartsWith("&"))
            {
                throw new CapabilityValidationException(
                    "When parent has query string, suffix must start with '&'.",
                    "INVALID_ATTENUATION_SUFFIX",
                    Id);
            }
        }
        else
        {
            // If parent has no '?', suffix must start with '/' or '?'
            if (!suffix.StartsWith("/") && !suffix.StartsWith("?"))
            {
                throw new CapabilityValidationException(
                    "When parent has no query string, suffix must start with '/' or '?'.",
                    "INVALID_ATTENUATION_SUFFIX",
                    Id);
            }
        }
    }

    /// <summary>
    /// Validates the entire delegated capability according to W3C ZCAP-LD specification.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    public override void Validate()
    {
        ValidateCommonFields();
        ValidateParentCapability();
        ValidateExpiration();
        ValidateAllowedAction();

        // Proof validation will be done separately by the verification service
        // as it requires cryptographic operations
    }

    /// <summary>
    /// Gets the allowed actions as an array of strings.
    /// </summary>
    /// <returns>An array of allowed action strings.</returns>
    public string[] GetAllowedActions()
    {
        if (AllowedAction == null)
        {
            return Array.Empty<string>();
        }

        return AllowedAction switch
        {
            string str => new[] { str },
            string[] arr => arr,
            _ => Array.Empty<string>()
        };
    }

    /// <summary>
    /// Checks if a specific action is allowed by this capability.
    /// </summary>
    /// <param name="action">The action to check.</param>
    /// <returns>True if the action is allowed; otherwise, false.</returns>
    public bool AllowsAction(string action)
    {
        if (string.IsNullOrWhiteSpace(action))
        {
            return false;
        }

        var allowedActions = GetAllowedActions();

        // If no actions specified, assume all actions are allowed
        if (allowedActions.Length == 0)
        {
            return true;
        }

        return allowedActions.Contains(action, StringComparer.Ordinal);
    }

    /// <summary>
    /// Checks if this capability has expired.
    /// </summary>
    /// <returns>True if expired; otherwise, false.</returns>
    public bool IsExpired()
    {
        return DateTime.UtcNow >= Expires;
    }

    /// <summary>
    /// Checks if this capability's expiration is more restrictive than the parent's.
    /// Per spec, child expiration must not exceed parent's expiration.
    /// </summary>
    /// <param name="parentExpires">The parent capability's expiration, or null if parent is root.</param>
    /// <returns>True if expiration is valid; otherwise, false.</returns>
    public bool HasValidExpiration(DateTime? parentExpires)
    {
        // If parent is a root capability (no expiration), any child expiration is valid
        if (parentExpires == null)
        {
            return true;
        }

        // Child expiration must not exceed parent's
        return Expires <= parentExpires.Value;
    }
}
