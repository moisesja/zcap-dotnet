using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Represents a root ZCAP-LD capability according to W3C specification.
/// Root capabilities represent initial authority granted by a target over itself.
/// Per the specification, root capabilities MUST NOT contain any fields beyond
/// @context, id, controller, and invocationTarget.
/// </summary>
public sealed class RootCapability : CapabilityBase
{
    private const string ZcapV1Context = "https://w3id.org/zcap/v1";
    private const string RootCapabilityIdPrefix = "urn:zcap:root:";

    /// <summary>
    /// Initializes a new instance of the <see cref="RootCapability"/> class.
    /// </summary>
    public RootCapability()
    {
        Context = ZcapV1Context;
    }

    /// <summary>
    /// Creates a new root capability with the specified parameters.
    /// </summary>
    /// <param name="invocationTarget">The target resource URI.</param>
    /// <param name="controller">The DID of the controller (can be string or array).</param>
    /// <returns>A new root capability with properly formatted ID.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    public static RootCapability Create(string invocationTarget, object controller)
    {
        if (string.IsNullOrWhiteSpace(invocationTarget))
        {
            throw new ArgumentNullException(nameof(invocationTarget), "InvocationTarget is required.");
        }

        if (controller == null)
        {
            throw new ArgumentNullException(nameof(controller), "Controller is required.");
        }

        // Generate the root capability ID according to spec:
        // "urn:zcap:root:{encodeURIComponent(invocationTarget)}"
        var encodedTarget = Uri.EscapeDataString(invocationTarget);
        var rootId = $"{RootCapabilityIdPrefix}{encodedTarget}";

        return new RootCapability
        {
            Id = rootId,
            InvocationTarget = invocationTarget,
            Controller = controller,
            Context = ZcapV1Context
        };
    }

    /// <summary>
    /// Validates the @context field for root capabilities.
    /// Root capabilities MUST have @context set to exactly "https://w3id.org/zcap/v1".
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when context is invalid.</exception>
    protected override void ValidateContext()
    {
        if (Context is not string contextStr)
        {
            throw new CapabilityValidationException(
                "Root capability @context must be a string, not an array.",
                "INVALID_ROOT_CONTEXT_TYPE",
                Id);
        }

        if (!string.Equals(contextStr, ZcapV1Context, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability @context must be exactly '{ZcapV1Context}'.",
                "INVALID_ROOT_CONTEXT_VALUE",
                Id);
        }
    }

    /// <summary>
    /// Validates the ID format for root capabilities.
    /// Root capability IDs MUST be in format "urn:zcap:root:{encodeURIComponent(invocationTarget)}".
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when ID format is invalid.</exception>
    private void ValidateIdFormat()
    {
        if (!Id.StartsWith(RootCapabilityIdPrefix, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability ID must start with '{RootCapabilityIdPrefix}'. Got: {Id}",
                "INVALID_ROOT_ID_FORMAT",
                Id);
        }

        // Verify the ID matches the expected format based on invocationTarget
        var expectedId = $"{RootCapabilityIdPrefix}{Uri.EscapeDataString(InvocationTarget)}";
        if (!string.Equals(Id, expectedId, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability ID does not match expected format. Expected: {expectedId}, Got: {Id}",
                "MISMATCHED_ROOT_ID",
                Id);
        }
    }

    /// <summary>
    /// Validates the entire root capability according to W3C ZCAP-LD specification.
    /// Per spec, root capabilities MUST NOT contain fields beyond the base requirements.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    public override void Validate()
    {
        ValidateCommonFields();
        ValidateIdFormat();

        // Root capabilities do not have proofs, expiration, caveats, etc.
        // The specification explicitly states: "Root capabilities MUST NOT contain any other fields."
    }

    /// <summary>
    /// Determines whether this root capability can be used to authorize a given invocation target.
    /// </summary>
    /// <param name="targetUri">The target URI being invoked.</param>
    /// <returns>True if the target matches the capability's invocationTarget; otherwise, false.</returns>
    public bool AuthorizesTarget(string targetUri)
    {
        if (string.IsNullOrWhiteSpace(targetUri))
        {
            return false;
        }

        // For root capabilities, the target must match exactly
        return string.Equals(InvocationTarget, targetUri, StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if this root capability is valid for the specified controller and target.
    /// </summary>
    /// <param name="controllerDid">The controller DID to check.</param>
    /// <param name="targetUri">The target URI to check.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    public bool IsValidFor(string controllerDid, string targetUri)
    {
        try
        {
            Validate();
            return IsController(controllerDid) && AuthorizesTarget(targetUri);
        }
        catch (CapabilityValidationException)
        {
            return false;
        }
    }
}
