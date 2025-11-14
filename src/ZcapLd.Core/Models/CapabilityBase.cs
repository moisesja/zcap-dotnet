using System.Text.Json.Serialization;
using ZcapLd.Core.Exceptions;

namespace ZcapLd.Core.Models;

/// <summary>
/// Base class for ZCAP-LD capabilities according to W3C specification.
/// Contains only the fields common to both root and delegated capabilities.
/// </summary>
public abstract class CapabilityBase
{
    /// <summary>
    /// Gets or sets the JSON-LD context for the capability.
    /// For root capabilities, this MUST be "https://w3id.org/zcap/v1".
    /// For delegated capabilities, this MUST be an array starting with "https://w3id.org/zcap/v1".
    /// </summary>
    [JsonPropertyName("@context")]
    public object Context { get; set; } = "https://w3id.org/zcap/v1";

    /// <summary>
    /// Gets or sets the unique identifier for this capability (URI).
    /// For root capabilities: Must be in format "urn:zcap:root:{encodeURIComponent(invocationTarget)}"
    /// For delegated capabilities: SHOULD use "urn:uuid:" format.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the DID or DIDs of the entities authorized to use this capability.
    /// Can be a single string or an array of strings.
    /// </summary>
    [JsonPropertyName("controller")]
    public object Controller { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the target resource URI this capability grants access to.
    /// For delegated capabilities, this MUST either match the parent's invocationTarget
    /// or use the parent's invocationTarget as a prefix (URL-based attenuation).
    /// </summary>
    [JsonPropertyName("invocationTarget")]
    public string InvocationTarget { get; set; } = string.Empty;

    /// <summary>
    /// Validates the basic fields common to all capabilities.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    protected virtual void ValidateCommonFields()
    {
        if (string.IsNullOrWhiteSpace(Id))
        {
            throw new CapabilityValidationException(
                "Capability ID is required and cannot be empty.",
                "MISSING_ID");
        }

        if (!Uri.TryCreate(Id, UriKind.Absolute, out _))
        {
            throw new CapabilityValidationException(
                $"Capability ID must be a valid URI: {Id}",
                "INVALID_ID_URI",
                Id);
        }

        if (string.IsNullOrWhiteSpace(InvocationTarget))
        {
            throw new CapabilityValidationException(
                "InvocationTarget is required and cannot be empty.",
                "MISSING_INVOCATION_TARGET",
                Id);
        }

        if (!Uri.TryCreate(InvocationTarget, UriKind.Absolute, out _))
        {
            throw new CapabilityValidationException(
                $"InvocationTarget must be a valid URI: {InvocationTarget}",
                "INVALID_INVOCATION_TARGET",
                Id);
        }

        ValidateController();
        ValidateContext();
    }

    /// <summary>
    /// Validates the controller field, which can be a string or array of strings.
    /// </summary>
    protected virtual void ValidateController()
    {
        if (Controller is string controllerStr)
        {
            if (string.IsNullOrWhiteSpace(controllerStr))
            {
                throw new CapabilityValidationException(
                    "Controller is required and cannot be empty.",
                    "MISSING_CONTROLLER",
                    Id);
            }

            if (!Uri.TryCreate(controllerStr, UriKind.Absolute, out _))
            {
                throw new CapabilityValidationException(
                    $"Controller must be a valid URI: {controllerStr}",
                    "INVALID_CONTROLLER_URI",
                    Id);
            }
        }
        else if (Controller is string[] controllerArray)
        {
            if (controllerArray.Length == 0)
            {
                throw new CapabilityValidationException(
                    "Controller array cannot be empty.",
                    "EMPTY_CONTROLLER_ARRAY",
                    Id);
            }

            foreach (var ctrl in controllerArray)
            {
                if (string.IsNullOrWhiteSpace(ctrl))
                {
                    throw new CapabilityValidationException(
                        "Controller array contains empty or null value.",
                        "INVALID_CONTROLLER_IN_ARRAY",
                        Id);
                }

                if (!Uri.TryCreate(ctrl, UriKind.Absolute, out _))
                {
                    throw new CapabilityValidationException(
                        $"Controller in array must be a valid URI: {ctrl}",
                        "INVALID_CONTROLLER_URI_IN_ARRAY",
                        Id);
                }
            }
        }
        else
        {
            throw new CapabilityValidationException(
                "Controller must be either a string or an array of strings.",
                "INVALID_CONTROLLER_TYPE",
                Id);
        }
    }

    /// <summary>
    /// Validates the @context field according to capability type.
    /// </summary>
    protected abstract void ValidateContext();

    /// <summary>
    /// Validates the entire capability according to W3C ZCAP-LD specification.
    /// </summary>
    /// <exception cref="CapabilityValidationException">Thrown when validation fails.</exception>
    public abstract void Validate();

    /// <summary>
    /// Gets the controller as an array of strings, regardless of whether it's stored as string or array.
    /// </summary>
    /// <returns>An array of controller DIDs.</returns>
    public string[] GetControllers()
    {
        return Controller switch
        {
            string str => new[] { str },
            string[] arr => arr,
            _ => Array.Empty<string>()
        };
    }

    /// <summary>
    /// Checks if a specific DID is authorized as a controller.
    /// </summary>
    /// <param name="did">The DID to check.</param>
    /// <returns>True if the DID is an authorized controller; otherwise, false.</returns>
    public bool IsController(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            return false;
        }

        return GetControllers().Contains(did, StringComparer.Ordinal);
    }
}
