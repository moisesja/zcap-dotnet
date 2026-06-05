using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for creating and managing ZCAP-LD capabilities
/// </summary>
public interface ICapabilityService
{
    /// <summary>
    /// Creates a new root capability
    /// </summary>
    /// <param name="controller">The controller(s) of the capability — a single DID
    /// (implicit from <see cref="string"/>) or several (implicit from <c>string[]</c>)</param>
    /// <param name="invocationTarget">The target resource URI</param>
    /// <param name="allowedActions">Optional; ignored for root capabilities. A root carries no
    /// <c>allowedAction</c> per W3C ZCAP-LD (it represents complete authority over the resource),
    /// so the implementation discards this. The interface previously declared it required, forcing
    /// callers to pass a throwaway array; the signature now matches the implementation (Issue #66).</param>
    /// <param name="expires">Optional expiration time</param>
    /// <param name="caveats">Optional caveats to apply</param>
    /// <returns>The created capability</returns>
    Task<Capability> CreateRootCapabilityAsync(
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null);

    /// <summary>
    /// Delegates a capability to another controller
    /// </summary>
    /// <param name="parentCapability">The parent capability to delegate</param>
    /// <param name="newController">The controller(s) of the new capability — a single DID
    /// (implicit from <see cref="string"/>) or several (implicit from <c>string[]</c>)</param>
    /// <param name="allowedActions">Actions to delegate (must be subset of parent)</param>
    /// <param name="expires">Optional expiration time (must not exceed parent)</param>
    /// <param name="caveats">Optional additional caveats</param>
    /// <param name="signerDid">Which of the parent's controllers signs the delegation.
    /// Defaults to the parent's first controller; must be one of the parent's controllers.</param>
    /// <returns>The delegated capability</returns>
    Task<Capability> DelegateCapabilityAsync(
        Capability parentCapability,
        ControllerSet newController,
        string[] allowedActions,
        DateTime? expires = null,
        Caveat[]? caveats = null,
        string? signerDid = null);

    /// <summary>
    /// Builds an <b>unsigned</b> <see cref="Invocation"/> for <paramref name="capability"/>, selecting
    /// the spec-correct <c>capability</c> wire shape automatically (Issue #51): a <b>root</b> capability
    /// is referenced by its id string, a <b>delegated</b> capability embeds the full zcap object so the
    /// verifier receives the delegated authority inline. Saves callers from choosing between
    /// <see cref="InvocationCapability.FromId"/> and <see cref="InvocationCapability.FromCapability"/>.
    /// Sign the result with <see cref="ISigningService.SignInvocationAsync"/> before presenting it.
    /// </summary>
    /// <param name="capability">The capability being invoked (root or delegated).</param>
    /// <param name="capabilityAction">The action to invoke (e.g. <c>"read"</c>).</param>
    /// <param name="invocationTarget">Target resource URI; defaults to <paramref name="capability"/>'s
    /// own <c>invocationTarget</c> when null.</param>
    /// <returns>An unsigned invocation carrying the spec-correct <c>capability</c> shape.</returns>
    Invocation CreateInvocation(Capability capability, string capabilityAction, string? invocationTarget = null);

    /// <summary>
    /// Builds an <b>unsigned</b> root <see cref="Invocation"/> that references the root capability by id
    /// string — for when only the root id is known (e.g. a resource server holding its root zcap urn but
    /// not the full object). For a delegated capability, or when you hold the full capability object,
    /// use <see cref="CreateInvocation"/>. Sign the result with
    /// <see cref="ISigningService.SignInvocationAsync"/>.
    /// </summary>
    /// <param name="rootCapabilityId">The root capability id (e.g. <c>urn:zcap:root:…</c>).</param>
    /// <param name="capabilityAction">The action to invoke.</param>
    /// <param name="invocationTarget">Target resource URI.</param>
    /// <returns>An unsigned root invocation referencing the capability by id string.</returns>
    Invocation CreateRootInvocation(string rootCapabilityId, string capabilityAction, string invocationTarget);

    /// <summary>
    /// Validates a capability and its chain
    /// </summary>
    /// <param name="capability">The capability to validate</param>
    /// <returns>True if the capability is valid</returns>
    Task<bool> ValidateCapabilityAsync(Capability capability);
}