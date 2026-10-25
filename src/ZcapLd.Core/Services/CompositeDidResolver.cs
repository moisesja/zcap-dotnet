using NetDid.Core.Model;
using NetDid.Core.Resolution;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Routes DID resolution operations to the appropriate sub-resolver based on registration.
/// Use this when different DID methods are resolved by different backends (e.g. did:key locally,
/// did:web via a universal resolver endpoint).
/// </summary>
/// <remarks>
/// <para>
/// Registrations are evaluated in order; the first match wins. Register the full method prefix
/// including the trailing colon (<c>"did:key:"</c>, not <c>"did:key"</c>): matching is an ordinal
/// <c>StartsWith</c>, so a prefix without the colon also matches other methods that share its
/// leading characters (<c>did:keyfoo:…</c>) and shadows any adapter registered later for them.
/// Complete all registrations before handing the composite to a verifier; <see cref="Register(string, IDidResolver)"/>
/// is not synchronized against concurrent resolution. Key resolution for a DID that no
/// registration matches throws <see cref="CapabilityValidationException"/>, which the verifier
/// classifies as an expected (Debug-level) failure like any other unresolvable
/// <c>verificationMethod</c>.
/// </para>
/// <para>
/// The composite also implements <see cref="IVerificationRelationshipResolver"/> (Issue #148), so
/// <see cref="VerificationService"/> can perform controller authorization through the same
/// method-specific adapters that resolve keys, without a separate relationship resolver being
/// wired. Relationship checks are routed by the <em>controller</em> DID, not by the verification
/// method's DID, because the controller's document is the authority being consulted and may
/// reference a method under a different DID. Routing fails closed with a tri-state result rather
/// than an exception, so a verifier checking several controllers continues to the next one:
/// </para>
/// <list type="bullet">
/// <item><description>No registered resolver matches the controller: <c>methodNotSupported</c>
/// (an expected, attacker-drivable outcome; the verifier logs it at Debug).</description></item>
/// <item><description>The matched resolver resolves keys only and does not implement
/// <see cref="IVerificationRelationshipResolver"/>: <c>internalError</c>. This is a deployment
/// misconfiguration — controllers of that method can never be authorized — so the verifier logs it
/// at Warning, and keeps doing so for every capability naming such a controller until the
/// configuration is fixed. Successful key resolution is never treated as evidence of authority.</description></item>
/// <item><description>The matched adapter throws (network outage, adapter bug, its own HTTP timeout):
/// <c>internalError</c> carrying the exception type and message, logged at Warning. Only cancellation
/// requested through the caller's <see cref="CancellationToken"/> propagates; an adapter-local
/// <see cref="OperationCanceledException"/> such as the <see cref="TaskCanceledException"/> that
/// <c>HttpClient.Timeout</c> raises is a fault for that controller alone.</description></item>
/// </list>
/// </remarks>
public class CompositeDidResolver : IDidResolver, IVerificationRelationshipResolver
{
    private readonly List<(Func<string, bool> CanHandle, IDidResolver Resolver)> _resolvers = new();

    /// <summary>
    /// Registers a resolver for DIDs matching a method prefix (e.g. "did:key:", "did:web:").
    /// Resolvers are evaluated in registration order; first match wins. Include the trailing colon
    /// so the prefix cannot match a different method that shares its leading characters.
    /// </summary>
    public void Register(string didMethodPrefix, IDidResolver resolver)
    {
        if (string.IsNullOrEmpty(didMethodPrefix))
            throw new ArgumentException("DID method prefix cannot be null or empty", nameof(didMethodPrefix));
        ArgumentNullException.ThrowIfNull(resolver);

        _resolvers.Add((did => did.StartsWith(didMethodPrefix, StringComparison.Ordinal), resolver));
    }

    /// <summary>
    /// Registers a resolver with a custom predicate for matching DIDs.
    /// Resolvers are evaluated in registration order; first match wins.
    /// </summary>
    public void Register(Func<string, bool> canHandle, IDidResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(canHandle);
        ArgumentNullException.ThrowIfNull(resolver);

        _resolvers.Add((canHandle, resolver));
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        return Resolve(baseDid).ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        return Resolve(did).GetVerificationMethodAsync(did);
    }

    /// <summary>
    /// Authorizes <paramref name="verificationMethodDidUrl"/> for <paramref name="relationship"/>
    /// against the document of <paramref name="controllerDid"/>, routed to the resolver registered
    /// for the controller's DID method. The controller is matched verbatim (no fragment stripping):
    /// a controller value that is not a bare DID is handed to the method adapter, which rejects it.
    /// See the class remarks for the fail-closed outcomes.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when <paramref name="controllerDid"/> or
    /// <paramref name="verificationMethodDidUrl"/> is null or whitespace, matching
    /// <see cref="DefaultVerificationRelationshipResolver"/>.</exception>
    public async Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid,
        string verificationMethodDidUrl,
        VerificationRelationship relationship,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(controllerDid);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodDidUrl);

        if (!TryResolve(controllerDid, out var resolver))
        {
            return VerificationRelationshipAuthorizationResult.NotResolvable(
                "methodNotSupported",
                $"No IDidResolver is registered for the DID method of controller '{controllerDid}'; " +
                "verification-relationship authorization is not possible.");
        }

        // Fail closed on a key-only adapter. Being able to resolve the controller's (or the
        // signer's) public key says nothing about which relationships the controller's document
        // grants, so key resolution is never consulted here.
        if (resolver is not IVerificationRelationshipResolver relationshipResolver)
        {
            return VerificationRelationshipAuthorizationResult.NotResolvable(
                "internalError",
                $"The IDidResolver registered for controller '{controllerDid}' ({resolver.GetType().Name}) " +
                "resolves keys only and does not implement IVerificationRelationshipResolver; " +
                "register a relationship-aware adapter for this DID method to authorize its controllers.");
        }

        try
        {
            return await relationshipResolver.IsAuthorizedForRelationshipAsync(
                controllerDid, verificationMethodDidUrl, relationship, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // A faulting adapter must not abort the verifier's multi-controller loop (an outage of one
            // method's host would otherwise lock out a co-controller of another method). Report it as
            // the same operator-actionable code as a misconfigured adapter so the verifier logs it at
            // Warning, denies this controller, and continues to the next one. Only cancellation the
            // CALLER requested propagates: an OperationCanceledException is not proof of that —
            // HttpClient.Timeout raises TaskCanceledException while the caller's token is untouched —
            // so the decision is made on the caller's token, not on the exception type (PR #151 review).
            return VerificationRelationshipAuthorizationResult.NotResolvable(
                "internalError",
                $"The IVerificationRelationshipResolver for controller '{controllerDid}' ({resolver.GetType().Name}) " +
                $"threw {ex.GetType().Name}: {ex.Message}");
        }
    }

    private IDidResolver Resolve(string did)
    {
        if (TryResolve(did, out var resolver))
            return resolver;

        // CapabilityValidationException (not InvalidOperationException): the DID comes from a
        // presented proof's verificationMethod, so an unknown method is an expected, attacker-drivable
        // failure that the verifier must log at Debug — the same classification DidKeyResolver uses
        // for a DID it does not handle (Issue #64 severity policy).
        throw new CapabilityValidationException(
            $"No IDidResolver registered that can handle DID: {did}. " +
            "Register a resolver using Register(prefix, resolver) or Register(predicate, resolver).");
    }

    private bool TryResolve(string did, out IDidResolver resolver)
    {
        foreach (var (canHandle, registered) in _resolvers)
        {
            if (canHandle(did))
            {
                resolver = registered;
                return true;
            }
        }

        resolver = null!;
        return false;
    }
}
