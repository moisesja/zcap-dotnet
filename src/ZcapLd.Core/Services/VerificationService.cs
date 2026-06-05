using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Key;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for verifying ZCAP-LD capabilities and invocations.
/// Implements W3C ZCAP-LD specification verification requirements.
/// Only requires an <see cref="IDidResolver"/> — no private key access needed.
/// </summary>
public class VerificationService : IVerificationService
{
    private readonly IDidResolver _didResolver;
    private readonly ICaveatProcessor _caveatProcessor;
    private readonly ICryptoSuiteProvider _suiteProvider;
    private readonly IRevocationService _revocationService;
    private readonly INonceStore _nonceStore;
    private readonly IDocumentCanonicalizerProvider _canonicalizerProvider;
    private readonly TimeSpan _nonceWindow;
    private readonly ILogger _logger;
    private readonly IVerificationRelationshipResolver _relationshipResolver;
    private const int MaxChainLength = 10; // Per spec: SHOULD limit to 10

    /// <summary>
    /// Default window during which invocation nonces are tracked for replay protection.
    /// </summary>
    public static readonly TimeSpan DefaultNonceWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Backward-compatible constructor (Ed25519 only). Each instance gets its own process-local
    /// <see cref="InMemoryNonceStore"/>, so replay state is NOT shared across
    /// <see cref="VerificationService"/> instances; in a per-request / multi-instance setup supply a
    /// shared <see cref="INonceStore"/> via the full constructor (Issue #62; PR #88 review).
    /// </summary>
    public VerificationService(IDidResolver didResolver, ICaveatProcessor caveatProcessor)
        : this(didResolver, caveatProcessor, CreateDefaultSuiteProvider(),
               new RevocationService(new InMemoryRevocationStore()))
    {
    }

    /// <summary>
    /// Backward-compatible constructor with custom revocation service (Ed25519 only). Each instance
    /// gets its own process-local <see cref="InMemoryNonceStore"/>, so replay state is NOT shared
    /// across <see cref="VerificationService"/> instances; in a per-request / multi-instance setup
    /// supply a shared <see cref="INonceStore"/> via the full constructor (Issue #62; PR #88 review).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        IRevocationService revocationService)
        : this(didResolver, caveatProcessor, CreateDefaultSuiteProvider(), revocationService)
    {
    }

    /// <summary>
    /// Constructor with explicit crypto suite provider. Each instance gets its own process-local
    /// <see cref="InMemoryNonceStore"/>, so replay state is NOT shared across
    /// <see cref="VerificationService"/> instances; in a per-request / multi-instance setup supply a
    /// shared <see cref="INonceStore"/> via the full constructor (Issue #62; PR #88 review).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider)
        : this(didResolver, caveatProcessor, suiteProvider,
               new RevocationService(new InMemoryRevocationStore()))
    {
    }

    /// <summary>
    /// Constructor with all core dependencies. Defaults to an in-process
    /// <see cref="InMemoryNonceStore"/> so replay protection is ON by default — the convenience
    /// constructors (including the 2- and 3-argument ones that chain here) are secure-by-default.
    /// Supply an explicit <see cref="INonceStore"/> via the longer constructor to change it:
    /// a shared store for multi-node verifiers (<see cref="InMemoryNonceStore"/> is process-local),
    /// or <see cref="NullNonceStore"/> to deliberately opt out of replay protection (Issue #62).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService)
        : this(didResolver, caveatProcessor, suiteProvider, revocationService,
               new InMemoryNonceStore())
    {
    }

    /// <summary>
    /// Constructor with all dependencies including replay protection (JCS canonicalization).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService,
        INonceStore nonceStore,
        TimeSpan? nonceWindow = null)
        : this(didResolver, caveatProcessor, suiteProvider, revocationService,
               nonceStore, SigningService.CreateDefaultCanonicalizerProvider(), nonceWindow)
    {
    }

    /// <summary>
    /// Full constructor with all dependencies including canonicalizer provider. The optional
    /// <paramref name="logger"/> receives a diagnostic whenever verification fails closed on an
    /// unexpected exception, so operators can tell a misconfiguration/transient fault apart from
    /// an invalid capability (Issue #64). Defaults to <see cref="NullLogger"/> (no output).
    /// The optional <paramref name="relationshipResolver"/> performs controller authorization by
    /// resolving the controller's DID document and checking the relevant verification relationship
    /// (<c>capabilityInvocation</c> / <c>capabilityDelegation</c>) — Issue #65. Resolution order:
    /// the explicit argument, else the supplied <paramref name="didResolver"/> if it also implements
    /// <see cref="IVerificationRelationshipResolver"/> (so a method-aware resolver like
    /// <see cref="DidKeyResolver"/> self-provides authorization for the DIDs it already resolves),
    /// else a <c>did:key</c>-backed default (<see cref="CreateDefaultRelationshipResolver"/>). Supply
    /// a method-appropriate resolver (e.g. one wired by NetDid's <c>AddNetDid</c>) for other DID
    /// methods, otherwise their controllers fail closed as not authorized.
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService,
        INonceStore nonceStore,
        IDocumentCanonicalizerProvider canonicalizerProvider,
        TimeSpan? nonceWindow = null,
        ILogger<VerificationService>? logger = null,
        IVerificationRelationshipResolver? relationshipResolver = null)
    {
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));
        _caveatProcessor = caveatProcessor ?? throw new ArgumentNullException(nameof(caveatProcessor));
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
        _revocationService = revocationService ?? throw new ArgumentNullException(nameof(revocationService));
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        _canonicalizerProvider = canonicalizerProvider ?? throw new ArgumentNullException(nameof(canonicalizerProvider));
        _nonceWindow = nonceWindow ?? DefaultNonceWindow;
        _logger = logger ?? NullLogger<VerificationService>.Instance;
        _relationshipResolver = relationshipResolver
            ?? didResolver as IVerificationRelationshipResolver
            ?? CreateDefaultRelationshipResolver();
    }

    internal static ICryptoSuiteProvider CreateDefaultSuiteProvider()
    {
        var provider = new CryptoSuiteProvider();
        provider.Register(CryptoSuite.Ed25519());
        provider.Register(CryptoSuite.P256());
        return provider;
    }

    /// <summary>
    /// Default controller-authorization resolver: resolves <c>did:key</c> controller documents
    /// and checks the requested verification relationship. <c>did:key</c> derives the DID from the
    /// key and lists it under every relationship, so this is the correct default for the common
    /// case. Non-<c>did:key</c> controllers require a method-appropriate
    /// <see cref="IVerificationRelationshipResolver"/> supplied via the constructor / DI.
    /// </summary>
    internal static IVerificationRelationshipResolver CreateDefaultRelationshipResolver() =>
        new DefaultVerificationRelationshipResolver(new DidKeyMethod(new DefaultKeyGenerator()));

    /// <summary>
    /// Logs the cause of a fail-closed verification at a severity chosen by exception type.
    /// Expected, attacker-drivable validation/parse failures — a malformed or unbuildable
    /// capability, an unsupported proof type, an unresolvable/malformed <c>verificationMethod</c>,
    /// a malformed <c>proofValue</c>, malformed wire JSON — log at <see cref="LogLevel.Debug"/>, so a
    /// hostile client posting bad wire data cannot flood the operator's Warning channel and mask a
    /// real misconfiguration. <see cref="LogLevel.Warning"/> is reserved for genuinely unexpected
    /// faults an operator must act on: a missing canonicalizer / crypto-suite registration
    /// (<see cref="CryptographicException"/>), a transient DID-resolution / infrastructure error, or
    /// any non-library exception. Fail-closed is unaffected either way (Issue #64; the structured
    /// invalid-vs-couldn't-check channel remains #70).
    /// <para>
    /// Classification is by exception <i>type</i>, so it is best-effort for third-party
    /// <see cref="IDidResolver"/> implementations: a custom (e.g. network) resolver that throws its own
    /// exception type on an attacker-referenced <c>verificationMethod</c> lands at Warning rather than
    /// Debug. That is the conservative default — an unresolvable method is genuinely ambiguous (attacker
    /// noise vs. a transient resolver outage the operator must see). The bundled <c>DidKeyResolver</c>
    /// already maps resolution failures to <see cref="CapabilityValidationException"/> (Debug).
    /// </para>
    /// </summary>
    private void LogFailedClosed(Exception ex, string template, params object?[] args)
    {
        var expected = ex is CapabilityValidationException or DelegationException
            or InvocationException or CaveatException or FormatException or JsonException;
        _logger.Log(expected ? LogLevel.Debug : LogLevel.Warning, ex, template, args);
    }

    /// <summary>
    /// True when a <see cref="AuthorizationDecision.ControllerNotResolvable"/> resolution error is an
    /// expected, attacker-drivable outcome (the presented capability's controller DID is malformed,
    /// unknown, or of an unsupported method) rather than an unexpected fault an operator must act on.
    /// Applies the same severity philosophy as <see cref="LogFailedClosed"/> to the relationship
    /// resolver's tri-state result (Issue #64 / #65): these W3C DID-resolution codes log at Debug; an
    /// unrecognized/null code (a possible transient or infrastructure fault on a legitimate controller)
    /// stays at Warning.
    /// </summary>
    private static bool IsExpectedResolutionError(string? resolutionError) => resolutionError is
        "notFound" or "invalidDid" or "invalidDidUrl" or "methodNotSupported" or "representationNotSupported";

    /// <summary>
    /// Decodes a proof's multibase <c>proofValue</c>, retyping a malformed/unsupported/empty value as
    /// a <see cref="CapabilityValidationException"/>. A bad <c>proofValue</c> is invalid <i>input</i>,
    /// not a crypto-configuration fault, so this keeps it on the Debug-severity side of
    /// <see cref="LogFailedClosed"/> instead of colliding with the missing-canonicalizer
    /// <see cref="CryptographicException"/> that must stay at Warning. <see cref="MultibaseCodec.Decode"/>
    /// throws <see cref="ArgumentException"/> (null/empty), a guard before its own try, and
    /// <see cref="CryptographicException"/> (bad prefix / undecodable) — both are an invalid proofValue
    /// here (this call's only sources of those types), so both are retyped.
    /// </summary>
    private static byte[] DecodeProofValue(string proofValue)
    {
        try
        {
            return MultibaseCodec.Decode(proofValue);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new CapabilityValidationException("Malformed or unsupported proofValue.", ex);
        }
    }

    /// <summary>
    /// Verifies a capability's cryptographic proof
    /// </summary>
    public async Task<bool> VerifyCapabilityProofAsync(Capability capability)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        if (await IsCapabilityRevokedAsync(capability.Id))
        {
            return false;
        }

        // Root capabilities have no proof
        if (string.IsNullOrEmpty(capability.ParentCapability))
        {
            // Root capability should NOT have a proof
            return capability.Proof == null;
        }

        // Honour ANCESTOR revocation on the standalone path (Issue #63). VerifyCapabilityChainAsync
        // resolves and revocation-checks every link, but this single-proof path resolves only the
        // embedded immediate parent. The remaining ancestors (root + every intermediate) are present
        // in the delegation proof's capabilityChain as id strings, so sweep the WHOLE chain and
        // reject if ANY ancestor has been revoked — so a revoked root/grandparent fails here too,
        // matching the chain path, not just a revoked immediate parent (the earlier depth-1 fix).
        var chainProof = capability.Proof?.FirstDelegationProofWithChain();
        if (chainProof != null && await IsAnyAncestorRevokedAsync(chainProof.CapabilityChain))
        {
            return false;
        }

        try
        {
            // Standalone proof verification requires parent authorization context.
            return await VerifyDelegationProofAsync(
                capability,
                parentCapabilityOverride: null,
                requireParentAuthorization: true);
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause: a config/transient fault (missing canonicalizer,
            // unsupported proof type, DID-resolution error) is otherwise indistinguishable from an
            // invalid capability (Issue #64).
            LogFailedClosed(ex,
                "VerifyCapabilityProofAsync failed closed for capability {CapabilityId}", capability.Id);
            return false;
        }
    }

    /// <summary>
    /// Verifies a delegated capability proof, optionally using an already-resolved parent.
    /// </summary>
    private async Task<bool> VerifyDelegationProofAsync(
        Capability capability,
        Capability? parentCapabilityOverride,
        bool requireParentAuthorization)
    {
        if (capability.Proof == null)
        {
            return false;
        }

        // Per ZCAP-LD v0.3 a delegated zcap's proof may be an array; it is valid if AT LEAST
        // ONE capabilityDelegation proof fully verifies (signature + parent authorization +
        // chain). Try each delegation proof in turn — a single proof's failure (unsupported
        // suite, unresolvable key, bad signature, unauthorized signer) must not reject the
        // others, and non-delegation proofs in the set are simply ignored here.
        foreach (var proof in capability.Proof.DelegationProofs())
        {
            if (await VerifySingleDelegationProofAsync(
                    capability, proof, parentCapabilityOverride, requireParentAuthorization))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<bool> VerifySingleDelegationProofAsync(
        Capability capability,
        Proof proof,
        Capability? parentCapabilityOverride,
        bool requireParentAuthorization)
    {
        try
        {
            var parentCapability = parentCapabilityOverride;
            if (parentCapability == null &&
                !TryExtractEmbeddedParentFromProofChain(proof.CapabilityChain, out parentCapability))
            {
                if (requireParentAuthorization)
                {
                    // Without embedded parent context, standalone authorization cannot be proven.
                    return false;
                }
            }

            // Verify the proof signature FIRST — before any authorization resolver I/O. A forged
            // delegation proof is then rejected on the cryptographic gate without resolving any
            // controller's DID document and without emitting authorization-path logs (defense in
            // depth; also keeps a forged chain from driving the relationship resolver). The
            // invocation path (VerifyInvocationAsync) orders signature before authorization likewise.
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(proof.VerificationMethod);
            var suite = _suiteProvider.GetByProofType(proof.Type);
            if (suite == null)
            {
                return false;
            }

            // Bind the suite (chosen from the proof's type) to the resolved key's type. The proof
            // type is part of the signed payload, so tampering breaks the signature, and key
            // importers reject cross-curve bytes — but this explicit guard self-documents the
            // invariant and future-proofs against custom resolvers/suites that might erode it
            // (Issue #68).
            if (!string.Equals(suite.KeyType, resolvedKey.KeyType, StringComparison.Ordinal))
            {
                return false;
            }

            var canonicalizer = ResolveCanonicalizer(suite);
            var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
            var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
                capabilityWithoutProof,
                proof,
                canonicalizer);
            var signatureBytes = DecodeProofValue(proof.ProofValue);

            if (!suite.Verify(canonicalBytes, signatureBytes, resolvedKey.PublicKeyBytes))
                return false;

            // Signature is valid; now enforce parent authorization. Revocation is checked by the
            // entry points, not here: VerifyBuiltChainAsync sweeps every link, and the standalone
            // VerifyCapabilityProofAsync sweeps the full ancestry via IsAnyAncestorRevokedAsync
            // (Issue #63), so a single delegation proof's check stays independent of chain state.
            if (requireParentAuthorization &&
                (parentCapability == null || parentCapability.Controller is null || parentCapability.Controller.IsEmpty))
            {
                return false;
            }

            if (parentCapability != null &&
                !await IsControllerAuthorizedAsync(
                    proof.VerificationMethod, parentCapability, VerificationRelationship.CapabilityDelegation))
            {
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A single malformed/unsupported proof must not abort evaluation of the rest.
            // Cancellation is intentionally NOT swallowed so callers can still observe it.
            return false;
        }
    }

    /// <summary>
    /// Verifies an invocation request
    /// SECURITY FIX S-04: Added validation for invocation ID (replay protection)
    /// </summary>
    public Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability)
        => VerifyInvocationAsync(invocation, capability, contextProperties: null);

    /// <inheritdoc />
    public async Task<bool> VerifyInvocationAsync(
        Invocation invocation,
        Capability capability,
        Dictionary<string, object>? contextProperties)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            if (string.IsNullOrWhiteSpace(invocation.Id))
            {
                return false;
            }

            // 1. Verify the capability chain is valid. Build it once here and reuse the same chain
            // for caveat evaluation in step 7 instead of rebuilding it (BuildCapabilityChainAsync
            // throwing is caught by this method's outer fail-closed catch).
            var chain = await BuildCapabilityChainAsync(capability);
            if (!await VerifyBuiltChainAsync(chain))
                return false;

            // 2. Verify invocation proof exists and has correct purpose
            if (invocation.Proof == null || invocation.Proof.ProofPurpose != Proof.CapabilityInvocationPurpose)
                return false;

            // 2a. Invocation MUST reference the capability being verified
            if (!string.Equals(invocation.Capability, capability.Id, StringComparison.Ordinal))
                return false;

            // 2b. Proof payload fields MUST be semantically consistent with invocation fields.
            // Proof.Capability is object?: after a JSON round-trip it is a JsonElement, not a
            // CLR string, so normalize via TryExtractStringValue rather than an `as string` cast
            // (which would yield null and reject every deserialized invocation — issue #58).
            var proofCapabilityId = invocation.Proof.Capability is { } proofCapability
                ? TryExtractStringValue(proofCapability)
                : null;
            if (!string.Equals(proofCapabilityId, invocation.Capability, StringComparison.Ordinal) ||
                !string.Equals(invocation.Proof.CapabilityAction, invocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(invocation.Proof.InvocationTarget, invocation.InvocationTarget, StringComparison.Ordinal))
                return false;

            // 3. Verify invocation target matches capability
            if (!IsValidInvocationTarget(invocation.InvocationTarget, capability.InvocationTarget))
                return false;

            // 4. Verify action is allowed.
            // Null AllowedAction == unrestricted (root capability); only enforce when
            // the field is present and non-empty.
            if (capability.AllowedAction is { Length: > 0 } actions &&
                !actions.Contains(invocation.CapabilityAction))
                return false;

            // 5. Verify the invocation signature
            if (!await VerifyInvocationSignatureAsync(invocation))
                return false;

            // 6. Verify the controller is authorized
            if (!await IsControllerAuthorizedAsync(
                    invocation.Proof.VerificationMethod, capability, VerificationRelationship.CapabilityInvocation))
                return false;

            // 7. SECURITY FIX S-05: Evaluate ALL caveats from the entire chain
            // Per spec: Children inherit ALL parent caveats, so we must check the entire chain.
            // Reuses the chain built and verified in step 1 (no rebuild).
            var context = new InvocationContext
            {
                InvocationTime = DateTime.UtcNow,
                RequestedAction = invocation.CapabilityAction,
                TargetResource = invocation.InvocationTarget
            };

            // Merge caller-provided properties into the invocation context
            if (contextProperties != null)
            {
                foreach (var kvp in contextProperties)
                {
                    context.Properties[kvp.Key] = kvp.Value;
                }
            }

            // Evaluate all caveats from the complete chain (not just leaf)
            if (!await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(chain.ToArray(), context))
                return false;

            // 8. Replay protection: reject if this invocation nonce has been seen before
            var nonceExpiry = DateTime.UtcNow.Add(_nonceWindow);
            if (await _nonceStore.TryMarkAsUsedAsync(invocation.Id, nonceExpiry))
                return false;

            return true;
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a misconfiguration/transient fault is
            // distinguishable from an invalid invocation (Issue #64).
            LogFailedClosed(ex,
                "VerifyInvocationAsync failed closed for invocation {InvocationId}", invocation.Id);
            return false;
        }
    }

    /// <summary>
    /// Verifies the cryptographic signature on an invocation-style proof (proof-of-possession):
    /// resolves the proof's <c>verificationMethod</c> to a public key, re-canonicalizes the
    /// invocation-without-proof plus proof options, and checks the signature. Shared by the
    /// invocation and signed-revocation paths. Does NOT check <c>proofPurpose</c>, authorization,
    /// or replay — callers own those. Throws <see cref="CapabilityValidationException"/> on an
    /// unsupported proof type (both callers wrap this in a fail-closed catch).
    /// </summary>
    private async Task<bool> VerifyInvocationSignatureAsync(Invocation invocation)
    {
        var proof = invocation.Proof!;
        var resolvedKey = await _didResolver.ResolvePublicKeyAsync(proof.VerificationMethod);
        var suite = _suiteProvider.GetByProofType(proof.Type)
            ?? throw new CapabilityValidationException(
                $"Unsupported proof type: {proof.Type}");

        // Bind the suite (chosen from the proof's type) to the resolved key's type (Issue #68).
        if (!string.Equals(suite.KeyType, resolvedKey.KeyType, StringComparison.Ordinal))
            return false;

        var canonicalizer = ResolveCanonicalizer(suite);
        var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            invocationWithoutProof,
            proof,
            canonicalizer);
        var signatureBytes = DecodeProofValue(proof.ProofValue);

        return suite.Verify(canonicalBytes, signatureBytes, resolvedKey.PublicKeyBytes);
    }

    /// <summary>
    /// Verifies a capability delegation chain
    /// Implements the chain verification algorithm from W3C ZCAP-LD spec section 6.1
    /// </summary>
    public async Task<bool> VerifyCapabilityChainAsync(Capability capability)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            // Build the complete chain from leaf to root, then verify it. Split so callers that
            // also need the built chain (revocation authorization, invocation caveat evaluation)
            // can build once and reuse it instead of rebuilding (see VerifyBuiltChainAsync callers).
            var chain = await BuildCapabilityChainAsync(capability);
            return await VerifyBuiltChainAsync(chain);
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a config/transient fault (an unbuildable chain,
            // a missing canonicalizer, a DID-resolution error) is distinguishable from an invalid
            // capability (Issue #64).
            LogFailedClosed(ex,
                "VerifyCapabilityChainAsync failed closed for capability {CapabilityId}", capability.Id);
            return false;
        }
    }

    /// <summary>
    /// Verifies an already-built root→leaf capability chain: length bound, per-link revocation,
    /// per-link delegation proof / attenuation / expiry / caveat compatibility, and root shape.
    /// Fully fail-closed — any unexpected failure yields <c>false</c>. Callers that have already
    /// built the chain (e.g. <see cref="IsRevokerAuthorizedAsync"/>, <see cref="VerifyInvocationAsync(Invocation, Capability)"/>)
    /// pass it here to avoid a redundant rebuild.
    /// </summary>
    private async Task<bool> VerifyBuiltChainAsync(List<Capability> chain)
    {
        try
        {
            // 1. Check chain length (MUST limit, SHOULD be max 10)
            if (chain.Count > MaxChainLength)
            {
                return false;
            }

            // 2. Revocation check for all capabilities in the chain.
            foreach (var chainCapability in chain)
            {
                if (await IsCapabilityRevokedAsync(chainCapability.Id))
                {
                    return false;
                }
            }

            // 3. Verify each link in the chain
            for (int i = 1; i < chain.Count; i++)
            {
                var parent = chain[i - 1];
                var child = chain[i];

                // Verify delegation proof
                if (!await VerifyDelegationProofAsync(
                        child,
                        parentCapabilityOverride: parent,
                        requireParentAuthorization: true))
                    return false;

                // Verify attenuation (child is more restrictive than parent)
                if (!ValidateAttenuation(child, parent))
                    return false;

                // Verify expiration hasn't passed
                var childExpiresAt = child.ExpiresAt;
                if (childExpiresAt.HasValue && childExpiresAt.Value < DateTime.UtcNow)
                    return false;

                // Verify caveats are compatible
                if (!await _caveatProcessor.ValidateCaveatCompatibilityAsync(parent.Caveat, child.Caveat))
                    return false;
            }

            // 4. Verify root capability (should have no proof)
            var root = chain[0];
            if (root.Proof != null)
                return false;

            return true;
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a misconfiguration/transient fault is
            // distinguishable from an invalid chain (Issue #64). This helper only has the built
            // chain in scope, so key the diagnostic on the leaf capability being verified.
            LogFailedClosed(ex,
                "Chain verification failed closed for leaf capability {CapabilityId}",
                chain.Count > 0 ? chain[^1].Id : "(empty chain)");
            return false;
        }
    }

    /// <summary>
    /// Resolves a DID to its public key for verification.
    /// Delegates to the configured <see cref="IDidResolver"/>.
    /// </summary>
    public async Task<ResolvedKey> ResolvePublicKeyAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        return await _didResolver.ResolvePublicKeyAsync(did);
    }

    /// <summary>
    /// Builds the complete capability chain from leaf to root
    /// </summary>
    private Task<List<Capability>> BuildCapabilityChainAsync(Capability capability)
    {
        var chain = new List<Capability>();
        var current = capability;
        var visitedIds = new HashSet<string>(StringComparer.Ordinal);
        string? expectedRootId = null;

        while (true)
        {
            if (string.IsNullOrWhiteSpace(current.Id))
            {
                throw new CapabilityValidationException("Capability in chain is missing required id.");
            }

            if (!visitedIds.Add(current.Id))
            {
                throw new CapabilityValidationException(
                    $"Detected a cycle in capability chain at capability ID '{current.Id}'.");
            }

            chain.Insert(0, current); // Add to beginning to build root->leaf order

            if (string.IsNullOrEmpty(current.ParentCapability))
            {
                // Reached root
                break;
            }

            // A delegated zcap may carry several proofs; the delegation chain lives on a
            // capabilityDelegation proof. Use the first delegation proof that carries one.
            // Assumption: every capabilityDelegation proof in a set describes the SAME chain
            // (they are independent signatures over one delegation), so the first one with a
            // chain is representative — VerifyDelegationProofAsync independently accepts any
            // delegation proof whose signature and parent authorization hold.
            var chainProof = current.Proof?.FirstDelegationProofWithChain();
            if (chainProof?.CapabilityChain == null || chainProof.CapabilityChain.Length == 0)
            {
                throw new CapabilityValidationException(
                    "Delegated capability missing capabilityChain in proof");
            }

            var chainRootId = TryExtractStringValue(chainProof.CapabilityChain[0]);
            if (string.IsNullOrWhiteSpace(chainRootId))
            {
                throw new CapabilityValidationException(
                    "capabilityChain first entry MUST be the root capability ID string");
            }

            if (expectedRootId == null)
            {
                expectedRootId = chainRootId;
            }
            else if (!string.Equals(expectedRootId, chainRootId, StringComparison.Ordinal))
            {
                throw new CapabilityValidationException(
                    $"Inconsistent root capability IDs in capabilityChain. Expected '{expectedRootId}', got '{chainRootId}'.");
            }

            if (chainProof.CapabilityChain.Length < 2)
            {
                throw new CapabilityValidationException(
                    "capabilityChain MUST include root capability ID and embedded immediate parent capability object.");
            }

            if (!TryDeserializeCapability(chainProof.CapabilityChain[^1], out var parentCapability) || parentCapability == null)
            {
                throw new CapabilityValidationException(
                    "capabilityChain last entry MUST embed the immediate parent capability object");
            }

            if (!string.Equals(parentCapability.Id, current.ParentCapability, StringComparison.Ordinal))
            {
                throw new CapabilityValidationException(
                    $"Embedded parent capability ID '{parentCapability.Id}' does not match parentCapability '{current.ParentCapability}'");
            }

            current = parentCapability;
        }

        var root = chain[0];

        if (!string.IsNullOrWhiteSpace(expectedRootId) &&
            !string.Equals(expectedRootId, root.Id, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability ID '{root.Id}' does not match capabilityChain root ID '{expectedRootId}'.");
        }

        if (!string.IsNullOrEmpty(root.ParentCapability))
        {
            throw new CapabilityValidationException("Root capability MUST NOT have parentCapability.");
        }

        if (root.Proof != null)
        {
            throw new CapabilityValidationException("Root capability MUST NOT include a delegation proof.");
        }

        if (root.Controller is null || root.Controller.IsEmpty)
        {
            throw new CapabilityValidationException("Root capability MUST include a non-empty controller.");
        }

        if (string.IsNullOrWhiteSpace(root.InvocationTarget) ||
            !Uri.IsWellFormedUriString(root.InvocationTarget, UriKind.Absolute))
        {
            throw new CapabilityValidationException("Root capability MUST include a valid absolute invocationTarget URI.");
        }

        return Task.FromResult(chain);
    }

    /// <summary>
    /// Validates that child capability is more restrictive than parent (attenuation)
    /// </summary>
    private bool ValidateAttenuation(Capability child, Capability parent)
    {
        // 1. Invocation target must match or be a valid prefix of parent
        if (!IsValidInvocationTarget(child.InvocationTarget, parent.InvocationTarget))
            return false;

        // 2. Expiration must not be later than parent
        var childExpires = child.ExpiresAt;
        var parentExpires = parent.ExpiresAt;
        if (childExpires.HasValue && parentExpires.HasValue)
        {
            if (childExpires.Value > parentExpires.Value)
                return false;
        }

        // 3. Allowed actions must be subset of parent (if parent specifies).
        // Null on either side == unrestricted at that level → no check needed.
        if (parent.AllowedAction is { Length: > 0 } parentActions &&
            child.AllowedAction is { Length: > 0 } childActions)
        {
            if (!childActions.All(action => parentActions.Contains(action)))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validates invocation target matches or is valid prefix of capability target
    /// Per spec: suffix MUST start with slash or question mark if no query exists,
    /// or ampersand when the capability target already contains a query.
    /// </summary>
    private bool IsValidInvocationTarget(string invocationTarget, string capabilityTarget)
    {
        if (string.IsNullOrEmpty(invocationTarget) || string.IsNullOrEmpty(capabilityTarget))
            return false;

        // Exact match is always valid
        if (invocationTarget == capabilityTarget)
            return true;

        // Check if invocationTarget is a valid prefix extension
        if (invocationTarget.StartsWith(capabilityTarget))
        {
            var suffix = invocationTarget.Substring(capabilityTarget.Length);

            // Suffix must start with appropriate delimiter
            if (suffix.Length == 0)
                return true; // Exact match (edge case)

            // If capability target has no query string, suffix must start with / or ?
            if (!capabilityTarget.Contains('?'))
            {
                return suffix.StartsWith('/') || suffix.StartsWith('?');
            }

            // If capability target has query string, suffix must start with &
            return suffix.StartsWith('&');
        }

        return false;
    }

    /// <summary>
    /// Checks if the proof's verification method is authorized by the capability's controller(s)
    /// for the given verification relationship (<see cref="VerificationRelationship.CapabilityInvocation"/>
    /// for an invocation, <see cref="VerificationRelationship.CapabilityDelegation"/> for a delegation).
    /// A capability may have multiple controllers; the proof is authorized when ANY one of them
    /// authorizes the verification method for that relationship.
    /// </summary>
    /// <remarks>
    /// Resolves each controller's DID document via <see cref="IVerificationRelationshipResolver"/>
    /// and confirms the verification method appears in the requested relationship — closing the
    /// remaining, architectural part of Issue #65. Unlike the prior DID-string match, this honors
    /// controllers whose authorized key lives under a different DID (cross-DID references) and the
    /// per-purpose key separation DID Core defines (a key authorized only for
    /// <c>capabilityInvocation</c> cannot delegate). Fail-closed and severity-aware (Issue #64):
    /// an expected denial logs at Debug; a controller that cannot be resolved
    /// (<see cref="AuthorizationDecision.ControllerNotResolvable"/>) is severity-classified by its
    /// resolution error (<see cref="IsExpectedResolutionError"/>) — an attacker-drivable malformed/
    /// unknown/unsupported controller DID logs at Debug (so a hostile client cannot flood the Warning
    /// channel — Issue #64), while an unexpected/transient resolver fault logs at Warning. Either way
    /// it is treated as not authorized. No forgery is enabled: the signature is always verified
    /// independently.
    /// </remarks>
    private async Task<bool> IsControllerAuthorizedAsync(
        string verificationMethod, Capability capability, VerificationRelationship relationship)
    {
        if (capability.Controller is null || capability.Controller.IsEmpty)
            return false;

        foreach (var controller in capability.Controller.Values)
        {
            var result = await _relationshipResolver.IsAuthorizedForRelationshipAsync(
                controller, verificationMethod, relationship);

            switch (result.Decision)
            {
                case AuthorizationDecision.Authorized:
                    return true;
                case AuthorizationDecision.ControllerNotResolvable:
                    // The controller string comes from the presented capability, so an attacker can
                    // drive this with a fabricated/undecodable controller (e.g. did:web:does-not-exist).
                    // Per the Issue #64 severity policy, an attacker-drivable resolution failure logs at
                    // Debug (so it cannot flood the Warning channel and mask a real fault); an unexpected
                    // resolution error code (possible transient/infrastructure fault on a legitimate
                    // controller) stays at Warning.
                    _logger.Log(
                        IsExpectedResolutionError(result.ResolutionError) ? LogLevel.Debug : LogLevel.Warning,
                        "Controller '{Controller}' could not be resolved during {Relationship} authorization: {Error}",
                        controller, relationship, result.ResolutionError);
                    break;
                default: // NotAuthorized
                    _logger.LogDebug(
                        "Verification method not authorized by controller '{Controller}' for {Relationship}.",
                        controller, relationship);
                    break;
            }
        }

        return false;
    }

    private static bool TryExtractEmbeddedParentFromProofChain(object[]? capabilityChain, out Capability? parentCapability)
    {
        parentCapability = null;
        if (capabilityChain == null || capabilityChain.Length == 0)
        {
            return false;
        }

        if (TryDeserializeCapability(capabilityChain[^1], out var parsedParent))
        {
            parentCapability = parsedParent;
            return true;
        }

        return false;
    }

    private static bool TryDeserializeCapability(object element, out Capability? capability)
    {
        capability = null;

        if (element is Capability cap)
        {
            capability = cap;
            return true;
        }

        if (element is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Object)
        {
            // Use shared options so caveats round-trip through their derived-class
            // fields — without this, embedded chain capabilities carrying caveats
            // either deserialize as discriminator-only stubs or throw on the
            // abstract Caveat base type (Issue #39).
            capability = JsonSerializer.Deserialize<Capability>(jsonElement.GetRawText(), ZcapJsonOptions.Default);
            return capability != null;
        }

        return false;
    }

    private static string? TryExtractStringValue(object element)
    {
        if (element is string value)
        {
            return value;
        }

        if (element is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.String)
        {
            return jsonElement.GetString();
        }

        return null;
    }

    /// <summary>
    /// Returns true if ANY capability referenced by a delegation proof's <c>capabilityChain</c> has
    /// been revoked. The chain carries the root id and every intermediate ancestor id — including
    /// the immediate parent — as id strings (the final embedded parent object's id also appears as
    /// a string), so a string-level sweep covers the full ancestry without resolving each ancestor
    /// as a <see cref="Capability"/>. This lets the standalone <see cref="VerifyCapabilityProofAsync"/>
    /// path honour ancestor revocation at every depth, matching the per-link sweep in
    /// <see cref="VerifyBuiltChainAsync"/> (Issue #63). Ids are de-duplicated so a chain that repeats
    /// an ancestor id (e.g. a directly-root-delegated parent) is not queried twice.
    /// </summary>
    private async Task<bool> IsAnyAncestorRevokedAsync(object[]? capabilityChain)
    {
        if (capabilityChain == null)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var element in capabilityChain)
        {
            var id = ExtractCapabilityId(element);
            if (!string.IsNullOrEmpty(id) && seen.Add(id) &&
                await IsCapabilityRevokedAsync(id))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts the capability id from a <c>capabilityChain</c> element — a bare id string for
    /// root/intermediate ancestors, or the <c>id</c> of an embedded parent object — without a
    /// full model deserialization. Returns null when no id can be read.
    /// </summary>
    private static string? ExtractCapabilityId(object element)
    {
        if (TryExtractStringValue(element) is { Length: > 0 } stringId)
        {
            return stringId;
        }

        if (element is Capability cap)
        {
            return cap.Id;
        }

        if (element is JsonElement obj && obj.ValueKind == JsonValueKind.Object &&
            obj.TryGetProperty("id", out var idProp) && idProp.ValueKind == JsonValueKind.String)
        {
            return idProp.GetString();
        }

        return null;
    }

    private IDocumentCanonicalizer ResolveCanonicalizer(ICryptoSuite suite)
    {
        return _canonicalizerProvider.GetByMethod(suite.CanonicalizationMethod)
            ?? throw new CryptographicException(
                $"No canonicalizer registered for method: {suite.CanonicalizationMethod}");
    }

    /// <summary>
    /// Revokes a capability from a <b>cryptographically signed</b> revocation request
    /// (proof-of-possession). The <paramref name="signedRevocation"/> must be a
    /// <see cref="Proof.CapabilityRevocationPurpose"/> proof, carrying <c>capabilityAction =
    /// "revoke"</c>, bound to <paramref name="capability"/> (its <c>capability</c> field equals
    /// <c>capability.Id</c>). The method <i>authenticates</i> the revoker by verifying the
    /// signature against the key resolved from <c>proof.verificationMethod</c> — possession of that
    /// private key is the proof of control — then <i>authorizes</i> by requiring that verification
    /// method to control the capability or any ancestor in its (cryptographically verified)
    /// delegation chain. A signed <c>reason</c>/<c>metadata</c> in the proof is recorded.
    /// </summary>
    /// <remarks>
    /// <b>Fail-closed:</b> any structural, signature, authorization, replay, or infrastructure
    /// failure returns <c>false</c> and records nothing. Caveats are deliberately <b>not</b>
    /// evaluated — revocation is a control-plane authority action, so an exhausted/expired caveat
    /// must not prevent a legitimate controller from revoking. The recorded <c>RevokedBy</c> is the
    /// authenticated verification method's bare DID, never a client-asserted string. Replay
    /// protection keys on <c>signedRevocation.Id</c>; clients must mint a fresh id per request.
    /// <para>
    /// <b>Authorization requires a fully valid chain.</b> The caveat carve-out above is narrow:
    /// authorization runs <see cref="VerifyCapabilityChainAsync"/>, which still enforces the leaf's
    /// own <c>expires</c> and every link's revocation state (it only skips <i>evaluating</i> caveats,
    /// not their delegation-time compatibility). Consequence: a capability that is itself expired, or
    /// one of whose ancestors has already been revoked, fails chain verification and therefore
    /// <b>cannot be explicitly (re-)revoked</b> — it is already inert, so this is by design rather
    /// than a bug, but callers building revocation audit trails should not expect a record for an
    /// already-dead capability.
    /// </para>
    /// COMPLIANCE: MUST-21, SHOULD-07.
    /// </remarks>
    /// <param name="capability">The capability to revoke, with its full delegation chain (for authorization).</param>
    /// <param name="signedRevocation">The signed revocation request (see <see cref="ISigningService.SignRevocationAsync"/>).</param>
    /// <returns>True if authenticated, authorized, fresh, and recorded; otherwise false.</returns>
    public async Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));
        if (signedRevocation == null)
            throw new ArgumentNullException(nameof(signedRevocation));

        try
        {
            if (string.IsNullOrWhiteSpace(signedRevocation.Id))
                return false;

            var proof = signedRevocation.Proof;
            // Must be a revocation-purpose proof carrying the revoke action, bound to THIS capability.
            if (proof is null || proof.ProofPurpose != Proof.CapabilityRevocationPurpose)
                return false;
            if (signedRevocation.CapabilityAction != Invocation.RevokeAction)
                return false;
            if (!string.Equals(signedRevocation.Capability, capability.Id, StringComparison.Ordinal))
                return false;

            // Proof payload fields MUST be consistent with the invocation body. Proof.Capability is
            // object?: after a JSON round-trip it is a JsonElement, so normalize via
            // TryExtractStringValue rather than an `as string` cast (issue #58).
            var proofCapabilityId = proof.Capability is { } proofCapability
                ? TryExtractStringValue(proofCapability)
                : null;
            if (!string.Equals(proofCapabilityId, signedRevocation.Capability, StringComparison.Ordinal) ||
                !string.Equals(proof.CapabilityAction, signedRevocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(proof.InvocationTarget, signedRevocation.InvocationTarget, StringComparison.Ordinal))
                return false;

            // AUTHENTICATE: the signature proves the caller holds verificationMethod's private key.
            if (!await VerifyInvocationSignatureAsync(signedRevocation))
                return false;

            // AUTHORIZE: the authenticated verificationMethod must control the capability or an
            // ancestor. IsRevokerAuthorizedAsync verifies the chain first (fail-closed).
            if (!await IsRevokerAuthorizedAsync(capability, proof.VerificationMethod))
                return false;

            // Record the revocation durably BEFORE consuming the replay nonce. If the store write
            // throws, control passes to the fail-closed catch with the nonce still unconsumed, so a
            // legitimate retry with the same signed request is not mistaken for a replay when nothing
            // was actually recorded. Revocation is idempotent, so the only cost of this ordering is a
            // replayed-after-eviction request re-applying the same record before the nonce check
            // below rejects it — harmless. (INonceStore has no release primitive, so reordering is
            // the minimal robust fix.)
            var revokerDid = proof.VerificationMethod.Split('#')[0];
            var (reason, metadata) = ExtractSignedRevocationDetails(proof);
            if (!await RevokeCapabilityCoreAsync(capability.Id, revokerDid, reason, metadata))
                return false;

            // Replay protection (nonce = request id): consumed only after the durable write
            // succeeded. A replayed id still returns false here; the record was idempotent.
            var nonceExpiry = DateTime.UtcNow.Add(_nonceWindow);
            if (await _nonceStore.TryMarkAsUsedAsync(signedRevocation.Id, nonceExpiry))
                return false;

            return true;
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a misconfiguration/transient fault (a signature
            // verification error, a store write failure, a DID-resolution error) is distinguishable
            // from a structurally invalid or unauthorized revocation request (Issue #64).
            LogFailedClosed(ex,
                "RevokeCapabilityAsync failed closed for capability {CapabilityId}", capability.Id);
            return false;
        }
    }

    /// <summary>
    /// True when <paramref name="verificationMethod"/> may revoke <paramref name="capability"/> —
    /// i.e. it controls the capability or any ancestor in its delegation chain. Cryptographically
    /// verifies the chain before trusting any controller fields; a forged or invalid chain yields
    /// false. <paramref name="verificationMethod"/> is the authenticated proof verification method
    /// (or a bare DID); authentication is performed by the caller.
    /// </summary>
    private async Task<bool> IsRevokerAuthorizedAsync(Capability capability, string verificationMethod)
    {
        try
        {
            // Build the chain once, then verify it cryptographically before trusting controller fields.
            // Without that verification, a caller passing a crafted Capability with a tampered controller
            // could authorize themselves to revoke a legitimate capability. (VerifyBuiltChainAsync reuses
            // this built chain instead of rebuilding it — see VerifyCapabilityChainAsync.)
            var chain = await BuildCapabilityChainAsync(capability);

            if (!await VerifyBuiltChainAsync(chain))
                return false;

            // Document-based authorization (Issue #65): the revoker is authorized when ANY link in
            // the cryptographically verified chain authorizes its verification method for the
            // capabilityDelegation relationship — revocation is a delegation-authority action (the
            // authority to delegate is the authority to revoke that delegation). This resolves each
            // controller's DID document (via the same IVerificationRelationshipResolver the
            // invocation/delegation paths use), so it honors cross-DID references and per-purpose key
            // separation: a key the controller's document lists only under capabilityInvocation can
            // no longer revoke. Self-revoke (the leaf's own controller) and up-chain delegators are
            // both covered because every link is checked.
            foreach (var link in chain)
            {
                if (await IsControllerAuthorizedAsync(
                        verificationMethod, link, VerificationRelationship.CapabilityDelegation))
                    return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail closed on ANY fault from the chain walk, not just a malformed chain.
            // BuildCapabilityChainAsync can throw CapabilityValidationException, JsonException, or a
            // DID-resolution error — all of which mean "cannot establish authorization", i.e. not
            // authorized. RevokeCapabilityAsync's own top-level catch would also fail closed (no caller
            // was ever at crash risk), but catching here keeps the authorization decision local and
            // attributes the cause to THIS step rather than the broader revocation flow (PR #84 review;
            // Issue #64). Severity is chosen by LogFailedClosed.
            LogFailedClosed(ex,
                "IsRevokerAuthorizedAsync failed closed for capability {CapabilityId}", capability.Id);
            return false;
        }
    }

    /// <summary>
    /// Extracts the signed <c>reason</c>/<c>metadata</c> a revocation proof carried in its
    /// <see cref="Proof.AdditionalProperties"/>. These were part of the verified signature, so they
    /// are authenticated by the time this is called.
    /// </summary>
    private static (string? Reason, IDictionary<string, string>? Metadata) ExtractSignedRevocationDetails(Proof proof)
    {
        string? reason = null;
        IDictionary<string, string>? metadata = null;

        if (proof.AdditionalProperties is { } extra)
        {
            if (extra.TryGetValue(Proof.RevocationReasonField, out var reasonElement) &&
                reasonElement.ValueKind == JsonValueKind.String)
            {
                reason = reasonElement.GetString();
            }

            if (extra.TryGetValue(Proof.RevocationMetadataField, out var metadataElement) &&
                metadataElement.ValueKind == JsonValueKind.Object)
            {
                metadata = metadataElement.Deserialize<Dictionary<string, string>>(ZcapJsonOptions.Default);
            }
        }

        return (reason, metadata);
    }

    /// <summary>
    /// Checks if a capability has been revoked
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    public Task<bool> IsCapabilityRevokedAsync(string capabilityId)
    {
        if (string.IsNullOrEmpty(capabilityId))
            return Task.FromResult(false);

        return _revocationService.IsRevokedAsync(capabilityId);
    }

    private async Task<bool> RevokeCapabilityCoreAsync(
        string capabilityId,
        string revokerDid,
        string? reason = null,
        IDictionary<string, string>? metadata = null)
    {
        await _revocationService.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId,
            RevokedBy = revokerDid,
            Reason = reason,
            Metadata = metadata
        });

        return true;
    }
}
