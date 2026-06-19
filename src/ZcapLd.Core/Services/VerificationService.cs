using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetCrypto;
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
    private readonly IRevocationService _revocationService;
    private readonly INonceStore _nonceStore;

    // Stage C (#108): canonicalization + signature verification delegated to DataProofs' legacy
    // cryptosuites. Suite metadata (proof type, the #68 key-type binding, context URL) comes from the
    // fixed ZcapSuiteCatalog; the canonicalization method is fixed per service instance.
    private readonly LegacyProofCrypto _legacyProofCrypto = new();

    private readonly TimeSpan _nonceWindow;
    private readonly TimeSpan _freshnessClockSkew;
    private readonly ILogger _logger;
    private readonly IVerificationRelationshipResolver _relationshipResolver;
    private readonly IRootCapabilityResolver? _rootResolver;
    private readonly VerificationPolicy _policy;
    private const int MaxChainLength = 10; // Per spec: SHOULD limit to 10
    private const string RootIdPrefix = "urn:zcap:root:";
    private const string ZcapV1Context = "https://w3id.org/zcap/v1";

    /// <summary>
    /// Default window during which invocation nonces are tracked for replay protection. Also serves as
    /// the upper staleness bound for <c>proof.created</c> freshness checking (Issue #71): widening this
    /// window extends BOTH the replay window and the acceptable signing age, so an invocation signed up
    /// to this long ago is accepted. Configurable per instance via the <c>nonceWindow</c> constructor
    /// parameter.
    /// </summary>
    public static readonly TimeSpan DefaultNonceWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default tolerance for a signed proof's <c>created</c> time being in the future (clock skew between
    /// signer and verifier) before it is rejected as not-yet-valid (Issue #71). Configurable per instance
    /// via the <c>freshnessClockSkew</c> constructor parameter.
    /// </summary>
    public static readonly TimeSpan DefaultFreshnessClockSkew = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Convenience constructor (JCS canonicalization). Each instance gets its own process-local
    /// <see cref="InMemoryNonceStore"/>, so replay state is NOT shared across
    /// <see cref="VerificationService"/> instances; in a per-request / multi-instance setup supply a
    /// shared <see cref="INonceStore"/> via the full constructor (Issue #62; PR #88 review).
    /// </summary>
    public VerificationService(IDidResolver didResolver, ICaveatProcessor caveatProcessor)
        : this(didResolver, caveatProcessor, new RevocationService(new InMemoryRevocationStore()))
    {
    }

    /// <summary>
    /// Convenience constructor with a custom revocation service (JCS canonicalization). Each instance
    /// gets its own process-local <see cref="InMemoryNonceStore"/>; supply a shared
    /// <see cref="INonceStore"/> via the full constructor for multi-instance setups (Issue #62).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        IRevocationService revocationService)
        : this(didResolver, caveatProcessor, revocationService, new InMemoryNonceStore())
    {
    }

    /// <summary>
    /// Full constructor. The optional <paramref name="logger"/> receives a diagnostic whenever
    /// verification fails closed on an unexpected exception, so operators can tell a
    /// misconfiguration/transient fault apart from an invalid capability (Issue #64); defaults to
    /// <see cref="NullLogger"/>. The optional <paramref name="relationshipResolver"/> performs
    /// controller authorization by resolving the controller's DID document and checking the relevant
    /// verification relationship (<c>capabilityInvocation</c> / <c>capabilityDelegation</c>) —
    /// Issue #65 — resolved from the explicit argument, else the supplied
    /// <paramref name="didResolver"/> if it also implements <see cref="IVerificationRelationshipResolver"/>,
    /// else a <c>did:key</c>-backed default. The optional <paramref name="freshnessClockSkew"/>
    /// tolerates a signed <c>proof.created</c> being up to that far in the future (Issue #71; default
    /// <see cref="DefaultFreshnessClockSkew"/>). The optional <paramref name="policy"/> enables opt-in
    /// verifier-side SHOULD checks (Issue #73; default <see cref="VerificationPolicy.Default"/>).
    /// All proofs are verified under RDFC-1.0 canonicalization (the only canonicalization ZCAP-LD
    /// supports; required for interop with <c>@digitalbazaar/zcap</c>).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        IRevocationService revocationService,
        INonceStore nonceStore,
        TimeSpan? nonceWindow = null,
        ILogger<VerificationService>? logger = null,
        IVerificationRelationshipResolver? relationshipResolver = null,
        IRootCapabilityResolver? rootResolver = null,
        TimeSpan? freshnessClockSkew = null,
        VerificationPolicy? policy = null)
    {
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));
        _caveatProcessor = caveatProcessor ?? throw new ArgumentNullException(nameof(caveatProcessor));
        _revocationService = revocationService ?? throw new ArgumentNullException(nameof(revocationService));
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        _nonceWindow = nonceWindow ?? DefaultNonceWindow;
        _freshnessClockSkew = freshnessClockSkew ?? DefaultFreshnessClockSkew;
        _logger = logger ?? NullLogger<VerificationService>.Instance;
        _relationshipResolver = relationshipResolver
            ?? didResolver as IVerificationRelationshipResolver
            ?? CreateDefaultRelationshipResolver();
        // Optional: spec-exact chains reference the root by id only, so the verifier needs a way to
        // obtain it (Issue #50). Resolution order mirrors the relationship resolver above: the explicit
        // argument, else the supplied didResolver if it ALSO implements IRootCapabilityResolver (a
        // resolver that can dereference its own roots self-provides), else null. Null is the secure
        // default — delegated verification then requires an explicit root via the overloads, otherwise
        // it fails closed.
        _rootResolver = rootResolver ?? didResolver as IRootCapabilityResolver;
        _policy = policy ?? VerificationPolicy.Default;
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
    /// Public-boundary choke point for the <c>...DetailedAsync</c> verify methods that closes the
    /// part-B logging gap (Issue #70 / #64): it awaits a verification core and, when the result is a
    /// <i>structurally-valid</i> denial — revoked, expired, bad signature, unauthorized controller,
    /// attenuation, caveat, replay, chain-too-long, malformed — logs that reason once before returning.
    /// Previously these branches returned <c>false</c> silently; only the exception path was logged.
    /// Such denials are attacker-drivable, so they log at <see cref="LogLevel.Debug"/> (a hostile client
    /// cannot flood the operator's Warning channel), matching the severity philosophy of
    /// <see cref="LogFailedClosed"/>. A <see cref="VerificationOutcome.CouldNotVerify"/> outcome was
    /// already logged with type-aware severity at the fault site by <see cref="LogFailedClosed"/>, so it
    /// is not logged again here; a successful result is not logged. Any exception thrown by the core
    /// (e.g. a null-argument guard) propagates unchanged so the existing throw contract is preserved.
    /// </summary>
    private async Task<VerificationResult> LogDenial(
        Task<VerificationResult> resultTask, string operation, string? id)
    {
        var result = await resultTask;
        if (!result.IsValid && result.Outcome != VerificationOutcome.CouldNotVerify)
        {
            _logger.LogDebug("{Operation} denied for {SubjectId}: {Outcome} — {Reason}",
                operation, id ?? "(null)", result.Outcome, result.Message);
        }

        return result;
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
    /// Verifies a capability's cryptographic proof. For a delegated capability the immediate parent
    /// must be obtainable: a deeper delegation embeds it in the proof chain, but a first-level
    /// delegation references the root by id only, so this overload succeeds for first-level caps only
    /// when an <see cref="IRootCapabilityResolver"/> is configured. Use
    /// <see cref="VerifyCapabilityProofAsync(Capability, Capability)"/> to supply the root explicitly.
    /// </summary>
    public async Task<bool> VerifyCapabilityProofAsync(Capability capability)
        => (await VerifyCapabilityProofDetailedAsync(capability)).IsValid;

    /// <inheritdoc />
    public async Task<bool> VerifyCapabilityProofAsync(Capability capability, Capability rootCapability)
        => (await VerifyCapabilityProofDetailedAsync(capability, rootCapability)).IsValid;

    /// <inheritdoc />
    public Task<VerificationResult> VerifyCapabilityProofDetailedAsync(Capability capability)
        => LogDenial(VerifyCapabilityProofCoreAsync(capability, explicitRoot: null),
            "VerifyCapabilityProof", capability?.Id);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyCapabilityProofDetailedAsync(Capability capability, Capability rootCapability)
    {
        if (rootCapability == null)
            throw new ArgumentNullException(nameof(rootCapability));
        return LogDenial(VerifyCapabilityProofCoreAsync(capability, rootCapability),
            "VerifyCapabilityProof", capability?.Id);
    }

    private async Task<VerificationResult> VerifyCapabilityProofCoreAsync(Capability capability, Capability? explicitRoot)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        if (await IsCapabilityRevokedAsync(capability.Id))
        {
            return VerificationResult.Fail(VerificationOutcome.Revoked,
                $"Capability '{capability.Id}' has been revoked.");
        }

        // Root capabilities have no proof
        if (string.IsNullOrEmpty(capability.ParentCapability))
        {
            // Root capability should NOT have a proof
            return capability.Proof == null
                ? VerificationResult.Valid
                : VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Root capability MUST NOT include a delegation proof.");
        }

        // Honour ANCESTOR revocation on the standalone path (Issue #63). VerifyCapabilityChainAsync
        // resolves and revocation-checks every link, but this single-proof path resolves only the
        // immediate parent. The remaining ancestors (root + every intermediate) are present in the
        // delegation proof's capabilityChain as id strings (the immediate parent as the embedded
        // object), so sweep the WHOLE chain and reject if ANY ancestor has been revoked — so a
        // revoked root/grandparent fails here too, matching the chain path (the earlier depth-1 fix).
        var chainProof = capability.Proof?.FirstDelegationProofWithChain();
        if (chainProof != null && await IsAnyAncestorRevokedAsync(chainProof.CapabilityChain))
        {
            return VerificationResult.Fail(VerificationOutcome.Revoked,
                "An ancestor capability in the delegation chain has been revoked.");
        }

        try
        {
            // Standalone proof verification requires parent authorization context. For a first-level
            // delegation the parent is the root (referenced by id only), obtained via explicitRoot or
            // the configured resolver inside VerifySingleDelegationProofAsync.
            return await VerifyDelegationProofAsync(
                capability,
                parentCapabilityOverride: null,
                requireParentAuthorization: true,
                explicitRoot: explicitRoot);
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause: a config/transient fault (missing canonicalizer,
            // unsupported proof type, DID-resolution error) is otherwise indistinguishable from an
            // invalid capability (Issue #64). Surface it as CouldNotVerify so callers can tell
            // "couldn't check" from "invalid" (Issue #70).
            LogFailedClosed(ex,
                "VerifyCapabilityProofAsync failed closed for capability {CapabilityId}", capability.Id);
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify, ex.Message);
        }
    }

    /// <summary>
    /// Verifies a delegated capability proof, optionally using an already-resolved parent. Returns the
    /// outcome of the first delegation proof that fully verifies, otherwise the most-recent failure
    /// reason (Issue #70).
    /// </summary>
    private async Task<VerificationResult> VerifyDelegationProofAsync(
        Capability capability,
        Capability? parentCapabilityOverride,
        bool requireParentAuthorization,
        Capability? explicitRoot = null,
        bool applyCreatedCheck = true)
    {
        if (capability.Proof == null)
        {
            return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                "Delegated capability is missing a proof.");
        }

        // Per ZCAP-LD v0.3 a delegated zcap's proof may be an array; it is valid if AT LEAST
        // ONE capabilityDelegation proof fully verifies (signature + parent authorization +
        // chain). Try each delegation proof in turn — a single proof's failure (unsupported
        // suite, unresolvable key, bad signature, unauthorized signer) must not reject the
        // others, and non-delegation proofs in the set are simply ignored here. When every proof
        // fails, surface the last specific reason (the common single-proof case is exact).
        var lastFailure = VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
            "No capabilityDelegation proof could be verified.");
        foreach (var proof in capability.Proof.DelegationProofs())
        {
            var result = await VerifySingleDelegationProofAsync(
                capability, proof, parentCapabilityOverride, requireParentAuthorization, explicitRoot,
                applyCreatedCheck);
            if (result.IsValid)
            {
                return result;
            }

            lastFailure = result;
        }

        return lastFailure;
    }

    private async Task<VerificationResult> VerifySingleDelegationProofAsync(
        Capability capability,
        Proof proof,
        Capability? parentCapabilityOverride,
        bool requireParentAuthorization,
        Capability? explicitRoot = null,
        bool applyCreatedCheck = true)
    {
        try
        {
            // Delegation-proof `created` soundness (Issue #99): reject a future-dated (beyond clock
            // skew) or unparseable `created` always, and a missing `created` under policy. Checked
            // BEFORE the signature gate — mirroring the invocation-side #71 freshness check — so it is a
            // cheap local gate independent of resolver I/O, and the failure cases stay observable
            // without a valid signature. There is NO staleness lower-bound: a durable delegation signed
            // long ago must still verify. Skipped on the revocation-authorization path
            // (applyCreatedCheck == false) so a delegation with a malformed `created` remains revocable,
            // mirroring the #73 expiration-ceiling carve-out.
            if (applyCreatedCheck && CheckDelegationProofCreated(proof) is { } createdFailure)
                return createdFailure;

            // Acquire the immediate parent. The chain-walk caller supplies it directly; the
            // standalone path derives it from the proof chain — an embedded last entry for a deeper
            // delegation, or the resolved root (by id) for a first-level delegation (Issue #50).
            var parentCapability = parentCapabilityOverride
                ?? await ResolveImmediateParentAsync(capability, proof.CapabilityChain, explicitRoot);
            if (parentCapability == null && requireParentAuthorization)
            {
                // Without parent context, standalone authorization cannot be proven.
                return VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
                    "Cannot resolve the immediate parent to authorize the delegation.");
            }

            // Verify the proof signature FIRST — before any authorization resolver I/O. A forged
            // delegation proof is then rejected on the cryptographic gate without resolving any
            // controller's DID document and without emitting authorization-path logs (defense in
            // depth; also keeps a forged chain from driving the relationship resolver). The
            // invocation path (VerifyInvocationAsync) orders signature before authorization likewise.
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(proof.VerificationMethod);
            var suite = ZcapSuiteCatalog.GetByProofType(proof.Type);
            if (suite == null)
            {
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    $"Unsupported delegation proof type: {proof.Type}");
            }

            // Bind the suite (chosen from the proof's type) to the resolved key's type (Issue #68);
            // see KeyTypeMatches for the rationale and the resolver↔suite vocabulary contract.
            if (!KeyTypeMatches(suite, resolvedKey))
            {
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    "Resolved key type does not match the delegation proof's suite.");
            }

            var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);

            if (!_legacyProofCrypto.Verify(capabilityWithoutProof, proof, resolvedKey))
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    "Delegation proof signature did not verify.");

            // Signature is valid; now enforce parent authorization. Revocation is checked by the
            // entry points, not here: VerifyBuiltChainAsync sweeps every link, and the standalone
            // VerifyCapabilityProofAsync sweeps the full ancestry via IsAnyAncestorRevokedAsync
            // (Issue #63), so a single delegation proof's check stays independent of chain state.
            if (requireParentAuthorization &&
                (parentCapability == null || parentCapability.Controller is null || parentCapability.Controller.IsEmpty))
            {
                return VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
                    "Parent capability has no controller to authorize the delegation.");
            }

            if (parentCapability != null &&
                !await IsControllerAuthorizedAsync(
                    proof.VerificationMethod, parentCapability, VerificationRelationship.CapabilityDelegation))
            {
                return VerificationResult.Fail(VerificationOutcome.UnauthorizedController,
                    "Delegation signer is not authorized by the parent capability's controller.");
            }

            // The standalone proof check must also reject a child broader than its parent
            // (attenuation) or already expired; otherwise a re-signed child that expands authority
            // beyond its parent can pass VerifyCapabilityProofAsync while VerifyCapabilityChainAsync
            // correctly rejects it (Issue #69). Skipped when no parent context is available.
            if (parentCapability != null && !ValidateAttenuation(capability, parentCapability))
            {
                return VerificationResult.Fail(VerificationOutcome.AttenuationViolation,
                    "Delegated capability exceeds the authority of its parent.");
            }

            // Caveat compatibility (symmetric with the chain path's check at VerifyBuiltChainAsync): a
            // child MUST NOT declare a same-type caveat that is LESS restrictive than its parent's — a
            // later ExpirationCaveat, a larger UsageCount, or a ValidWhileTrue retargeted to a URI the
            // parent does not control. Without this, the standalone single-proof check accepted such a
            // child while the full chain verifier rejected it (the #69 attenuation fix, left open for
            // caveats).
            if (parentCapability != null &&
                !await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCapability.Caveat, capability.Caveat))
            {
                return VerificationResult.Fail(VerificationOutcome.CaveatFailed,
                    "Delegated capability's caveats are not compatible with its parent's.");
            }

            if (capability.ExpiresAt is { } childExpiresAt && childExpiresAt < DateTime.UtcNow)
            {
                return VerificationResult.Fail(VerificationOutcome.Expired,
                    "Delegated capability has expired.");
            }

            return VerificationResult.Valid;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A single malformed/unsupported proof must not abort evaluation of the rest, so this is
            // caught here rather than at the entry point. Classify by exception type (mirroring
            // LogFailedClosed): an expected, attacker-drivable validation/parse failure (unresolvable
            // verificationMethod, malformed proofValue, non-spec chain shape) is an invalid delegation;
            // an unexpected fault (missing canonicalizer/suite, transient resolver error) is
            // "couldn't check" (Issue #64 / #70). Either way this proof is rejected; cancellation is
            // intentionally NOT swallowed so callers can still observe it.
            var outcome = ex is CapabilityValidationException or DelegationException
                or InvocationException or CaveatException or FormatException or JsonException
                ? VerificationOutcome.InvalidDelegation
                : VerificationOutcome.CouldNotVerify;
            return VerificationResult.Fail(outcome, ex.Message);
        }
    }

    /// <summary>
    /// Verifies an invocation request
    /// SECURITY FIX S-04: Added validation for invocation ID (replay protection)
    /// </summary>
    public async Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability)
        => (await VerifyInvocationDetailedAsync(invocation, capability)).IsValid;

    /// <inheritdoc />
    public async Task<bool> VerifyInvocationAsync(
        Invocation invocation,
        Capability capability,
        Dictionary<string, object>? contextProperties)
        => (await VerifyInvocationDetailedAsync(invocation, capability, contextProperties)).IsValid;

    /// <inheritdoc />
    public async Task<bool> VerifyInvocationAsync(
        Invocation invocation,
        Capability capability,
        Capability rootCapability,
        Dictionary<string, object>? contextProperties)
        => (await VerifyInvocationDetailedAsync(invocation, capability, rootCapability, contextProperties)).IsValid;

    /// <inheritdoc />
    public Task<VerificationResult> VerifyInvocationDetailedAsync(Invocation invocation, Capability capability)
        => LogDenial(VerifyInvocationCoreAsync(invocation, capability, contextProperties: null, explicitRoot: null),
            "VerifyInvocation", invocation?.Id);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyInvocationDetailedAsync(
        Invocation invocation,
        Capability capability,
        Dictionary<string, object>? contextProperties)
        => LogDenial(VerifyInvocationCoreAsync(invocation, capability, contextProperties, explicitRoot: null),
            "VerifyInvocation", invocation?.Id);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyInvocationDetailedAsync(
        Invocation invocation,
        Capability capability,
        Capability rootCapability,
        Dictionary<string, object>? contextProperties)
    {
        if (rootCapability == null)
            throw new ArgumentNullException(nameof(rootCapability));
        return LogDenial(VerifyInvocationCoreAsync(invocation, capability, contextProperties, explicitRoot: rootCapability),
            "VerifyInvocation", invocation?.Id);
    }

    // ─── Path A: Data Integrity capabilityInvocation (@digitalbazaar/zcap-compatible) ───────────────

    /// <summary>
    /// Verifies a <c>@digitalbazaar/zcap</c>-compatible ("Path A") Data Integrity invocation: an
    /// application document carrying a <c>capabilityInvocation</c> proof whose proof object alone holds
    /// <c>capability</c>/<c>capabilityAction</c>/<c>invocationTarget</c> (they are NOT duplicated into the
    /// signed document body). The signature is verified over the application document
    /// (<c>SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))</c>); the capability chain, attenuation,
    /// caveats, controller authorization, freshness and replay are then enforced exactly as for the
    /// self-contained <see cref="Invocation"/> envelope path. For a DELEGATED invocation, supply the root
    /// via the <c>rootCapability</c> overload (or register an <see cref="IRootCapabilityResolver"/>).
    /// </summary>
    public async Task<bool> VerifyCapabilityInvocationAsync(JsonObject securedDocument)
        => (await VerifyCapabilityInvocationDetailedAsync(securedDocument)).IsValid;

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject)"/>
    public async Task<bool> VerifyCapabilityInvocationAsync(JsonObject securedDocument, Capability rootCapability)
        => (await VerifyCapabilityInvocationDetailedAsync(securedDocument, rootCapability)).IsValid;

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject)"/>
    public Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(JsonObject securedDocument)
        => LogDenial(VerifyCapabilityInvocationCoreAsync(securedDocument, explicitRoot: null, contextProperties: null),
            "VerifyCapabilityInvocation", TryGetDocId(securedDocument));

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject)"/>
    public Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(JsonObject securedDocument, Capability rootCapability)
    {
        ArgumentNullException.ThrowIfNull(rootCapability);
        return LogDenial(VerifyCapabilityInvocationCoreAsync(securedDocument, explicitRoot: rootCapability, contextProperties: null),
            "VerifyCapabilityInvocation", TryGetDocId(securedDocument));
    }

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject)"/>
    public Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(
        JsonObject securedDocument, Capability? rootCapability, Dictionary<string, object>? contextProperties)
        => LogDenial(VerifyCapabilityInvocationCoreAsync(securedDocument, rootCapability, contextProperties),
            "VerifyCapabilityInvocation", TryGetDocId(securedDocument));

    private static string? TryGetDocId(JsonObject? doc)
        => doc is not null && doc.TryGetPropertyValue("id", out var node)
           && node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private async Task<VerificationResult> VerifyCapabilityInvocationCoreAsync(
        JsonObject securedDocument, Capability? explicitRoot, Dictionary<string, object>? contextProperties)
    {
        ArgumentNullException.ThrowIfNull(securedDocument);
        try
        {
            // 1. Split the secured document into the signed application document and its proof.
            if (!securedDocument.TryGetPropertyValue("proof", out var proofNode) || proofNode is null)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Secured invocation document is missing a proof.");

            Proof? proof;
            try { proof = proofNode.Deserialize<Proof>(ZcapJsonOptions.Default); }
            catch (JsonException) { proof = null; }
            if (proof is null)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof could not be parsed.");

            if (proof.ProofPurpose != Proof.CapabilityInvocationPurpose)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Proof does not have the capabilityInvocation proofPurpose.");

            var applicationDocument = securedDocument.DeepClone()!.AsObject();
            applicationDocument.Remove("proof");

            // 2. Freshness (Issue #71): bound replay independently of nonce eviction; reuse the validated
            // instant for time-based caveats.
            var createdUtc = GetFreshProofCreatedUtc(proof);
            if (createdUtc is null)
                return VerificationResult.Fail(VerificationOutcome.StaleProof,
                    "Invocation proof.created is missing, future-dated beyond clock skew, or older than the replay window.");

            // 3. The invocation parameters live ONLY in the proof (Path A).
            var proofCapability = proof.Capability;
            if (proofCapability is null)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof is missing capability.");
            if (string.IsNullOrEmpty(proof.CapabilityAction))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof is missing capabilityAction.");
            if (string.IsNullOrEmpty(proof.InvocationTarget))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof is missing invocationTarget.");

            // 4. Resolve the invoked capability from the proof's capability shape: a root id string is
            // dereferenced to the trusted root; an embedded delegated zcap is used directly (its chain is
            // verified in step 5). A delegated invocation supplying only an id string is rejected (Issue #51).
            Capability capability;
            if (proofCapability.IsRootReference)
            {
                if (string.IsNullOrEmpty(proofCapability.CapabilityId))
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        "Root invocation is missing the root capability id.");
                capability = await ResolveRootCapabilityAsync(proofCapability.CapabilityId, explicitRoot);
            }
            else if (proofCapability.EmbeddedCapability is { } embedded)
            {
                capability = embedded;
            }
            else
            {
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Delegated invocation must embed the full delegated capability object.");
            }

            // 5. Verify the capability chain (delegation proofs, attenuation, @context, expiry, revocation).
            var chain = await BuildCapabilityChainAsync(capability, explicitRoot);
            var chainResult = await VerifyBuiltChainAsync(chain);
            if (!chainResult.IsValid)
                return chainResult;

            // 6. invocationTarget must be permitted by the leaf capability's target.
            if (!IsValidInvocationTarget(proof.InvocationTarget, capability.InvocationTarget))
                return VerificationResult.Fail(VerificationOutcome.InvalidTarget,
                    "Invocation target is not permitted by the capability's invocationTarget.");

            // 7. capabilityAction must be allowed (null/empty allowedAction == unrestricted root).
            if (capability.AllowedAction is { Length: > 0 } actions && !actions.Contains(proof.CapabilityAction))
                return VerificationResult.Fail(VerificationOutcome.ActionNotAllowed,
                    $"Action '{proof.CapabilityAction}' is not in the capability's allowedAction.");

            // 8. Verify the signature over the APPLICATION DOCUMENT (Path A signs the application payload,
            // not a self-contained invocation envelope). Bind the suite (from proof.Type) to the resolved
            // key type (Issue #68) before trusting the signature.
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(proof.VerificationMethod);
            var suite = ZcapSuiteCatalog.GetByProofType(proof.Type);
            if (suite is null || !KeyTypeMatches(suite, resolvedKey))
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    "Invocation proof suite is unknown or does not match the resolved key type.");
            if (!_legacyProofCrypto.Verify(applicationDocument, proof, resolvedKey))
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    "Invocation proof signature did not verify.");

            // 9. The invoker's verificationMethod must be authorized for capabilityInvocation by the
            // invoked capability's controller.
            if (!await IsControllerAuthorizedAsync(
                    proof.VerificationMethod, capability, VerificationRelationship.CapabilityInvocation))
                return VerificationResult.Fail(VerificationOutcome.UnauthorizedController,
                    "Invoker is not authorized by the capability's controller for capabilityInvocation.");

            // 10. Evaluate all caveats across the chain against the signed invocation time.
            var context = new InvocationContext
            {
                InvocationTime = createdUtc.Value,
                RequestedAction = proof.CapabilityAction,
                TargetResource = proof.InvocationTarget,
            };
            if (contextProperties != null)
                foreach (var kvp in contextProperties)
                    context.Properties[kvp.Key] = kvp.Value;
            if (!await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(chain.ToArray(), context))
                return VerificationResult.Fail(VerificationOutcome.CaveatFailed,
                    "A caveat in the capability chain was not satisfied.");

            // 11. Replay protection keyed on the application document id (the spec's invocation id / nonce).
            var nonce = TryGetDocId(securedDocument);
            if (string.IsNullOrEmpty(nonce))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Secured invocation document is missing an id (required as the replay nonce).");
            if (await _nonceStore.TryMarkAsUsedAsync(nonce, DateTime.UtcNow.Add(_nonceWindow)))
                return VerificationResult.Fail(VerificationOutcome.Replayed,
                    "Invocation nonce has already been used within the replay window.");

            return VerificationResult.Valid;
        }
        catch (Exception ex)
        {
            LogFailedClosed(ex, "VerifyCapabilityInvocationAsync failed closed");
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify, ex.Message);
        }
    }

    private async Task<VerificationResult> VerifyInvocationCoreAsync(
        Invocation invocation,
        Capability capability,
        Dictionary<string, object>? contextProperties,
        Capability? explicitRoot)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            if (string.IsNullOrWhiteSpace(invocation.Id))
            {
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation is missing a required id.");
            }

            // 1. Verify the capability chain is valid. Build it once here and reuse the same chain
            // for caveat evaluation in step 7 instead of rebuilding it (BuildCapabilityChainAsync
            // throwing is caught by this method's outer fail-closed catch). Propagate the chain's
            // specific failure reason (revoked / attenuation / chain-too-long / …) unchanged.
            var chain = await BuildCapabilityChainAsync(capability, explicitRoot);
            var chainResult = await VerifyBuiltChainAsync(chain);
            if (!chainResult.IsValid)
                return chainResult;

            // 2. Verify invocation proof exists and has correct purpose
            if (invocation.Proof == null || invocation.Proof.ProofPurpose != Proof.CapabilityInvocationPurpose)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof is missing or does not have the capabilityInvocation proofPurpose.");

            // 2a. Freshness (Issue #71): the signed proof.created must be present and within the
            // freshness window, bounding replay independently of nonce-store eviction. Runs before the
            // expensive signature/authorization work. The validated instant is reused for caveat
            // evaluation in step 7 (InvocationTime), so time-based caveats honour the signed time.
            var invocationCreatedUtc = GetFreshProofCreatedUtc(invocation.Proof);
            if (invocationCreatedUtc is null)
                return VerificationResult.Fail(VerificationOutcome.StaleProof,
                    "Invocation proof.created is missing, future-dated beyond clock skew, or older than the replay window.");

            // 2b. The invocation MUST reference the capability being verified, in the spec-defined
            // shape (Issue #51): a root invocation carries the root zcap id STRING; a delegated DI
            // invocation MUST embed the FULL delegated zcap object. Strict spec mode — a delegated
            // invocation that supplies only an id string is rejected: the verifier requires the
            // embedded authority rather than dereferencing the delegated zcap by id.
            var invocationCapability = invocation.Capability;
            if (!string.Equals(invocationCapability.CapabilityId, capability.Id, StringComparison.Ordinal))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation does not reference the capability being verified.");

            if (string.IsNullOrEmpty(capability.ParentCapability))
            {
                // Root invocation: capability MUST be the bare root id string.
                if (!invocationCapability.IsRootReference)
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        "Root invocation must reference the capability by its root id string.");
            }
            else
            {
                // Delegated DI invocation: capability MUST be the full embedded delegated zcap, whose
                // id binds it to the capability being verified (checked above via CapabilityId). The
                // embedded object's own delegation proof/chain is verified by the chain walk in step 1,
                // which the caller drives from this same delegated zcap.
                if (invocationCapability.EmbeddedCapability is null)
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        "Delegated invocation must embed the full delegated capability object.");
            }

            // 2c. Proof payload fields MUST be semantically consistent with the invocation body: the
            // proof's signed `capability` MUST reference the same id in the same shape (root id string
            // vs embedded object) as the invocation, and the action/target MUST match.
            var proofCapability = invocation.Proof.Capability;
            if (proofCapability is null ||
                !string.Equals(proofCapability.CapabilityId, invocationCapability.CapabilityId, StringComparison.Ordinal) ||
                proofCapability.IsRootReference != invocationCapability.IsRootReference ||
                !string.Equals(invocation.Proof.CapabilityAction, invocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(invocation.Proof.InvocationTarget, invocation.InvocationTarget, StringComparison.Ordinal))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof fields are inconsistent with the invocation body.");

            // 3. Verify invocation target matches capability
            if (!IsValidInvocationTarget(invocation.InvocationTarget, capability.InvocationTarget))
                return VerificationResult.Fail(VerificationOutcome.InvalidTarget,
                    "Invocation target is not permitted by the capability's invocationTarget.");

            // 4. Verify action is allowed.
            // Null AllowedAction == unrestricted (root capability); only enforce when
            // the field is present and non-empty.
            if (capability.AllowedAction is { Length: > 0 } actions &&
                !actions.Contains(invocation.CapabilityAction))
                return VerificationResult.Fail(VerificationOutcome.ActionNotAllowed,
                    $"Action '{invocation.CapabilityAction}' is not in the capability's allowedAction.");

            // 5. Verify the invocation signature
            if (!await VerifyInvocationSignatureAsync(invocation))
                return VerificationResult.Fail(VerificationOutcome.InvalidSignature,
                    "Invocation proof signature did not verify.");

            // 6. Verify the controller is authorized
            if (!await IsControllerAuthorizedAsync(
                    invocation.Proof.VerificationMethod, capability, VerificationRelationship.CapabilityInvocation))
                return VerificationResult.Fail(VerificationOutcome.UnauthorizedController,
                    "Invoker is not authorized by the capability's controller for capabilityInvocation.");

            // 7. SECURITY FIX S-05: Evaluate ALL caveats from the entire chain
            // Per spec: Children inherit ALL parent caveats, so we must check the entire chain.
            // Reuses the chain built and verified in step 1 (no rebuild).
            var context = new InvocationContext
            {
                // Use the signed proof.created (validated fresh in step 2c) so time-based caveats
                // evaluate against the invoker's signed time rather than the verifier's wall clock.
                InvocationTime = invocationCreatedUtc.Value,
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
                return VerificationResult.Fail(VerificationOutcome.CaveatFailed,
                    "A caveat in the capability chain was not satisfied.");

            // 8. Replay protection: reject if this invocation nonce has been seen before
            var nonceExpiry = DateTime.UtcNow.Add(_nonceWindow);
            if (await _nonceStore.TryMarkAsUsedAsync(invocation.Id, nonceExpiry))
                return VerificationResult.Fail(VerificationOutcome.Replayed,
                    "Invocation nonce has already been used within the replay window.");

            return VerificationResult.Valid;
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a misconfiguration/transient fault is
            // distinguishable from an invalid invocation (Issue #64). Surface it as CouldNotVerify so
            // callers can tell "couldn't check" from "invalid" (Issue #70).
            LogFailedClosed(ex,
                "VerifyInvocationAsync failed closed for invocation {InvocationId}", invocation.Id);
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify, ex.Message);
        }
    }

    /// <summary>
    /// Validates a signed invocation/revocation proof's <c>created</c> freshness (Issue #71): it must be
    /// present and parseable, not future-dated beyond <see cref="_freshnessClockSkew"/>, and no older than
    /// <see cref="_nonceWindow"/>. Reusing the nonce window as the staleness bound gives the invariant
    /// "anything still evictable from the nonce store is already too stale to pass freshness," so replay is
    /// bounded even after the nonce entry evicts (or when replay protection is the no-op opt-out). Returns
    /// the parsed UTC instant on success; <c>null</c> means the caller must fail closed.
    /// </summary>
    private DateTime? GetFreshProofCreatedUtc(Proof proof)
    {
        var createdAt = proof.CreatedAt; // ZcapTimestamps.ParseOrNull(Created); null if missing/unparseable
        if (createdAt is null)
            return null;

        var nowUtc = DateTime.UtcNow;
        if (createdAt.Value > nowUtc + _freshnessClockSkew)
            return null; // future-dated beyond clock skew
        if (nowUtc - createdAt.Value > _nonceWindow)
            return null; // older than the replay window

        return createdAt;
    }

    /// <summary>
    /// Validates a <b>delegation</b> proof's <c>created</c> timestamp (Issue #99). Unlike
    /// <see cref="GetFreshProofCreatedUtc"/> — which guards ephemeral invocation/revocation proofs and
    /// applies a staleness <em>lower</em>-bound (the nonce window) — a delegation proof is <b>durable</b>:
    /// a capability delegated months ago is legitimately valid until it <c>expires</c>, so there is
    /// deliberately <b>no</b> lower-bound here. The checks are:
    /// <list type="bullet">
    ///   <item>future-dated beyond <see cref="_freshnessClockSkew"/> → always rejected (no well-formed
    ///   signer stamps a future <c>created</c>);</item>
    ///   <item>present but unparseable → always rejected (a provably-malformed timestamp);</item>
    ///   <item>missing/empty → rejected only when
    ///   <see cref="VerificationPolicy.RequireDelegationProofCreated"/> is enabled, so pre-existing or
    ///   cross-stack delegations that omit <c>created</c> still verify by default.</item>
    /// </list>
    /// Returns <see langword="null"/> when the proof's <c>created</c> is acceptable; otherwise a
    /// fail-closed <see cref="VerificationResult"/> carrying <see cref="VerificationOutcome.InvalidProofTime"/>.
    /// Reads the raw <see cref="Proof.Created"/> string and parses defensively rather than touching
    /// <see cref="Proof.CreatedAt"/> (which <em>throws</em> on a non-empty unparseable value), so the
    /// unparseable case surfaces as <see cref="VerificationOutcome.InvalidProofTime"/> here rather than
    /// being reclassified as <see cref="VerificationOutcome.InvalidDelegation"/> by the per-proof catch.
    /// </summary>
    private VerificationResult? CheckDelegationProofCreated(Proof proof)
    {
        if (string.IsNullOrEmpty(proof.Created))
        {
            // Missing/empty: durable delegations minted before this check (or by another stack) may
            // legitimately omit `created`, so this is fail-closed only under the opt-in policy.
            return _policy.RequireDelegationProofCreated
                ? VerificationResult.Fail(VerificationOutcome.InvalidProofTime,
                    "Delegation proof has no created timestamp; the verifier's policy requires one.")
                : null;
        }

        DateTime createdUtc;
        try
        {
            createdUtc = ZcapTimestamps.Parse(proof.Created);
        }
        catch (FormatException)
        {
            // Present but not ISO-8601: provably malformed, always rejected (no legitimate-capability
            // compat surface). Catch FormatException ONLY so a genuine fault is not masked here.
            return VerificationResult.Fail(VerificationOutcome.InvalidProofTime,
                "Delegation proof created timestamp is unparseable.");
        }

        if (createdUtc > DateTime.UtcNow + _freshnessClockSkew)
            return VerificationResult.Fail(VerificationOutcome.InvalidProofTime,
                "Delegation proof created timestamp is in the future beyond the allowed clock skew.");

        return null;
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
        var suite = ZcapSuiteCatalog.GetByProofType(proof.Type)
            ?? throw new CapabilityValidationException(
                $"Unsupported proof type: {proof.Type}");

        // Bind the suite (chosen from the proof's type) to the resolved key's type (Issue #68);
        // see KeyTypeMatches for the rationale and the resolver↔suite vocabulary contract.
        if (!KeyTypeMatches(suite, resolvedKey))
            return false;

        var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);

        return _legacyProofCrypto.Verify(invocationWithoutProof, proof, resolvedKey);
    }

    /// <summary>
    /// Binds the signature suite (selected from the attacker-controlled <c>proof.Type</c>) to the key
    /// the DID actually resolves to: the suite's <c>KeyType</c> must equal the
    /// <see cref="ResolvedKey.KeyType"/> exactly (Issue #68). The proof type is part of the signed
    /// payload, so tampering already breaks the signature, and key importers reject cross-curve bytes —
    /// but this explicit, fail-closed guard self-documents the invariant and future-proofs against
    /// custom resolvers that might erode those downstream protections.
    /// <para>
    /// This couples two vocabularies by design: an <see cref="IDidResolver"/> MUST emit the exact
    /// <see cref="ResolvedKey.KeyType"/> string the matching suite uses
    /// (e.g. <c>Ed25519VerificationKey2020</c>), not a synonym (<c>Multikey</c>, <c>JsonWebKey2020</c>,
    /// <c>Ed25519VerificationKey2018</c>). The in-library pairs already align —
    /// <c>DidKeyResolver.MapKeyType</c> ↔ <c>ZcapSuiteCatalog</c> — and the contract
    /// is documented on both members. The single source of truth for the two verify paths.
    /// </para>
    /// </summary>
    private static bool KeyTypeMatches(ZcapSuiteInfo suite, ResolvedKey resolvedKey) =>
        string.Equals(suite.KeyType, resolvedKey.KeyType, StringComparison.Ordinal);

    /// <summary>
    /// Verifies a capability delegation chain.
    /// Implements the chain verification algorithm from W3C ZCAP-LD spec section 6.1.
    /// For a first-level (or deeper) delegation the root is referenced by id only, so this overload
    /// succeeds only when an <see cref="IRootCapabilityResolver"/> is configured; otherwise use
    /// <see cref="VerifyCapabilityChainAsync(Capability, Capability)"/> to supply the root explicitly.
    /// </summary>
    public async Task<bool> VerifyCapabilityChainAsync(Capability capability)
        => (await VerifyCapabilityChainDetailedAsync(capability)).IsValid;

    /// <inheritdoc />
    public async Task<bool> VerifyCapabilityChainAsync(Capability capability, Capability rootCapability)
        => (await VerifyCapabilityChainDetailedAsync(capability, rootCapability)).IsValid;

    /// <inheritdoc />
    public Task<VerificationResult> VerifyCapabilityChainDetailedAsync(Capability capability)
        => LogDenial(VerifyCapabilityChainCoreAsync(capability, explicitRoot: null),
            "VerifyCapabilityChain", capability?.Id);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyCapabilityChainDetailedAsync(Capability capability, Capability rootCapability)
    {
        if (rootCapability == null)
            throw new ArgumentNullException(nameof(rootCapability));
        return LogDenial(VerifyCapabilityChainCoreAsync(capability, rootCapability),
            "VerifyCapabilityChain", capability?.Id);
    }

    private async Task<VerificationResult> VerifyCapabilityChainCoreAsync(Capability capability, Capability? explicitRoot)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            // Build the complete chain from leaf to root, then verify it. Split so callers that
            // also need the built chain (revocation authorization, invocation caveat evaluation)
            // can build once and reuse it instead of rebuilding (see VerifyBuiltChainAsync callers).
            var chain = await BuildCapabilityChainAsync(capability, explicitRoot);
            return await VerifyBuiltChainAsync(chain);
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a config/transient fault (an unbuildable chain,
            // a missing canonicalizer, a DID-resolution error) is distinguishable from an invalid
            // capability (Issue #64). Surface it as CouldNotVerify so callers can tell "couldn't
            // check" from "invalid" (Issue #70).
            LogFailedClosed(ex,
                "VerifyCapabilityChainAsync failed closed for capability {CapabilityId}", capability.Id);
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify, ex.Message);
        }
    }

    /// <summary>
    /// Verifies an already-built root→leaf capability chain: length bound, per-link revocation,
    /// per-link delegation proof / attenuation / expiry / caveat compatibility, and root shape.
    /// Fully fail-closed — any unexpected failure yields <c>false</c>. Callers that have already
    /// built the chain (e.g. <see cref="IsRevokerAuthorizedAsync"/>, <see cref="VerifyInvocationAsync(Invocation, Capability)"/>)
    /// pass it here to avoid a redundant rebuild.
    /// <para>
    /// <paramref name="applyExpirationCeiling"/> gates the opt-in verifier-side 3-month delegated
    /// expiration ceiling (Issue #73). Default <see langword="true"/> for the invocation and
    /// chain-verification paths; the revocation-authorization path passes <see langword="false"/> so a
    /// long-lived delegation can always be revoked (the ceiling is a SHOULD on accepting/invoking a
    /// zcap, never a reason to refuse removing one). It is a no-op unless
    /// <see cref="VerificationPolicy.EnforceMaxDelegationExpiration"/> is also enabled.
    /// </para>
    /// <para>
    /// <paramref name="applyCreatedCheck"/> gates the per-link delegation-proof <c>created</c> soundness
    /// check (Issue #99). Default <see langword="true"/>; the revocation-authorization path passes
    /// <see langword="false"/> for the same reason as the ceiling — a delegation with a malformed
    /// <c>created</c> must stay revocable.
    /// </para>
    /// </summary>
    private async Task<VerificationResult> VerifyBuiltChainAsync(
        List<Capability> chain, bool applyExpirationCeiling = true, bool applyCreatedCheck = true,
        bool requireDelegatedExpires = true)
    {
        try
        {
            // 1. Check chain length (MUST limit, SHOULD be max 10)
            if (chain.Count > MaxChainLength)
            {
                return VerificationResult.Fail(VerificationOutcome.ChainTooLong,
                    $"Delegation chain length {chain.Count} exceeds the maximum of {MaxChainLength}.");
            }

            // 2. Revocation check for all capabilities in the chain.
            foreach (var chainCapability in chain)
            {
                if (await IsCapabilityRevokedAsync(chainCapability.Id))
                {
                    return VerificationResult.Fail(VerificationOutcome.Revoked,
                        $"Capability '{chainCapability.Id}' in the chain has been revoked.");
                }
            }

            // Snapshot the opt-in expiration ceiling once for the whole chain (Issue #73; PR #102
            // review): every delegated link is compared against the same instant rather than re-reading
            // the clock per link, and AddMonths is never evaluated when the policy is off (or on the
            // revocation path). Null means "do not apply the ceiling".
            DateTime? expirationCeilingCutoff = (applyExpirationCeiling && _policy.EnforceMaxDelegationExpiration)
                ? DateTime.UtcNow.AddMonths(_policy.MaxDelegationExpirationMonths)
                : null;

            // 3. Verify each link in the chain
            for (int i = 1; i < chain.Count; i++)
            {
                var parent = chain[i - 1];
                var child = chain[i];

                // R-CTX-2 (MUST): a delegated zcap's @context is an array whose FIRST entry is the
                // zcap-ld context, and which includes the signing suite's context so the proof terms
                // (type/proofValue/proofPurpose) JSON-LD-expand to the same RDF terms the spec
                // reference impl produces. Checked before the signature so a malformed context
                // surfaces as MalformedCapability rather than InvalidSignature. (Under RDFC the
                // @context is part of the signed N-Quads, so this is also defense-in-depth.)
                var childContext = AsArrayContext(child.Context);
                if (childContext is null || childContext.Count == 0 || childContext[0] != ZcapV1Context)
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        $"Delegated capability '{child.Id}' @context MUST be an array beginning with \"{ZcapV1Context}\".");

                // An unknown/absent proof type yields a null suite context — skip the suite-context
                // assertion deliberately (the signature gate below rejects an unknown suite anyway);
                // the check only applies when we know which suite context the proof terms require.
                var suiteContextUrl = ZcapSuiteCatalog.GetByProofType(
                    child.Proof?.FirstDelegationProof()?.Type)?.ContextUrl;
                if (suiteContextUrl is not null && !childContext.Contains(suiteContextUrl))
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        $"Delegated capability '{child.Id}' @context MUST include the signing suite context " +
                        $"'{suiteContextUrl}'.");

                // Verify delegation proof — propagate its specific reason (signature / authorization /
                // attenuation / expiry) so a broken link surfaces precisely (Issue #70).
                var linkResult = await VerifyDelegationProofAsync(
                    child,
                    parentCapabilityOverride: parent,
                    requireParentAuthorization: true,
                    applyCreatedCheck: applyCreatedCheck);
                if (!linkResult.IsValid)
                    return linkResult;

                // Verify attenuation (child is more restrictive than parent)
                if (!ValidateAttenuation(child, parent))
                    return VerificationResult.Fail(VerificationOutcome.AttenuationViolation,
                        $"Capability '{child.Id}' exceeds the authority of its parent '{parent.Id}'.");

                // Delegated zcaps MUST carry an expiration (ZCAP-LD MUST-15). Enforced HERE on the
                // verification path — the crypto paths never call CapabilityService.ValidateCapabilityAsync,
                // where the create-time check lives — so without this a delegated capability that simply
                // omits `expires` is accepted, treated as never-expiring, and slips past the attenuation
                // comparison (which only fires when both sides have a value), letting a child outlive a
                // short-lived parent indefinitely. Every non-root link (chain[1..]) is delegated, so this
                // applies to all of them. Skipped on the revocation-authorization path
                // (requireDelegatedExpires == false) so a non-expiring delegation stays REVOCABLE —
                // refusing to authorize its removal would be backwards (mirrors the #73/#99 carve-outs).
                var childExpiresAt = child.ExpiresAt;
                if (requireDelegatedExpires && childExpiresAt is null)
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        $"Delegated capability '{child.Id}' MUST include an expiration (expires).");

                // Verify expiration hasn't passed
                if (childExpiresAt.HasValue && childExpiresAt.Value < DateTime.UtcNow)
                    return VerificationResult.Fail(VerificationOutcome.Expired,
                        $"Capability '{child.Id}' in the chain has expired.");

                // Verifier-side SHOULD (opt-in): bound each delegated link's expiration to
                // MaxDelegationExpirationMonths in the future, measured at verification time (Issue #73).
                // This is the spec-correct home for the 3-month ceiling — the create-time hard throw was
                // removed in #61. Off by default (it is a SHOULD and can reject legitimately long-lived
                // delegations); skipped entirely on the revocation-authorization path so a long-lived
                // delegation remains revocable (cutoff is null then). Applied to EVERY delegated link
                // (chain[1..], i.e. the invoked leaf and every intermediate), not just the invoked leaf:
                // the verifier stores each link's revocation until that link expires, so the
                // storage-burden bound the SHOULD exists for must hold for the whole chain — and under
                // attenuation (child expires ≤ parent) the ancestors are the longest-lived links.
                if (expirationCeilingCutoff is { } ceiling)
                {
                    // A delegated zcap with no `expires` is effectively unbounded — strictly worse for
                    // the storage burden this ceiling caps (and the spec independently MUSTs that
                    // delegated zcaps carry an expiration). Treat "missing" as "infinitely far out" and
                    // reject it under this policy, otherwise the trivial bypass (omit `expires`) defeats
                    // the feature for an operator who enabled it expecting a bound.
                    if (!childExpiresAt.HasValue)
                        return VerificationResult.Fail(VerificationOutcome.ExpirationTooFarInFuture,
                            $"Delegated capability '{child.Id}' has no expiration; the verifier's policy " +
                            $"requires it to expire within {_policy.MaxDelegationExpirationMonths} month(s).");

                    if (childExpiresAt.Value > ceiling)
                        return VerificationResult.Fail(VerificationOutcome.ExpirationTooFarInFuture,
                            $"Capability '{child.Id}' expires more than {_policy.MaxDelegationExpirationMonths} " +
                            "month(s) in the future, exceeding the verifier's policy ceiling.");
                }

                // Verify caveats are compatible
                if (!await _caveatProcessor.ValidateCaveatCompatibilityAsync(parent.Caveat, child.Caveat))
                    return VerificationResult.Fail(VerificationOutcome.CaveatFailed,
                        $"Caveats on '{child.Id}' are not compatible with its parent '{parent.Id}'.");
            }

            // 4. Verify root capability (should have no proof)
            var root = chain[0];
            if (root.Proof != null)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Root capability MUST NOT include a delegation proof.");

            return VerificationResult.Valid;
        }
        catch (Exception ex)
        {
            // Fail closed, but record the cause so a misconfiguration/transient fault is
            // distinguishable from an invalid chain (Issue #64). This helper only has the built
            // chain in scope, so key the diagnostic on the leaf capability being verified. Surface it
            // as CouldNotVerify so callers can tell "couldn't check" from "invalid" (Issue #70).
            LogFailedClosed(ex,
                "Chain verification failed closed for leaf capability {CapabilityId}",
                chain.Count > 0 ? chain[^1].Id : "(empty chain)");
            return VerificationResult.Fail(VerificationOutcome.CouldNotVerify, ex.Message);
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
    /// Builds the complete capability chain from leaf to root, strictly validating each link's
    /// <c>capabilityChain</c> against the spec-exact shape. The root is referenced by id only, so it
    /// is obtained via <see cref="ResolveRootCapabilityAsync"/> (an explicit root, else the configured
    /// <see cref="IRootCapabilityResolver"/>, else fail closed). Rejects any non-spec shape — an
    /// embedded root, a missing/duplicated root id, an immediate parent that is missing/wrong/also
    /// referenced by id, or an out-of-order/non-minimal ancestor list (Issue #50).
    /// </summary>
    private async Task<List<Capability>> BuildCapabilityChainAsync(Capability capability, Capability? explicitRoot)
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

            // Bound the WORK, not just the final acceptance: stop walking as soon as the chain exceeds
            // the maximum length, BEFORE deserializing the next embedded parent. Previously the
            // MaxChainLength gate ran only in VerifyBuiltChainAsync, after the entire attacker-supplied
            // nesting had been walked and re-deserialized. Returning the over-length chain (rather than
            // throwing) lets that gate still reject it with the precise ChainTooLong outcome; the root
            // invariants below are intentionally skipped for the truncated chain since it is rejected
            // for length regardless.
            if (chain.Count > MaxChainLength)
            {
                return chain;
            }

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
            if (chainProof?.CapabilityChain is not { Length: > 0 } rawChain)
            {
                throw new CapabilityValidationException(
                    "Delegated capability missing capabilityChain in proof");
            }

            // capabilityChain[0] MUST be the root id string, consistent across the whole walk.
            var chainRootId = TryExtractStringValue(rawChain[0]);
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

            // Strictly validate this link's chain shape and obtain its immediate parent (the resolved
            // root for a first-level delegation, the embedded last entry for a deeper one).
            current = await ValidateChainShapeAndResolveParentAsync(rawChain, current, chainRootId, explicitRoot);
        }

        var root = chain[0];

        if (!string.IsNullOrWhiteSpace(expectedRootId) &&
            !string.Equals(expectedRootId, root.Id, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Root capability ID '{root.Id}' does not match capabilityChain root ID '{expectedRootId}'.");
        }

        // Structural root invariants (shared with the standalone proof path); also covers a direct-root
        // verification, where the leaf IS the root and ResolveRootCapabilityAsync is never reached.
        ValidateRootCapabilityInvariants(root, _policy.RejectUnknownRootFields);

        return chain;
    }

    /// <summary>
    /// Strictly validates one delegated capability's <c>capabilityChain</c> against the spec-exact
    /// shape and returns its immediate parent. For a first-level delegation the chain MUST be exactly
    /// <c>[rootId]</c> and the parent is the resolved root; for a deeper delegation the chain MUST be
    /// <c>[rootId, ...ancestorIds, {immediateParent}]</c> — the parent embedded as the last entry,
    /// every earlier entry an ancestor id string (root and ancestors by reference only, never
    /// embedded), with no duplicates, the immediate parent never also referenced by id, and the
    /// ancestor-id prefix exactly equal to the parent's own chain rendered by id (order + minimality).
    /// </summary>
    private async Task<Capability> ValidateChainShapeAndResolveParentAsync(
        object[] rawChain, Capability current, string chainRootId, Capability? explicitRoot)
    {
        var parentId = current.ParentCapability!;

        // First-level delegation: the parent IS the root, referenced by id only -> chain is EXACTLY [rootId].
        if (string.Equals(parentId, chainRootId, StringComparison.Ordinal))
        {
            if (rawChain.Length != 1)
            {
                throw new CapabilityValidationException(
                    "First-level delegation capabilityChain MUST be exactly [rootCapabilityId] (root referenced by id only).");
            }

            return await ResolveRootCapabilityAsync(chainRootId, explicitRoot);
        }

        // Deeper delegation: [rootId, ...ancestorIds, {immediate parent embedded}].
        if (rawChain.Length < 2)
        {
            throw new CapabilityValidationException(
                "Delegated capabilityChain MUST include the root id and the embedded immediate parent capability object.");
        }

        // The last entry MUST embed the immediate parent.
        if (!TryDeserializeCapability(rawChain[^1], out var embeddedParent) || embeddedParent == null)
        {
            throw new CapabilityValidationException(
                "capabilityChain last entry MUST embed the immediate parent capability object.");
        }

        if (string.IsNullOrEmpty(embeddedParent.Id) ||
            !string.Equals(embeddedParent.Id, parentId, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Embedded parent capability ID '{embeddedParent.Id}' does not match parentCapability '{parentId}'.");
        }

        // Every entry before the embedded parent MUST be an ancestor id STRING — never an embedded
        // object (root and ancestors are by reference only), with no duplicates, and the immediate
        // parent MUST NOT also appear here (reject parent-both-id-and-embedded).
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < rawChain.Length - 1; i++)
        {
            var id = TryExtractStringValue(rawChain[i]);
            if (string.IsNullOrEmpty(id))
            {
                throw new CapabilityValidationException(
                    "capabilityChain ancestor entries MUST be id strings; an embedded ancestor (including the root) is not allowed.");
            }

            if (!seen.Add(id))
            {
                throw new CapabilityValidationException(
                    $"capabilityChain contains a duplicate ancestor id '{id}'.");
            }

            if (string.Equals(id, parentId, StringComparison.Ordinal))
            {
                throw new CapabilityValidationException(
                    "Immediate parent MUST be embedded only, not also referenced by id in capabilityChain.");
            }
        }

        // Order + minimality: this chain's ancestor-id prefix MUST equal the embedded parent's own
        // chain rendered by id (root + the parent's ancestors). This binds each level to its parent's
        // chain, rejecting injected, reordered, or extra ancestor ids.
        var parentChain = embeddedParent.Proof?.FirstDelegationProofWithChain()?.CapabilityChain;
        IEnumerable<string> expectedPrefix = parentChain is { Length: > 0 }
            ? parentChain.Select(e => ExtractCapabilityId(e) ?? string.Empty)
            : new[] { chainRootId };
        var actualPrefix = rawChain.Take(rawChain.Length - 1).Select(e => TryExtractStringValue(e) ?? string.Empty);
        if (!expectedPrefix.SequenceEqual(actualPrefix, StringComparer.Ordinal))
        {
            throw new CapabilityValidationException(
                "capabilityChain ancestor ids are not minimal/ordered per spec (must equal the parent's chain rendered by id).");
        }

        return embeddedParent;
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

        // 3. Allowed actions: when the parent restricts actions, the child MUST also restrict to a
        // subset. A child that OMITS allowedAction under a restricting parent is NOT a valid
        // attenuation — it would widen authority back to "any action" (the omit-to-widen bypass).
        // Matches @digitalbazaar/zcap hasValidAllowedAction (an undefined child allowedAction under
        // a restricting parent is rejected). A parent with no allowedAction is unrestricted, so a
        // first-level child of an action-less root may legitimately omit it.
        if (parent.AllowedAction is { Length: > 0 } parentActions)
        {
            if (child.AllowedAction is not { Length: > 0 } childActions ||
                !childActions.All(action => parentActions.Contains(action)))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validates invocation target matches or is valid prefix of capability target
    /// Per spec: suffix MUST start with slash or question mark if no query exists,
    /// or ampersand when the capability target already contains a query.
    /// </summary>
    /// <remarks>Internal (not private) so the ordinal prefix matching can be unit-tested
    /// directly; the fail-closed call sites make a black-box test indistinguishable (Issue #74).</remarks>
    internal bool IsValidInvocationTarget(string invocationTarget, string capabilityTarget)
    {
        if (string.IsNullOrEmpty(invocationTarget) || string.IsNullOrEmpty(capabilityTarget))
            return false;

        // Exact match is always valid
        if (invocationTarget == capabilityTarget)
            return true;

        // Check if invocationTarget is a valid prefix extension.
        // Ordinal comparison keeps this consistent with the ordinal Substring index math
        // below (and the ordinal `==`/char checks around it); a culture-sensitive overload
        // can treat ignorable Unicode code points as zero-width, disagreeing on length and
        // throwing ArgumentOutOfRangeException in the subsequent Substring (Issue #74).
        if (invocationTarget.StartsWith(capabilityTarget, StringComparison.Ordinal))
        {
            var suffix = invocationTarget.Substring(capabilityTarget.Length);

            // Suffix must start with appropriate delimiter
            if (suffix.Length == 0)
                return true; // Exact match (edge case)

            // Reject a path-traversal ("..") segment in the extension. Lexical prefix matching is
            // spec-correct, but if a downstream resource server resolves/normalizes dot-segments
            // (or normalizes differently than this verifier) a target like ".../a/../../secret" could
            // escape the capability's intended subtree. Safer-by-default at the authorization boundary
            // (Issue #74 follow-up); only the path portion is inspected, so ".." inside a query is fine.
            if (SuffixHasDotSegment(suffix))
                return false;

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

    private static readonly char[] QueryOrFragmentChars = { '?', '#' };

    /// <summary>
    /// True if the path portion of a target suffix contains a <c>..</c> path segment (a complete
    /// segment, not a substring like <c>a..b</c>). Anything from the first <c>?</c> or <c>#</c>
    /// onward is treated as query/fragment and ignored.
    /// </summary>
    private static bool SuffixHasDotSegment(string suffix)
    {
        var queryStart = suffix.IndexOfAny(QueryOrFragmentChars);
        var path = queryStart >= 0 ? suffix.Substring(0, queryStart) : suffix;
        foreach (var segment in path.Split('/'))
        {
            if (segment == "..")
                return true;
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

    /// <summary>
    /// Resolves the immediate parent of a delegated <paramref name="capability"/> from its proof
    /// <paramref name="capabilityChain"/> on the standalone single-proof path, applying the SAME
    /// strict spec-exact shape validation as the chain walk (<see cref="ValidateChainShapeAndResolveParentAsync"/>)
    /// so both verifier entry points reject non-spec chains identically (Issue #50). Returns the
    /// resolved root for a first-level delegation (chain <c>[rootId]</c>) or the embedded last entry
    /// for a deeper one. Returns null only when the chain is absent/empty (so the caller fails closed
    /// where parent authorization is required); a malformed shape or an unobtainable root throws,
    /// which <see cref="VerifySingleDelegationProofAsync"/>'s catch turns into a fail-closed result.
    /// </summary>
    private async Task<Capability?> ResolveImmediateParentAsync(
        Capability capability, object[]? capabilityChain, Capability? explicitRoot)
    {
        if (capabilityChain is not { Length: > 0 } rawChain)
        {
            return null;
        }

        var chainRootId = TryExtractStringValue(rawChain[0]);
        if (string.IsNullOrWhiteSpace(chainRootId))
        {
            throw new CapabilityValidationException(
                "capabilityChain first entry MUST be the root capability ID string");
        }

        return await ValidateChainShapeAndResolveParentAsync(rawChain, capability, chainRootId, explicitRoot);
    }

    /// <summary>
    /// Obtains the root capability that a spec-exact chain references by id only. Precedence:
    /// an explicitly supplied root (from a verify/revoke overload), else the configured
    /// <see cref="IRootCapabilityResolver"/>, else fail closed. The result is bound to the chain —
    /// its <c>id</c> MUST equal <paramref name="rootCapabilityId"/>, and when the id uses the
    /// standard <c>urn:zcap:root:</c> form its encoded invocation target MUST match the root's
    /// <c>invocationTarget</c> — preventing a substituted or unrelated root (Issue #50).
    /// </summary>
    private async Task<Capability> ResolveRootCapabilityAsync(string rootCapabilityId, Capability? explicitRoot)
    {
        var root = explicitRoot;
        if (root == null && _rootResolver != null)
        {
            root = await _rootResolver.ResolveRootAsync(rootCapabilityId);
        }

        if (root == null)
        {
            throw new CapabilityValidationException(
                $"Cannot obtain root capability '{rootCapabilityId}': supply it via an explicit-root " +
                "verify/revoke overload or register an IRootCapabilityResolver.");
        }

        if (string.IsNullOrEmpty(root.Id) ||
            !string.Equals(root.Id, rootCapabilityId, StringComparison.Ordinal))
        {
            throw new CapabilityValidationException(
                $"Resolved root capability id '{root.Id}' does not match the referenced root id '{rootCapabilityId}'.");
        }

        // Hardening: the standard root id encodes its invocation target, so a mismatch means a
        // substituted root. Only enforced for the canonical urn:zcap:root: form (the spec SHOULD).
        if (rootCapabilityId.StartsWith(RootIdPrefix, StringComparison.Ordinal))
        {
            var encodedTarget = rootCapabilityId.Substring(RootIdPrefix.Length);
            var decodedTarget = Uri.UnescapeDataString(encodedTarget);
            if (!string.Equals(decodedTarget, root.InvocationTarget, StringComparison.Ordinal))
            {
                throw new CapabilityValidationException(
                    $"Root capability invocationTarget '{root.InvocationTarget}' does not match the target " +
                    $"encoded in root id '{rootCapabilityId}'.");
            }
        }

        // Enforce the structural root invariants on the standalone proof path too, so it rejects a
        // malformed root identically to the chain-walk path (which validates chain[0] below).
        ValidateRootCapabilityInvariants(root, _policy.RejectUnknownRootFields);
        return root;
    }

    /// <summary>
    /// Enforces the structural invariants every root capability MUST satisfy per W3C ZCAP-LD v0.3:
    /// its <c>@context</c> is the single string <c>https://w3id.org/zcap/v1</c>; it has no
    /// <c>parentCapability</c>, no delegation <c>proof</c> (a root is an unsigned trust anchor), and
    /// no other fields beyond <c>@context</c>/<c>id</c>/<c>controller</c>/<c>invocationTarget</c> (so
    /// no <c>expires</c>/<c>allowedAction</c>/<c>caveat</c>/extension fields); a non-empty
    /// <c>controller</c>; and a valid absolute <c>invocationTarget</c>. Applied wherever a root is
    /// obtained — the resolved root on the standalone proof path (<see cref="ResolveRootCapabilityAsync"/>)
    /// and the <c>chain[0]</c> root on the chain-walk path — so both verifier entry points reject a
    /// malformed root identically. Mirrors the create-time checks in
    /// <c>CapabilityService.ValidateCapabilityAsync</c>, which the crypto verify paths never call.
    /// </summary>
    private static void ValidateRootCapabilityInvariants(Capability root, bool rejectUnknownRootFields)
    {
        // R-CTX-1 (MUST): a root @context is the single string "https://w3id.org/zcap/v1".
        if (AsStringContext(root.Context) != ZcapV1Context)
        {
            throw new CapabilityValidationException(
                $"Root capability @context MUST be the string \"{ZcapV1Context}\".");
        }

        if (!string.IsNullOrEmpty(root.ParentCapability))
        {
            throw new CapabilityValidationException("Root capability MUST NOT have parentCapability.");
        }

        if (root.Proof != null)
        {
            throw new CapabilityValidationException("Root capability MUST NOT include a delegation proof.");
        }

        // R-ROOT-NOEXTRA (MUST NOT): a root carries ONLY @context/id/controller/invocationTarget.
        // The unambiguous forbidden fields are rejected unconditionally: db's checkCapability rejects a
        // root that carries `expires`, and `allowedAction`/`caveat` are spec MUST-NOTs that are
        // meaningless on a root (zcap's own create path never emits them).
        if (root.Expires != null)
        {
            throw new CapabilityValidationException("Root capability MUST NOT have expires.");
        }
        if (root.AllowedAction != null)
        {
            throw new CapabilityValidationException("Root capability MUST NOT have allowedAction.");
        }
        if (root.Caveat != null)
        {
            throw new CapabilityValidationException("Root capability MUST NOT have caveat.");
        }

        // Arbitrary unmodeled fields are rejected ONLY under the opt-in policy: db's checkCapability
        // IGNORES (does not reject) unknown root fields, and Capability.AdditionalProperties
        // ([JsonExtensionData]) exists to round-trip such fields — so rejecting them by default would
        // be stricter than the reference impl and fight that design. Verifiers that want strict
        // spec conformance enable VerificationPolicy.RejectUnknownRootFields.
        if (rejectUnknownRootFields && root.AdditionalProperties is { Count: > 0 })
        {
            throw new CapabilityValidationException(
                "Root capability MUST NOT carry fields other than @context, id, controller, invocationTarget.");
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
    }

    /// <summary>The <c>@context</c> as a single string (native or deserialized JsonElement), else null.</summary>
    private static string? AsStringContext(object? context) => context switch
    {
        string s => s,
        JsonElement { ValueKind: JsonValueKind.String } e => e.GetString(),
        _ => null,
    };

    /// <summary>The <c>@context</c> entries when it is an array of strings (native or JsonElement), else null.</summary>
    private static IReadOnlyList<string>? AsArrayContext(object? context)
    {
        static string? AsStr(object? x) => x switch
        {
            string s => s,
            JsonElement { ValueKind: JsonValueKind.String } e => e.GetString(),
            _ => null,
        };

        switch (context)
        {
            case object[] arr:
            {
                var list = new List<string>(arr.Length);
                foreach (var x in arr)
                {
                    if (AsStr(x) is not { } s) return null;
                    list.Add(s);
                }
                return list;
            }
            case JsonElement { ValueKind: JsonValueKind.Array } e:
            {
                var list = new List<string>();
                foreach (var item in e.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String) return null;
                    list.Add(item.GetString()!);
                }
                return list;
            }
            default:
                return null;
        }
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
    /// been revoked. A spec-exact chain carries the root id and every intermediate ancestor as id
    /// strings and the immediate parent as the embedded final object, so
    /// <see cref="ExtractCapabilityId"/> reads every ancestor's id (string or embedded) and the sweep
    /// covers the full ancestry without resolving each ancestor as a <see cref="Capability"/>. This
    /// lets the standalone <see cref="VerifyCapabilityProofAsync(Capability)"/> path honour ancestor
    /// revocation at every depth, matching the per-link sweep in <see cref="VerifyBuiltChainAsync"/>
    /// (Issue #63). Ids are de-duplicated defensively so any repeated entry is queried only once.
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
    /// authorization runs <see cref="VerifyCapabilityChainAsync(Capability)"/>, which still enforces the leaf's
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
    public Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation)
        => RevokeCapabilityInternalAsync(capability, signedRevocation, explicitRoot: null);

    /// <inheritdoc />
    public Task<bool> RevokeCapabilityAsync(Capability capability, Invocation signedRevocation, Capability rootCapability)
    {
        if (rootCapability == null)
            throw new ArgumentNullException(nameof(rootCapability));
        return RevokeCapabilityInternalAsync(capability, signedRevocation, rootCapability);
    }

    private async Task<bool> RevokeCapabilityInternalAsync(
        Capability capability, Invocation signedRevocation, Capability? explicitRoot)
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
            // Freshness (Issue #71): same created-window gate as the invocation path, so a captured
            // signed revocation cannot be replayed after its nonce entry evicts.
            if (GetFreshProofCreatedUtc(proof) is null)
                return false;
            if (signedRevocation.CapabilityAction != Invocation.RevokeAction)
                return false;
            // Revocation references the target capability by id (a root-style reference); unlike a
            // delegated DI invocation it is not required to embed the full zcap (Issue #51 governs the
            // capabilityInvocation shape, not this control-plane capabilityRevocation action).
            if (!string.Equals(signedRevocation.Capability.CapabilityId, capability.Id, StringComparison.Ordinal))
                return false;

            // Proof payload fields MUST be consistent with the invocation body.
            var proofCapabilityId = proof.Capability?.CapabilityId;
            if (!string.Equals(proofCapabilityId, signedRevocation.Capability.CapabilityId, StringComparison.Ordinal) ||
                !string.Equals(proof.CapabilityAction, signedRevocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(proof.InvocationTarget, signedRevocation.InvocationTarget, StringComparison.Ordinal))
                return false;

            // AUTHENTICATE: the signature proves the caller holds verificationMethod's private key.
            if (!await VerifyInvocationSignatureAsync(signedRevocation))
                return false;

            // AUTHORIZE: the authenticated verificationMethod must control the capability or an
            // ancestor. IsRevokerAuthorizedAsync verifies the chain first (fail-closed).
            if (!await IsRevokerAuthorizedAsync(capability, proof.VerificationMethod, explicitRoot))
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
    private async Task<bool> IsRevokerAuthorizedAsync(
        Capability capability, string verificationMethod, Capability? explicitRoot)
    {
        try
        {
            // Build the chain once, then verify it cryptographically before trusting controller fields.
            // Without that verification, a caller passing a crafted Capability with a tampered controller
            // could authorize themselves to revoke a legitimate capability. (VerifyBuiltChainAsync reuses
            // this built chain instead of rebuilding it — see VerifyCapabilityChainAsync.)
            var chain = await BuildCapabilityChainAsync(capability, explicitRoot);

            // Do NOT apply the opt-in 3-month expiration ceiling (Issue #73), the delegation-proof
            // `created` soundness check (Issue #99), nor the delegated-`expires` MUST here: revocation
            // must stay possible for a long-lived, malformed-`created`, or non-expiring delegation —
            // refusing to authorize its removal would be exactly backwards. All three are constraints on
            // accepting/invoking a zcap, not on revoking one.
            if (!(await VerifyBuiltChainAsync(
                    chain, applyExpirationCeiling: false, applyCreatedCheck: false,
                    requireDelegatedExpires: false)).IsValid)
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
