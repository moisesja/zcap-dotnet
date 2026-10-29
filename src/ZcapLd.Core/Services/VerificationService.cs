using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
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
    private readonly IRevocationService _revocationService;
    private readonly INonceStore _nonceStore;

    // Stage C (#108): canonicalization + signature verification delegated to DataProofs' legacy
    // cryptosuites. Suite metadata (proof type, the #68 key-type binding, context URL) comes from the
    // fixed ZcapSuiteCatalog; the canonicalization method is fixed per service instance.
    private readonly LegacyProofCrypto _legacyProofCrypto;

    private readonly TimeSpan _nonceWindow;
    private readonly TimeSpan _freshnessClockSkew;
    private readonly ILogger _logger;
    private readonly IVerificationRelationshipResolver _relationshipResolver;
    private readonly IRootCapabilityResolver? _rootResolver;
    private readonly VerificationPolicy _policy;
    private readonly CaveatTypeRegistry? _caveats;
    private readonly IReadOnlyDictionary<string, ICaveatHandler> _caveatHandlers;
    private const int MaxChainLength = 10; // Per spec: SHOULD limit to 10

    /// <summary>
    /// The most chains the delegation proofs of one capability may name before the search stops. A chain
    /// with one proof per link names exactly one.
    /// </summary>
    internal const int MaxChainCandidates = 16;
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
    /// Convenience constructor (RDFC-1.0 canonicalization). Each instance gets its own process-local
    /// <see cref="InMemoryNonceStore"/>, so replay state is NOT shared across
    /// <see cref="VerificationService"/> instances; in a per-request / multi-instance setup supply a
    /// shared <see cref="INonceStore"/> via the full constructor (Issue #62; PR #88 review).
    /// </summary>
    public VerificationService(IDidResolver didResolver)
        : this(didResolver, new RevocationService(new InMemoryRevocationStore()))
    {
    }

    /// <summary>
    /// Convenience constructor with a custom revocation service (RDFC-1.0 canonicalization). Each instance
    /// gets its own process-local <see cref="InMemoryNonceStore"/>; supply a shared
    /// <see cref="INonceStore"/> via the full constructor for multi-instance setups (Issue #62).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        IRevocationService revocationService)
        : this(didResolver, revocationService, new InMemoryNonceStore())
    {
    }

    /// <summary>
    /// Full constructor. The optional <paramref name="logger"/> receives a diagnostic whenever
    /// verification fails closed on an unexpected exception, so operators can tell a
    /// misconfiguration/transient fault apart from an invalid capability (Issue #64); defaults to
    /// <see cref="NullLogger"/>. The optional <paramref name="relationshipResolver"/> performs
    /// controller authorization by resolving the controller's DID document and checking the relevant
    /// verification relationship (<c>capabilityInvocation</c> / <c>capabilityDelegation</c>) —
    /// Issue #65 — resolved in this precedence: the explicit argument; else the supplied
    /// <paramref name="didResolver"/> when it also implements <see cref="IVerificationRelationshipResolver"/>
    /// (<see cref="DidKeyResolver"/> does, and <see cref="CompositeDidResolver"/> routes the check to
    /// the adapter registered for the controller's DID method — Issue #148); else a
    /// <c>did:key</c>-only default that denies every non-<c>did:key</c> controller. Pass the explicit
    /// argument only to override what the resolver self-provides. The optional <paramref name="freshnessClockSkew"/>
    /// tolerates a signed <c>proof.created</c> being up to that far in the future (Issue #71; default
    /// <see cref="DefaultFreshnessClockSkew"/>). The optional <paramref name="policy"/> enables opt-in
    /// verifier-side SHOULD checks (Issue #73; default <see cref="VerificationPolicy.Default"/>).
    /// All proofs are verified under RDFC-1.0 canonicalization (the only canonicalization ZCAP-LD
    /// supports; required for interop with <c>@digitalbazaar/zcap</c>).
    /// <para>
    /// The optional <paramref name="caveats"/> registry enables the caveat extension profile (#157):
    /// capabilities may then carry the registered caveat types, every delegated link must restate and
    /// narrow its parent's caveats, and invocations are allowed only after the matching
    /// <paramref name="caveatHandlers"/> agree. Without a registry any caveat is rejected. Each handler
    /// must name a registered type, at most one handler per type. The registry is frozen.
    /// </para>
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        IRevocationService revocationService,
        INonceStore nonceStore,
        TimeSpan? nonceWindow = null,
        ILogger<VerificationService>? logger = null,
        IVerificationRelationshipResolver? relationshipResolver = null,
        IRootCapabilityResolver? rootResolver = null,
        TimeSpan? freshnessClockSkew = null,
        VerificationPolicy? policy = null,
        CaveatTypeRegistry? caveats = null,
        IEnumerable<ICaveatHandler>? caveatHandlers = null)
    {
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));
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
        caveats?.Freeze();
        _caveats = caveats;
        _legacyProofCrypto = new LegacyProofCrypto(caveats);
        _caveatHandlers = IndexCaveatHandlers(caveats, caveatHandlers);
    }

    private static IReadOnlyDictionary<string, ICaveatHandler> IndexCaveatHandlers(
        CaveatTypeRegistry? caveats, IEnumerable<ICaveatHandler>? handlers)
    {
        var index = new Dictionary<string, ICaveatHandler>(StringComparer.Ordinal);
        foreach (var handler in handlers ?? Enumerable.Empty<ICaveatHandler>())
        {
            ArgumentNullException.ThrowIfNull(handler, nameof(handlers));
            if (caveats?.Resolve(handler.CaveatType) is null)
                throw new ArgumentException(
                    $"Caveat handler {handler.GetType().FullName} enforces '{handler.CaveatType}', which is not a registered caveat type.",
                    nameof(handlers));
            if (!index.TryAdd(handler.CaveatType, handler))
                throw new ArgumentException($"More than one caveat handler enforces '{handler.CaveatType}'.", nameof(handlers));
        }

        return index;
    }

    /// <summary>
    /// Default controller-authorization resolver: resolves <c>did:key</c> controller documents
    /// and checks the requested verification relationship. <c>did:key</c> derives the DID from the
    /// key and lists it under every relationship, so this is the correct default for the common
    /// case. Non-<c>did:key</c> controllers require a method-appropriate
    /// <see cref="IVerificationRelationshipResolver"/>: either supplied via the constructor / DI, or
    /// self-provided by the <c>didResolver</c> — a <see cref="CompositeDidResolver"/> routes the check
    /// to the adapter registered for the controller's method (Issue #148).
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
            or InvocationException or FormatException or JsonException;
        _logger.Log(expected ? LogLevel.Debug : LogLevel.Warning, ex, template, args);
    }

    /// <summary>
    /// Public-boundary choke point for the <c>...DetailedAsync</c> verify methods that closes the
    /// part-B logging gap (Issue #70 / #64): it awaits a verification core and, when the result is a
    /// <i>structurally-valid</i> denial — revoked, expired, bad signature, unauthorized controller,
    /// attenuation, replay, chain-too-long, malformed — logs that reason once before returning.
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

        if ((CapabilityProfile.Validate(capability, caveats: _caveats) ?? CapabilityProfile.Validate(explicitRoot, caveats: _caveats)) is { } profileFailure)
            return profileFailure;

        if (!CanonicalIri.IsCanonical(capability.Id))
            return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                $"Capability id {CanonicalIri.RequirementMessage}.");

        // Root capabilities have no proof
        if (string.IsNullOrEmpty(capability.ParentCapability))
        {
            if (await IsCapabilityRevokedAsync(capability.Id, RevocationScope.Root))
            {
                return VerificationResult.Fail(VerificationOutcome.Revoked,
                    $"Capability '{capability.Id}' has been revoked.");
            }

            // Root capability should NOT have a proof
            return capability.Proof == null
                ? VerificationResult.Valid
                : VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Root capability MUST NOT include a delegation proof.");
        }

        try
        {
            // Per ZCAP-LD v0.4.0 a delegated zcap's proof may be a set; the capability is valid if at least
            // one delegation proof verifies. Each proof is a candidate evaluated on its own, as the chain
            // walk evaluates each chain a proof set names: the link is verified first (signature, parent
            // authorization, attenuation, expiry), then the ancestry that proof names is authenticated and
            // swept for revocation (#63, #158), and the first candidate passing both wins. A proof that
            // fails never vetoes another (PR #162 review); when every candidate fails the result is a
            // revocation found on any verified route, else the last failure (Issue #70). Revocation is
            // swept per candidate because the proof that verifies may be any of them, and a junk proof
            // must neither hide nor force a revocation (#157).
            VerificationResult? revokedResult = null;
            var last = capability.Proof is null
                ? VerificationResult.Fail(VerificationOutcome.MalformedCapability, "Delegated capability is missing a proof.")
                : VerificationResult.Fail(VerificationOutcome.InvalidDelegation, "No capabilityDelegation proof could be verified.");
            foreach (var delegationProof in capability.Proof?.DelegationProofs() ?? Enumerable.Empty<Proof>())
            {
                if (delegationProof.CapabilityChain?.Any(entry => !CanonicalIri.IsCanonical(ExtractCapabilityId(entry))) == true)
                {
                    last = VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        $"Every capabilityChain id {CanonicalIri.RequirementMessage}.");
                    continue;
                }

                // 1. The link itself. For a first-level delegation the parent is the root (referenced by
                // id only), obtained via explicitRoot or the configured resolver inside
                // VerifySingleDelegationProofAsync.
                var link = await VerifySingleDelegationProofAsync(
                    capability, delegationProof, parentCapabilityOverride: null,
                    requireParentAuthorization: true, explicitRoot);
                if (!link.IsValid)
                {
                    last = link;
                    continue;
                }

                // 2. Revocation of the leaf and of every ancestor this proof names, each under the
                // delegator of a proof that has verified (SweepStandaloneRouteAsync).
                var (sweepFailure, lookups) = await SweepStandaloneRouteAsync(capability, delegationProof, explicitRoot);
                if (sweepFailure is not null)
                {
                    last = sweepFailure;
                    continue;
                }

                if (await _revocationService.FindRevocationAsync(lookups) is { } revoked)
                {
                    // A revocation found on a verified route is reported over any other candidate's
                    // failure, so a junk proof in the set cannot mask it in the outcome.
                    last = revokedResult = VerificationResult.Fail(VerificationOutcome.Revoked,
                        string.Equals(revoked.CapabilityId, capability.Id, StringComparison.Ordinal)
                            ? $"Capability '{capability.Id}' has been revoked."
                            : "An ancestor capability in the delegation chain has been revoked.");
                    continue;
                }

                // A single link never authorizes caveats: only invocation verification enforces them
                // (#157). Below the first level the ancestors' caveats are checked for integrity but not
                // for policy here, so with caveats enabled such a link is never reported as valid on its own.
                var mayCarryCaveats = capability.AdditionalProperties?.ContainsKey(CaveatCodec.Property) == true ||
                    (_caveats is { IsEmpty: false } &&
                     capability.Proof?.DelegationProofs().Any(proof => proof.CapabilityChain is { Length: > 1 }) == true);
                return mayCarryCaveats ? CaveatEnforcementRequired(grants: null) : link;
            }

            return revokedResult ?? last;
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

    private async Task<VerificationResult> VerifySingleDelegationProofAsync(
        Capability capability,
        Proof proof,
        Capability? parentCapabilityOverride,
        bool requireParentAuthorization,
        Capability? explicitRoot = null,
        bool applyCreatedCheck = true,
        bool applyCaveatPolicy = true)
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
            // entry points, not here: VerifyBuiltChainAsync sweeps every verified link, and the
            // standalone VerifyCapabilityProofAsync sweeps each proof's chain (StandaloneRevocationLookups;
            // Issue #63), so a single delegation proof's check stays independent of chain state.
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

            if (capability.ExpiresAt is { } childExpiresAt && childExpiresAt < DateTime.UtcNow)
            {
                return VerificationResult.Fail(VerificationOutcome.Expired,
                    "Delegated capability has expired.");
            }

            if (parentCapability != null &&
                CheckCaveatAttenuation(capability, parentCapability, applyCaveatPolicy) is { } caveatFailure)
            {
                return caveatFailure;
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
                or InvocationException or FormatException or JsonException
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
        Capability rootCapability)
        => (await VerifyInvocationDetailedAsync(invocation, capability, rootCapability)).IsValid;

    /// <inheritdoc />
    public Task<VerificationResult> VerifyInvocationDetailedAsync(Invocation invocation, Capability capability)
        => LogDenial(VerifyInvocationCoreAsync(invocation, capability, explicitRoot: null),
            "VerifyInvocation", invocation?.Id);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyInvocationDetailedAsync(
        Invocation invocation,
        Capability capability,
        Capability rootCapability)
    {
        if (rootCapability == null)
            throw new ArgumentNullException(nameof(rootCapability));
        return LogDenial(VerifyInvocationCoreAsync(invocation, capability, explicitRoot: rootCapability),
            "VerifyInvocation", invocation?.Id);
    }

    // ─── Path A: Data Integrity capabilityInvocation (@digitalbazaar/zcap-compatible) ───────────────

    /// <summary>
    /// Verifies a <c>@digitalbazaar/zcap</c>-compatible ("Path A") Data Integrity invocation: an
    /// application document carrying a <c>capabilityInvocation</c> proof whose proof object alone holds
    /// <c>capability</c>/<c>capabilityAction</c>/<c>invocationTarget</c>. The signature is verified over
    /// the application document (<c>SHA-256(RDFC(proofOptions)) || SHA-256(RDFC(document))</c>); the
    /// capability chain, attenuation, controller authorization, freshness and replay are then
    /// enforced as for the self-contained <see cref="Invocation"/> envelope path.
    /// <para>
    /// SECURITY: the relying party MUST declare what it is willing to authorize via
    /// <paramref name="expectedAction"/> and <paramref name="expectedTargets"/> (and optionally
    /// <c>expectedRootCapabilityIds</c>) — exactly as the <c>@digitalbazaar/zcap</c> reference requires.
    /// Without this binding, a valid invocation the attacker signed over a DIFFERENT capability it holds
    /// could be replayed against this endpoint (confused deputy). The verifier also requires the
    /// application document's <c>@context</c> to bind the invocation terms (see the core).
    /// </para>
    /// </summary>
    /// <param name="securedDocument">The application document and its invocation proof.</param>
    /// <param name="expectedAction">The action the relying party authorizes; must equal the proof's
    /// <c>capabilityAction</c> exactly.</param>
    /// <param name="expectedTargets">The acceptable invocation target(s); the proof's
    /// <c>invocationTarget</c> must be one of them (exact match).</param>
    public async Task<bool> VerifyCapabilityInvocationAsync(
        JsonObject securedDocument, string expectedAction, IReadOnlyCollection<string> expectedTargets)
        => (await VerifyCapabilityInvocationDetailedAsync(securedDocument, expectedAction, expectedTargets)).IsValid;

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject, string, IReadOnlyCollection{string})"/>
    public async Task<bool> VerifyCapabilityInvocationAsync(
        JsonObject securedDocument, string expectedAction, IReadOnlyCollection<string> expectedTargets, Capability rootCapability)
        => (await VerifyCapabilityInvocationDetailedAsync(
            securedDocument, expectedAction, expectedTargets, rootCapability: rootCapability)).IsValid;

    /// <summary>Single-expected-target convenience overload.</summary>
    public Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(
        JsonObject securedDocument, string expectedAction, string expectedTarget,
        Capability? rootCapability = null)
        => VerifyCapabilityInvocationDetailedAsync(
            securedDocument, expectedAction, new[] { expectedTarget }, expectedRootCapabilityIds: null,
            rootCapability);

    /// <inheritdoc cref="VerifyCapabilityInvocationAsync(JsonObject, string, IReadOnlyCollection{string})"/>
    /// <param name="securedDocument">The application document and its invocation proof.</param>
    /// <param name="expectedAction">The action authorized by the relying party.</param>
    /// <param name="expectedTargets">The targets authorized by the relying party.</param>
    /// <param name="rootCapability">Optional explicit root trust anchor.</param>
    /// <param name="expectedRootCapabilityIds">Optional: if supplied, the dereferenced chain root id MUST
    /// be one of these (defense in depth against a resolver serving an attacker-controlled root).</param>
    public Task<VerificationResult> VerifyCapabilityInvocationDetailedAsync(
        JsonObject securedDocument,
        string expectedAction,
        IReadOnlyCollection<string> expectedTargets,
        IReadOnlyCollection<string>? expectedRootCapabilityIds = null,
        Capability? rootCapability = null)
    {
        ArgumentNullException.ThrowIfNull(securedDocument);
        if (string.IsNullOrEmpty(expectedAction))
            throw new ArgumentException("An expected action is required.", nameof(expectedAction));
        ArgumentNullException.ThrowIfNull(expectedTargets);
        if (expectedTargets.Count == 0)
            throw new ArgumentException("At least one expected target is required.", nameof(expectedTargets));

        return LogDenial(
            VerifyCapabilityInvocationCoreAsync(
                securedDocument, expectedAction, expectedTargets, expectedRootCapabilityIds, rootCapability),
            "VerifyCapabilityInvocation", TryGetDocId(securedDocument));
    }

    private static string? TryGetDocId(JsonObject? doc)
        => doc is not null && doc.TryGetPropertyValue("id", out var node)
           && node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>The <c>@context</c> entries when a <see cref="JsonNode"/> is an array of strings, else null.</summary>
    private static IReadOnlyList<string>? AsArrayContextNode(JsonNode? context)
    {
        if (context is not JsonArray arr)
            return null;
        var list = new List<string>(arr.Count);
        foreach (var item in arr)
        {
            if (item is JsonValue v && v.TryGetValue<string>(out var s))
                list.Add(s);
            else
                return null;
        }
        return list;
    }

    private async Task<VerificationResult> VerifyCapabilityInvocationCoreAsync(
        JsonObject securedDocument,
        string expectedAction,
        IReadOnlyCollection<string> expectedTargets,
        IReadOnlyCollection<string>? expectedRootCapabilityIds,
        Capability? explicitRoot)
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

            if (CapabilityProfile.GetProofRejectionReason(proof, _caveats) is { } proofProfileReason)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability, proofProfileReason);

            if (proof.ProofPurpose != Proof.CapabilityInvocationPurpose)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Proof does not have the capabilityInvocation proofPurpose.");

            // The document id is the replay nonce (step 11). A relative or non-normalized id is not
            // what RDFC signs, so a captured invocation could be replayed under a new nonce (#157).
            var nonce = TryGetDocId(securedDocument);
            if (string.IsNullOrEmpty(nonce))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Secured invocation document is missing an id (required as the replay nonce).");
            if (!CanonicalIri.IsCanonical(nonce))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Secured invocation document id {CanonicalIri.RequirementMessage}.");

            var applicationDocument = securedDocument.DeepClone()!.AsObject();
            applicationDocument.Remove("proof");

            // 1a. SECURITY (forgery defense): the proof's invocation terms (capability/capabilityAction/
            // invocationTarget) are defined ONLY in the zcap/v1 context, and the proof options canonicalize
            // under the DOCUMENT's @context. If the document @context omits zcap/v1 (or the suite context),
            // RDFC-1.0 drops those terms from the signed N-Quads — they become unauthenticated and an
            // attacker could rewrite them after signing without breaking the signature. Require the document
            // @context to bind them (mirrors the chain R-CTX-2 check and @digitalbazaar/zcap's
            // checkProofContext / suite matchProof).
            var docContext = AsArrayContextNode(applicationDocument["@context"]);
            var suiteContextUrl = ZcapSuiteCatalog.GetByProofType(proof.Type)?.ContextUrl;
            if (docContext is null || docContext.Count == 0 || docContext[0] != ZcapV1Context ||
                (suiteContextUrl is not null && !docContext.Contains(suiteContextUrl)))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Invocation application document @context MUST be an array beginning with \"{ZcapV1Context}\" " +
                    "and include the signing suite context, so the proof's invocation terms are signature-bound.");

            // 2. Freshness (Issue #71): bound replay independently of nonce eviction; reuse the validated
            // instant before accepting the invocation.
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
            if (!CanonicalIri.IsSignedTarget(proof.InvocationTarget))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Invocation target {CanonicalIri.TargetMessage}.");

            // 3a. SECURITY (confused-deputy defense): the relying party declared what it authorizes via
            // expectedAction/expectedTargets. The proof's action/target MUST match exactly — otherwise a
            // valid invocation the attacker signed over a DIFFERENT capability it holds could be replayed
            // against this endpoint. Mirrors @digitalbazaar/zcap, which requires expectedAction + expectedTarget.
            if (!string.Equals(proof.CapabilityAction, expectedAction, StringComparison.Ordinal))
                return VerificationResult.Fail(VerificationOutcome.ActionNotAllowed,
                    $"Invocation action '{proof.CapabilityAction}' does not match the expected action '{expectedAction}'.");
            if (!expectedTargets.Contains(proof.InvocationTarget, StringComparer.Ordinal))
                return VerificationResult.Fail(VerificationOutcome.InvalidTarget,
                    $"Invocation target '{proof.InvocationTarget}' is not among the relying party's expected targets.");

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
            if ((CapabilityProfile.Validate(capability, caveats: _caveats) ?? CapabilityProfile.Validate(explicitRoot, caveats: _caveats)) is { } profileFailure)
                return profileFailure;
            var (chainResult, chain) = await BuildAndVerifyChainAsync(capability, explicitRoot);
            if (chain is null)
                return chainResult;

            // 5a. SECURITY (defense in depth): if the relying party pinned the acceptable root
            // capabilities, the dereferenced chain root MUST be one of them — blocks an
            // IRootCapabilityResolver that serves an attacker-controlled root over a broad/overlapping target.
            if (expectedRootCapabilityIds is { Count: > 0 } &&
                !expectedRootCapabilityIds.Contains(chain[0].Id, StringComparer.Ordinal))
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Resolved root capability '{chain[0].Id}' is not among the relying party's expected roots.");

            // 5b. Caveats (#157): every caveat type needs a handler here, checked before any nonce is used.
            var caveatGrants = CollectCaveatGrants(chain);
            if (RequireCaveatHandlers(caveatGrants) is { } unsupportedCaveat)
                return unsupportedCaveat;

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

            // 11. Replay protection keyed on the application document id (the spec's invocation id /
            // nonce), validated as a signed, normalized IRI before step 1a.
            if (await _nonceStore.TryMarkAsUsedAsync(nonce, DateTime.UtcNow.Add(_nonceWindow)))
                return VerificationResult.Fail(VerificationOutcome.Replayed,
                    "Invocation nonce has already been used within the replay window.");

            // 12. Caveat handlers run last, so a replayed or otherwise invalid invocation never reaches them.
            if (caveatGrants.Count > 0 &&
                await EnforceCaveatsAsync(caveatGrants, chain, proof.CapabilityAction, proof.InvocationTarget,
                    nonce, proof.VerificationMethod, createdUtc.Value) is { } caveatFailure)
                return caveatFailure;

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
        Capability? explicitRoot)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            if (CapabilityProfile.Validate(invocation.Capability?.EmbeddedCapability, caveats: _caveats) is { } invocationProfileFailure)
                return invocationProfileFailure;
            if (CapabilityProfile.GetProofRejectionReason(invocation.Proof, _caveats) is { } invocationProfileReason)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability, invocationProfileReason);

            if (string.IsNullOrWhiteSpace(invocation.Id))
            {
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation is missing a required id.");
            }

            // The id is the replay nonce; a variant the signature does not distinguish would be a
            // fresh nonce for a captured invocation (#157).
            if (!CanonicalIri.IsCanonical(invocation.Id))
            {
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Invocation id {CanonicalIri.RequirementMessage}.");
            }

            // A target RDF drops is unsigned and could be rewritten in transit (#157).
            if (!CanonicalIri.IsSignedTarget(invocation.InvocationTarget))
            {
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"Invocation target {CanonicalIri.TargetMessage}.");
            }

            // 1. Verify the capability chain is valid. Build it once here and reuse the same chain
            // instead of rebuilding it (a chain that cannot be built throws, which this method's
            // outer fail-closed catch handles). Propagate the chain's
            // specific failure reason (revoked / attenuation / chain-too-long / …) unchanged.
            if ((CapabilityProfile.Validate(capability, caveats: _caveats) ?? CapabilityProfile.Validate(explicitRoot, caveats: _caveats)) is { } profileFailure)
                return profileFailure;
            var (chainResult, chain) = await BuildAndVerifyChainAsync(capability, explicitRoot);
            if (chain is null)
                return chainResult;

            // 1a. Caveats (#157): every caveat type needs a handler here, checked before any nonce is used.
            var caveatGrants = CollectCaveatGrants(chain);
            if (RequireCaveatHandlers(caveatGrants) is { } unsupportedCaveat)
                return unsupportedCaveat;

            // 2. Verify invocation proof exists and has correct purpose
            if (invocation.Proof == null || invocation.Proof.ProofPurpose != Proof.CapabilityInvocationPurpose)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Invocation proof is missing or does not have the capabilityInvocation proofPurpose.");

            // 2a. Freshness (Issue #71): the signed proof.created must be present and within the
            // freshness window, bounding replay independently of nonce-store eviction. Runs before the
            // expensive signature/authorization work.
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
            if (invocationCapability is null || !string.Equals(invocationCapability.CapabilityId, capability.Id, StringComparison.Ordinal))
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

                // The invoker signed the embedded copy, the chain was verified from the supplied one,
                // and caveats are read from the chain: with caveats they must be the same capability.
                if (caveatGrants.Count > 0 && !IsSameJson(invocationCapability.EmbeddedCapability, capability))
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        "The invocation's embedded capability differs from the capability being verified.");
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

            // 8. Replay protection: reject if this invocation nonce has been seen before
            var nonceExpiry = DateTime.UtcNow.Add(_nonceWindow);
            if (await _nonceStore.TryMarkAsUsedAsync(invocation.Id, nonceExpiry))
                return VerificationResult.Fail(VerificationOutcome.Replayed,
                    "Invocation nonce has already been used within the replay window.");

            // 9. Caveat handlers run last, so a replayed or otherwise invalid invocation never reaches them.
            if (caveatGrants.Count > 0 &&
                await EnforceCaveatsAsync(caveatGrants, chain, invocation.CapabilityAction, invocation.InvocationTarget,
                    invocation.Id, invocation.Proof.VerificationMethod, invocationCreatedUtc.Value) is { } caveatFailure)
                return caveatFailure;

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
            // also need the built chain (revocation authorization, invocation verification)
            // can build once and reuse it instead of rebuilding (see VerifyBuiltChainAsync callers).
            if ((CapabilityProfile.Validate(capability, caveats: _caveats) ?? CapabilityProfile.Validate(explicitRoot, caveats: _caveats)) is { } profileFailure)
                return profileFailure;
            var (result, chain) = await BuildAndVerifyChainAsync(capability, explicitRoot);
            if (chain is null)
                return result;

            // A valid chain with caveats is authentic but not authorized: only invocation verification
            // enforces caveats (#157). The authenticated caveats are returned for inspection.
            var grants = CollectCaveatGrants(chain);
            return grants.Count == 0 ? result : CaveatEnforcementRequired(grants);
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
    /// per-link delegation proof / attenuation / expiry, and root shape.
    /// Fully fail-closed — any unexpected failure yields <c>false</c>. Callers that have already
    /// built the chain (e.g. <see cref="AuthorizeRevocationAsync"/>, <see cref="VerifyInvocationAsync(Invocation, Capability)"/>)
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
    /// <para>
    /// <paramref name="applyCaveatPolicy"/> gates caveat policy (<see cref="Caveat.Validate"/> and
    /// <see cref="Caveat.IsAttenuationOf"/>); the revocation path passes <see langword="false"/> and
    /// keeps only caveat integrity, which signature verification needs (#157).
    /// </para>
    /// </summary>
    private async Task<VerificationResult> VerifyBuiltChainAsync(
        List<Capability> chain, IReadOnlyList<Proof?> linkProofs, ChainSearch search,
        bool applyExpirationCeiling = true, bool applyCreatedCheck = true, bool requireDelegatedExpires = true,
        bool applyCaveatPolicy = true)
    {
        try
        {
            // 1. Check chain length (MUST limit, SHOULD be max 10)
            if (chain.Count > MaxChainLength)
            {
                return VerificationResult.Fail(VerificationOutcome.ChainTooLong,
                    $"Delegation chain length {chain.Count} exceeds the maximum of {MaxChainLength}.");
            }

            // 2. Profile check for every capability in the chain. Revocation is step 5, after each link's
            // proof has verified: a record is scoped to the delegator that signed the link, and only a
            // verified proof says who that is (#158).
            foreach (var chainCapability in chain)
            {
                if (!search.Validated.Contains(chainCapability))
                {
                    if (CapabilityProfile.Validate(chainCapability, caveats: _caveats) is { } profileFailure)
                        return profileFailure;
                    search.Validated.Add(chainCapability);
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
                var linkProof = linkProofs[i];
                var suiteContextUrl = ZcapSuiteCatalog.GetByProofType(linkProof?.Type)?.ContextUrl;
                if (suiteContextUrl is not null && !childContext.Contains(suiteContextUrl))
                    return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                        $"Delegated capability '{child.Id}' @context MUST include the signing suite context " +
                        $"'{suiteContextUrl}'.");

                // Verify the delegation proof that named this parent, and only that one: another proof
                // in the set names its own chain and is tried as its own candidate (#157). Propagate the
                // specific reason (signature / authorization / attenuation / expiry) so a broken link
                // surfaces precisely (Issue #70).
                VerificationResult linkResult;
                if (linkProof is null)
                {
                    linkResult = VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
                        $"No delegation proof of '{child.Id}' names its parent.");
                }
                else
                {
                    var linkKey = search.LinkKey(child, linkProof, parent);
                    if (!search.Links.TryGetValue(linkKey, out linkResult!))
                        search.Links[linkKey] = linkResult = await VerifySingleDelegationProofAsync(
                            child, linkProof, parent, requireParentAuthorization: true,
                            applyCreatedCheck: applyCreatedCheck, applyCaveatPolicy: applyCaveatPolicy);
                }
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

            }

            // 4. Verify root capability (should have no proof)
            var root = chain[0];
            if (root.Proof != null)
                return VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    "Root capability MUST NOT include a delegation proof.");

            // 5. Revocation for every link in one store read (#158): the root in the root scope and each
            // delegated link under the delegator of the proof that just verified it, the scope the signed
            // revocation path records in. An unscoped (legacy or operator) record for any id in the chain
            // also revokes it. Deliberately not memoized across candidates by bare id: a record is per
            // (id, scope), and a junk proof naming another delegator must not shadow the genuine answer.
            if (await _revocationService.FindRevocationAsync(ChainRevocationLookups(chain, linkProofs)) is { } revoked)
            {
                return VerificationResult.Fail(VerificationOutcome.Revoked,
                    $"Capability '{revoked.CapabilityId}' in the chain has been revoked.");
            }

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
    /// One root→leaf chain that a capability's proofs name, with the delegation proof of each link whose
    /// <c>capabilityChain</c> resolved that link's parent (<see langword="null"/> for the root), or the
    /// reason the chain could not be built.
    /// </summary>
    private sealed record ChainCandidate(
        List<Capability> Chain, Proof?[] LinkProofs, CapabilityValidationException? BuildFailure);

    /// <summary>
    /// Work shared by the candidates of one chain search. Candidates usually share their links (the
    /// proofs of a set embed copies of the same ancestors), so each result is computed once per call:
    /// a link's verification by the RFC 8785 content of child, proof and parent, roots by id, profile
    /// validation by reference, and the controllers already refused for a revoker.
    /// Everything memoized depends only on that input and on verifier state that is fixed for the call.
    /// </summary>
    private sealed class ChainSearch
    {
        private readonly Dictionary<object, string> _contentKeys = new(ReferenceEqualityComparer.Instance);

        public Dictionary<string, VerificationResult> Links { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, Capability> Roots { get; } = new(StringComparer.Ordinal);
        public HashSet<Capability> Validated { get; } = new(ReferenceEqualityComparer.Instance);
        public HashSet<string> RefusedControllers { get; } = new(StringComparer.Ordinal);

        public string LinkKey(Capability child, Proof proof, Capability parent)
            => $"{ContentKey(child)}|{ContentKey(proof)}|{ContentKey(parent)}";

        private string ContentKey(object value)
        {
            if (!_contentKeys.TryGetValue(value, out var key))
                _contentKeys[value] = key = Convert.ToHexString(SHA256.HashData(CanonicalForComparison(value)));
            return key;
        }
    }

    /// <summary>
    /// Builds and verifies the capability's chain. A proof set may name several chains (for example two
    /// representations of the same parent), and the capability is valid when at least one delegation
    /// proof verifies together with the chain it names. Candidates are tried depth first in proof order
    /// (one per proof when every link has a single proof), at most <see cref="MaxChainCandidates"/> of
    /// them. Returns the first chain that verifies, otherwise the last candidate's failure. When that
    /// candidate could not be built its exception is rethrown, so a malformed single chain fails closed
    /// exactly as it did before proof sets were searched. <paramref name="accept"/>, when given, must
    /// also hold for a verified chain (revocation: the revoker controls one of its links).
    /// </summary>
    private async Task<(VerificationResult Result, List<Capability>? Chain)> BuildAndVerifyChainAsync(
        Capability capability, Capability? explicitRoot, bool applyExpirationCeiling = true,
        bool applyCreatedCheck = true, bool requireDelegatedExpires = true, bool applyCaveatPolicy = true,
        Func<List<Capability>, IReadOnlyList<Proof?>, ChainSearch, Task<bool>>? accept = null)
    {
        VerificationResult? lastResult = null;
        CapabilityValidationException? lastFailure = null;
        var examined = 0;
        var search = new ChainSearch();
        await foreach (var candidate in ExtendChainAsync(
                           capability, [], [], expectedRootId: null, requiredChainIds: null, explicitRoot, search))
        {
            if (++examined > MaxChainCandidates)
                return (VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
                    $"None of the first {MaxChainCandidates} chains named by the capability's delegation proofs verified."), null);

            if (candidate.BuildFailure is { } failure)
            {
                (lastFailure, lastResult) = (failure, null);
                continue;
            }

            var result = await VerifyBuiltChainAsync(
                candidate.Chain, candidate.LinkProofs, search, applyExpirationCeiling, applyCreatedCheck,
                requireDelegatedExpires, applyCaveatPolicy);
            if (result.IsValid && (accept is null || await accept(candidate.Chain, candidate.LinkProofs, search)))
                return (result, candidate.Chain);
            (lastFailure, lastResult) = (null, result.IsValid
                ? VerificationResult.Fail(VerificationOutcome.InvalidDelegation, "The verified chain was not accepted.")
                : result);
        }

        if (lastFailure is not null)
            ExceptionDispatchInfo.Throw(lastFailure);
        return (lastResult ?? VerificationResult.Fail(VerificationOutcome.InvalidDelegation,
            "No delegation chain could be built."), null);
    }

    /// <summary>
    /// Enumerates the chains from <paramref name="current"/> up to the root, strictly validating each
    /// link's <c>capabilityChain</c> against the spec-exact shape (Issue #50). The root is referenced by id
    /// only, so it is obtained via <see cref="ResolveRootCapabilityAsync"/> (an explicit root, else the
    /// configured <see cref="IRootCapabilityResolver"/>, else fail closed). Each delegation proof is
    /// followed only with the parent its own chain names, and a parent is reached only through a proof
    /// naming exactly the ancestors its child lists, so an unverified proof can neither choose the parent
    /// another proof is judged against (#157) nor hide a valid chain.
    /// </summary>
    /// <param name="current">The capability whose parent this step resolves.</param>
    /// <param name="below">The links already walked, leaf first.</param>
    /// <param name="belowProofs">For each of <paramref name="below"/>, the proof that named its parent.</param>
    /// <param name="requiredChainIds">The ancestor ids the child lists before <paramref name="current"/>,
    /// which <paramref name="current"/>'s proof must name; <see langword="null"/> for the leaf.</param>
    /// <param name="expectedRootId">The root id the walk has committed to, once known.</param>
    /// <param name="explicitRoot">A root supplied by the caller, preferred over the resolver.</param>
    /// <param name="search">Work shared by the candidates of this search.</param>
    private async IAsyncEnumerable<ChainCandidate> ExtendChainAsync(
        Capability current, ImmutableList<Capability> below, ImmutableList<Proof?> belowProofs,
        string? expectedRootId, string[]? requiredChainIds, Capability? explicitRoot, ChainSearch search)
    {
        static ChainCandidate Failed(CapabilityValidationException failure) => new([], [], failure);
        static ChainCandidate Complete(ImmutableList<Capability> leafFirst, ImmutableList<Proof?> proofs)
            => new(leafFirst.Reverse().ToList(), proofs.Reverse().ToArray(), null);

        if (string.IsNullOrWhiteSpace(current.Id))
        {
            yield return Failed(new CapabilityValidationException("Capability in chain is missing required id."));
            yield break;
        }

        if (!CanonicalIri.IsCanonical(current.Id))
        {
            yield return Failed(new CapabilityValidationException(
                $"Capability id '{current.Id}' in chain {CanonicalIri.RequirementMessage}."));
            yield break;
        }

        if (below.Any(link => string.Equals(link.Id, current.Id, StringComparison.Ordinal)))
        {
            yield return Failed(new CapabilityValidationException(
                $"Detected a cycle in capability chain at capability ID '{current.Id}'."));
            yield break;
        }

        var path = below.Add(current);

        // Bound the WORK, not just the final acceptance: stop walking as soon as the chain exceeds the
        // maximum length, BEFORE deserializing the next embedded parent. The over-length chain is still
        // returned so VerifyBuiltChainAsync rejects it with the precise ChainTooLong outcome; the root
        // invariants are skipped because it is rejected for length regardless.
        if (path.Count > MaxChainLength)
        {
            yield return Complete(path, belowProofs.Add(null));
            yield break;
        }

        if (string.IsNullOrEmpty(current.ParentCapability))
        {
            CapabilityValidationException? rootFailure = null;
            if (!string.IsNullOrWhiteSpace(expectedRootId) &&
                !string.Equals(expectedRootId, current.Id, StringComparison.Ordinal))
            {
                rootFailure = new CapabilityValidationException(
                    $"Root capability ID '{current.Id}' does not match capabilityChain root ID '{expectedRootId}'.");
            }
            else
            {
                // Structural root invariants (shared with the standalone proof path); also covers a
                // direct-root verification, where the leaf IS the root and no resolver is consulted.
                try
                {
                    ValidateRootCapabilityInvariants(current, _policy.RejectUnknownRootFields);
                }
                catch (CapabilityValidationException ex)
                {
                    rootFailure = ex;
                }
            }

            yield return rootFailure is null ? Complete(path, belowProofs.Add(null)) : Failed(rootFailure);
            yield break;
        }

        var proofs = current.Proof?.DelegationProofs()
            .Where(proof => proof.CapabilityChain is { Length: > 0 } chain &&
                            (requiredChainIds is null || ChainIds(chain).SequenceEqual(requiredChainIds, StringComparer.Ordinal)))
            .ToList() ?? [];
        if (proofs.Count == 0)
        {
            yield return Failed(new CapabilityValidationException(requiredChainIds is null
                ? "Delegated capability missing capabilityChain in proof"
                : "capabilityChain ancestor ids are not minimal/ordered per spec (must equal the parent's chain rendered by id)."));
            yield break;
        }

        foreach (var proof in proofs)
        {
            var rawChain = proof.CapabilityChain!;
            string? chainRootId = null;
            Capability? parent = null;
            CapabilityValidationException? failure = null;
            try
            {
                // capabilityChain[0] MUST be the root id string, consistent across the whole walk.
                chainRootId = TryExtractStringValue(rawChain[0]);
                if (string.IsNullOrWhiteSpace(chainRootId))
                    throw new CapabilityValidationException(
                        "capabilityChain first entry MUST be the root capability ID string");
                if (expectedRootId is not null && !string.Equals(expectedRootId, chainRootId, StringComparison.Ordinal))
                    throw new CapabilityValidationException(
                        $"Inconsistent root capability IDs in capabilityChain. Expected '{expectedRootId}', got '{chainRootId}'.");

                // Strictly validate this link's chain shape and obtain its immediate parent (the resolved
                // root for a first-level delegation, the embedded last entry for a deeper one).
                parent = await ValidateChainShapeAndResolveParentAsync(rawChain, current, chainRootId, explicitRoot, search);
            }
            catch (Exception ex) when (ex is CapabilityValidationException or DelegationException
                                           or InvocationException or FormatException or JsonException)
            {
                // Malformed input in this proof's chain (an embedded parent that does not parse, a
                // non-spec shape) fails this candidate only, classified as VerifySingleDelegationProofAsync
                // classifies it; other proofs are still tried. Infrastructure faults propagate.
                failure = ex as CapabilityValidationException ?? new CapabilityValidationException(ex.Message, ex);
            }

            if (failure is not null)
            {
                yield return Failed(failure);
                continue;
            }

            // A deeper parent must itself be reached through a proof naming exactly these ancestors.
            var parentChainIds = string.Equals(current.ParentCapability, chainRootId, StringComparison.Ordinal)
                ? null
                : rawChain[..^1].Select(entry => TryExtractStringValue(entry) ?? string.Empty).ToArray();
            await foreach (var candidate in ExtendChainAsync(
                               parent!, path, belowProofs.Add(proof), chainRootId, parentChainIds, explicitRoot, search))
                yield return candidate;
        }
    }

    /// <summary>A <c>capabilityChain</c> rendered by id: strings as written, an embedded capability by its id.</summary>
    private static string[] ChainIds(object[] chain)
        => chain.Select(entry => ExtractCapabilityId(entry) ?? string.Empty).ToArray();

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
        object[] rawChain, Capability current, string chainRootId, Capability? explicitRoot,
        ChainSearch? search = null)
    {
        var parentId = current.ParentCapability!;

        // Every id the chain names is a revocation key; only the normalized form is signed.
        if (rawChain.Any(entry => !CanonicalIri.IsCanonical(ExtractCapabilityId(entry))))
        {
            throw new CapabilityValidationException(
                $"Every capabilityChain id {CanonicalIri.RequirementMessage}.");
        }

        // First-level delegation: the parent IS the root, referenced by id only -> chain is EXACTLY [rootId].
        if (string.Equals(parentId, chainRootId, StringComparison.Ordinal))
        {
            if (rawChain.Length != 1)
            {
                throw new CapabilityValidationException(
                    "First-level delegation capabilityChain MUST be exactly [rootCapabilityId] (root referenced by id only).");
            }

            if (search is null)
                return await ResolveRootCapabilityAsync(chainRootId, explicitRoot);
            if (!search.Roots.TryGetValue(chainRootId, out var root))
                search.Roots[chainRootId] = root = await ResolveRootCapabilityAsync(chainRootId, explicitRoot);
            return root;
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
        // chain, rejecting injected, reordered, or extra ancestor ids. A parent with several delegation
        // proofs may name different chains; the chain walk then follows only the proofs naming this one.
        var parentChains = embeddedParent.Proof?.DelegationProofs()
            .Where(p => p.CapabilityChain is { Length: > 0 })
            .Select(p => ChainIds(p.CapabilityChain!))
            .ToList() ?? [];
        if (parentChains.Count == 0)
            parentChains.Add(new[] { chainRootId });
        var actualPrefix = rawChain.Take(rawChain.Length - 1).Select(e => TryExtractStringValue(e) ?? string.Empty).ToArray();
        if (!parentChains.Any(expectedPrefix => expectedPrefix.SequenceEqual(actualPrefix, StringComparer.Ordinal)))
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
    /// Caveat attenuation for one delegation link (#157): both capabilities' caveats must be
    /// registered and well formed, and every caveat type the parent carries must be restated by the
    /// child and narrowed (<see cref="Caveat.IsAttenuationOf"/>). A child may add caveat types.
    /// With <paramref name="applyPolicy"/> false (revocation) only integrity is checked.
    /// </summary>
    private VerificationResult? CheckCaveatAttenuation(Capability child, Capability parent, bool applyPolicy)
    {
        if (CaveatCodec.TryRead(child, _caveats, applyPolicy, out var childCaveats) is { } childFailure)
            return childFailure;
        if (CaveatCodec.TryRead(parent, _caveats, applyPolicy, out var parentCaveats) is { } parentFailure)
            return parentFailure;
        if (!applyPolicy)
            return null;

        foreach (var parentCaveat in parentCaveats)
        {
            var type = parentCaveat.Registration.Type;
            if (childCaveats.FirstOrDefault(entry => entry.Registration.Type == type)?.Value is not { } childCaveat)
                return VerificationResult.Fail(VerificationOutcome.AttenuationViolation,
                    $"Capability '{child.Id}' drops its parent's '{type}' caveat.");

            bool narrows;
            try
            {
                narrows = childCaveat.IsAttenuationOf(parentCaveat.Value!);
            }
            catch (Exception ex)
            {
                LogFailedClosed(ex, "Caveat {CaveatType} attenuation check failed for {CapabilityId}", type, child.Id);
                return VerificationResult.Fail(VerificationOutcome.CouldNotVerify,
                    $"The '{type}' attenuation rule failed: {ex.Message}");
            }

            if (!narrows)
                return VerificationResult.Fail(VerificationOutcome.AttenuationViolation,
                    $"Capability '{child.Id}' widens its parent's '{type}' caveat.");
        }

        return null;
    }

    /// <summary>
    /// The authenticated caveats of a verified chain, root side first, each keyed by the ids from the
    /// root to its capability. Empty when no caveat registry is configured.
    /// </summary>
    private IReadOnlyList<CaveatGrant> CollectCaveatGrants(List<Capability> chain)
    {
        var grants = new List<CaveatGrant>();
        if (_caveats is null)
            return grants;

        for (var i = 1; i < chain.Count; i++)
        {
            if (CaveatCodec.TryRead(chain[i], _caveats, materialize: true, out var entries) is { } failure)
                throw new CapabilityValidationException(failure.Message ?? "A verified capability's caveats are invalid.");
            if (entries.Count == 0)
                continue;
            var key = CaveatCodec.GrantKey(chain.Take(i + 1).Select(link => link.Id));
            grants.AddRange(entries.Select(entry => new CaveatGrant(chain[i].Id, key, entry.Value!)));
        }

        return grants;
    }

    /// <summary>The non-authorizing result for a valid chain that carries caveats (#157).</summary>
    private static VerificationResult CaveatEnforcementRequired(IReadOnlyList<CaveatGrant>? grants)
        => new()
        {
            Outcome = VerificationOutcome.CaveatEnforcementRequired,
            Message = "The chain is valid but carries caveats, which only invocation verification enforces.",
            Caveats = grants,
        };

    /// <summary>Fails when a caveat type in the chain has no handler at this verifier.</summary>
    private VerificationResult? RequireCaveatHandlers(IReadOnlyList<CaveatGrant> grants)
        => grants.Select(grant => grant.Caveat.Type).FirstOrDefault(type => !_caveatHandlers.ContainsKey(type)) is { } missing
            ? VerificationResult.Fail(VerificationOutcome.UnsupportedCaveat,
                $"No caveat handler is registered for '{missing}', so this verifier cannot enforce it.")
            : null;

    /// <summary>
    /// Runs the caveat handlers after every other check has passed, in ordinal type order, stopping at
    /// the first denial and releasing the handlers that had already allowed the invocation.
    /// </summary>
    private async Task<VerificationResult?> EnforceCaveatsAsync(
        IReadOnlyList<CaveatGrant> grants, List<Capability> chain, string action, string target,
        string invocationId, string verificationMethod, DateTime created)
    {
        var allowed = new List<(ICaveatHandler Handler, CaveatEnforcementContext Context)>();
        foreach (var group in grants.GroupBy(grant => grant.Caveat.Type).OrderBy(group => group.Key, StringComparer.Ordinal))
        {
            var handler = _caveatHandlers[group.Key];
            var context = new CaveatEnforcementContext
            {
                CaveatType = group.Key,
                Grants = group.ToArray(),
                Chain = chain.ToArray(),
                RootCapabilityId = chain[0].Id,
                CapabilityAction = action,
                InvocationTarget = target,
                InvocationId = invocationId,
                VerificationMethod = verificationMethod,
                Created = created,
            };

            CaveatDecision decision;
            try
            {
                decision = await handler.EnforceAsync(context) ?? CaveatDecision.Deny("The caveat handler returned no decision.");
            }
            catch (Exception ex)
            {
                // Every exception, including a TaskCanceledException from a ledger timeout: there is
                // no caller token on this path, so cancellation is never the caller's (#151). The
                // earlier handlers' allowances must be released either way.
                await ReleaseCaveatsAsync(allowed);
                LogFailedClosed(ex, "Caveat handler for {CaveatType} failed closed for invocation {InvocationId}",
                    group.Key, invocationId);
                return VerificationResult.Fail(VerificationOutcome.CouldNotVerify,
                    $"The '{group.Key}' caveat handler failed: {ex.Message}");
            }

            if (!decision.IsSatisfied)
            {
                await ReleaseCaveatsAsync(allowed);
                return VerificationResult.Fail(VerificationOutcome.CaveatNotSatisfied,
                    decision.Reason ?? $"The '{group.Key}' caveat is not satisfied.");
            }

            allowed.Add((handler, context));
        }

        return null;
    }

    private async Task ReleaseCaveatsAsync(List<(ICaveatHandler Handler, CaveatEnforcementContext Context)> allowed)
    {
        foreach (var (handler, context) in allowed)
        {
            try
            {
                await handler.ReleaseAsync(context);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Caveat handler for {CaveatType} failed to release invocation {InvocationId}",
                    context.CaveatType, context.InvocationId);
            }
        }
    }

    /// <summary>
    /// Validates invocation target matches or is valid prefix of capability target
    /// Per spec: suffix MUST start with slash or question mark if no query exists,
    /// or ampersand when the capability target already contains a query.
    /// </summary>
    /// <remarks>Internal (not private) so the ordinal prefix matching can be unit-tested
    /// directly; the fail-closed call sites make a black-box test indistinguishable (Issue #74).</remarks>
    internal bool IsValidInvocationTarget(string invocationTarget, string capabilityTarget)
        => InvocationTargetPolicy.IsValid(invocationTarget, capabilityTarget, _policy.AllowTargetAttenuation);

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
        string verificationMethod, Capability capability, VerificationRelationship relationship,
        HashSet<string>? refused = null)
    {
        if (capability.Controller is null || capability.Controller.IsEmpty)
            return false;

        foreach (var controller in capability.Controller.Values)
        {
            // Within one search the method and relationship are fixed, so a refusal holds for every chain.
            // Only refusals are remembered: a controller that authorized one chain stays usable on another.
            if (refused is not null && refused.Contains(controller))
                continue;

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
                        "Controller '{Controller}' could not be resolved during {Relationship} authorization: {Error} — {Message}",
                        controller, relationship, result.ResolutionError, result.Message);
                    refused?.Add(controller);
                    break;
                default: // NotAuthorized
                    _logger.LogDebug(
                        "Verification method not authorized by controller '{Controller}' for {Relationship}.",
                        controller, relationship);
                    refused?.Add(controller);
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
    /// Enforces the structural invariants every root capability MUST satisfy per W3C ZCAP-LD v0.4.0:
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
        CapabilityProfile.EnsureSupported(root);

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
            // Preserve the same JSON representation used by the signing boundary.
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
    /// The revocation lookups of a verified root→leaf chain (#158): the root in
    /// <see cref="RevocationScope.Root"/> and each delegated link under the delegator of the proof that
    /// verified it (<paramref name="linkProofs"/>, non-null for every delegated link once step 3 has run).
    /// </summary>
    private static List<RevocationLookup> ChainRevocationLookups(List<Capability> chain, IReadOnlyList<Proof?> linkProofs)
    {
        var lookups = new List<RevocationLookup>(chain.Count) { new(chain[0].Id, RevocationScope.Root) };
        for (var i = 1; i < chain.Count; i++)
            lookups.Add(new RevocationLookup(chain[i].Id, RevocationScope.ForDelegationProof(linkProofs[i]!)));
        return lookups;
    }

    /// <summary>
    /// Upper bound on the distinct lookups one standalone sweep sends to the store. A genuine chain
    /// needs about two per link; reaching the bound fails the candidate closed.
    /// </summary>
    private const int MaxStandaloneRevocationLookups = 256;

    /// <summary>How one delegation proof relates to the route the standalone sweep is walking.</summary>
    private enum RouteStep
    {
        /// <summary>The proof names the required prefix, verifies, and its ancestry is usable; lookups were added.</summary>
        Fits,

        /// <summary>The proof does not belong to this route (wrong prefix or parent, non-canonical id,
        /// unparsable or non-embedded parent) or does not verify; it is skipped, as the chain walk skips it.</summary>
        DoesNotFit,

        /// <summary>The route cannot be swept: an embedded parent has no proof that fits and verifies,
        /// the budget is spent, or an infrastructure fault interrupted the walk.</summary>
        Unusable,
    }

    /// <summary>
    /// The result of walking one delegation proof's route: its step, the lookups the route contributes
    /// when it fits (its own state, never shared with sibling routes), and the failure to report when it
    /// does not.
    /// </summary>
    private sealed record RouteWalk(RouteStep Step, IReadOnlyList<RevocationLookup> Lookups, VerificationResult? Failure)
    {
        public static readonly RouteWalk NoFit = new(RouteStep.DoesNotFit, [], null);

        public static RouteWalk Unusable(VerificationResult failure) => new(RouteStep.Unusable, [], failure);

        /// <summary>A fitting route, de-duplicated and bounded; the bound fails closed.</summary>
        public static RouteWalk Fits(IEnumerable<RevocationLookup> lookups)
        {
            var distinct = lookups.Distinct().ToList();
            return distinct.Count <= MaxStandaloneRevocationLookups
                ? new RouteWalk(RouteStep.Fits, distinct, null)
                : Unusable(VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                    $"The delegation proof's ancestry exceeds the revocation sweep budget of {MaxStandaloneRevocationLookups} lookups."));
        }
    }

    /// <summary>
    /// The revocation lookups for one <b>verified</b> delegation proof of the leaf on the standalone
    /// <see cref="VerifyCapabilityProofAsync(Capability)"/> path (#158), or the failure to report when the
    /// ancestry that proof names cannot be authenticated. The leaf is looked up under the proof's
    /// delegator, authentic because the proof has verified. <see cref="WalkRouteAsync"/> then descends the
    /// proof's <c>capabilityChain</c> as the chain walk does: the first entry is the root (root scope); a
    /// deeper chain embeds the immediate parent as its last entry, whose own delegation proofs must name
    /// the chain's prefix and embed <i>its</i> parent in turn. Before an embedded parent's delegator is
    /// trusted, that parent's proof is verified as a chain link against the next ancestor (signature,
    /// parent-controller authorization, attenuation, expiry), up to the resolved or explicit root. The
    /// presented ancestry is otherwise unauthenticated: its controller could re-sign a child around a copy
    /// of a revoked parent with its proof stripped or its <c>verificationMethod</c> swapped, and the sweep
    /// would query the wrong scope (PR #162 review). Candidate isolation applies at every level: each
    /// nested proof is walked as its own route, a route that does not fit, does not verify or has no
    /// usable ancestry is discarded together with everything it collected, and an embedded parent fits
    /// when at least one of its proofs yields a complete authenticated route. Only a parent with no such
    /// route fails this candidate, with a fault if any branch faulted, else the last branch's reason, else
    /// <see cref="VerificationOutcome.MalformedCapability"/>. Lookups are de-duplicated and capped.
    /// </summary>
    private async Task<(VerificationResult? Failure, List<RevocationLookup> Lookups)> SweepStandaloneRouteAsync(
        Capability leaf, Proof verifiedProof, Capability? explicitRoot)
    {
        var walk = await WalkRouteAsync(leaf, verifiedProof, requiredChainIds: null, depth: 1, explicitRoot);
        if (walk.Step == RouteStep.Fits)
            walk = RouteWalk.Fits(walk.Lookups.Prepend(new RevocationLookup(leaf.Id, RevocationScope.ForDelegationProof(verifiedProof))));

        return walk.Step == RouteStep.Fits
            ? (null, walk.Lookups.ToList())
            : (walk.Failure ?? VerificationResult.Fail(VerificationOutcome.MalformedCapability,
                "The delegation proof's capabilityChain embeds an ancestor without a delegation proof that names the " +
                "chain's prefix, embeds its own parent and verifies."), []);
    }

    /// <summary>
    /// Walks one delegation <paramref name="proof"/> of <paramref name="current"/> and returns the lookups
    /// of the ancestors it reaches, as its own route. <paramref name="requiredChainIds"/> is the prefix a
    /// nested proof must name (null for the leaf's own, already verified proof). Unparsable embeddings do
    /// not throw.
    /// </summary>
    private async Task<RouteWalk> WalkRouteAsync(
        Capability current, Proof proof, string[]? requiredChainIds, int depth, Capability? explicitRoot)
    {
        if (depth > MaxChainLength || proof.CapabilityChain is not { Length: > 0 } chain)
            return RouteWalk.NoFit;

        var ids = ChainIds(chain);
        if (ids.Any(id => !CanonicalIri.IsCanonical(id)) ||
            (requiredChainIds is not null && !ids.SequenceEqual(requiredChainIds, StringComparer.Ordinal)))
            return RouteWalk.NoFit;

        var rootLookup = new RevocationLookup(ids[0], RevocationScope.Root);

        // First-level delegation: the parent IS the root, referenced by id only.
        if (chain.Length == 1)
        {
            return string.Equals(current.ParentCapability, ids[0], StringComparison.Ordinal)
                ? RouteWalk.Fits([rootLookup])
                : RouteWalk.NoFit;
        }

        // Deeper: [rootId, ...ancestorIds, {immediate parent}], ancestors as id strings only.
        Capability? parent;
        try
        {
            if (chain[..^1].Any(entry => TryExtractStringValue(entry) is null) ||
                !TryDeserializeCapability(chain[^1], out parent) || parent is null)
                return RouteWalk.NoFit;
        }
        catch (JsonException)
        {
            return RouteWalk.NoFit;
        }

        if (!string.Equals(parent.Id, current.ParentCapability, StringComparison.Ordinal))
            return RouteWalk.NoFit;

        // The embedded parent is trusted only through a proof of its own that names the prefix AND
        // verifies as a chain link against the next ancestor AND whose own ancestry walks to the root; it
        // is then looked up under that proof's delegator. Each proof is its own branch: a branch that
        // fails is discarded with everything it collected, so it can neither veto a sibling branch that
        // completes nor leave its lookups behind (PR #162 review). Intermediate ancestors are reached the
        // same way through their own embeddings.
        var prefix = ids[..^1];
        var lookups = new List<RevocationLookup> { rootLookup };
        var fitted = false;
        VerificationResult? fault = null;
        VerificationResult? failure = null;
        foreach (var parentProof in parent.Proof?.DelegationProofs() ?? Enumerable.Empty<Proof>())
        {
            if (parentProof.CapabilityChain is not { Length: > 0 } parentChain ||
                !ChainIds(parentChain).SequenceEqual(prefix, StringComparer.Ordinal) ||
                !RevocationScope.TryForDelegationProof(parentProof, out var parentScope))
                continue;

            var verified = await VerifySingleDelegationProofAsync(
                parent, parentProof, parentCapabilityOverride: null, requireParentAuthorization: true,
                explicitRoot, applyCreatedCheck: false, applyCaveatPolicy: false);
            var branch = verified.IsValid
                ? await WalkRouteAsync(parent, parentProof, prefix, depth + 1, explicitRoot)
                : RouteWalk.Unusable(verified);
            if (branch.Step != RouteStep.Fits)
            {
                // An infrastructure fault is reported as such, never as a bad ancestor.
                if (branch.Failure?.Outcome == VerificationOutcome.CouldNotVerify)
                    fault = branch.Failure;
                else if (branch.Failure is not null)
                    failure = branch.Failure;
                continue;
            }

            lookups.AddRange(branch.Lookups);
            lookups.Add(new RevocationLookup(parent.Id, parentScope));
            fitted = true;
        }

        if (fitted)
            return RouteWalk.Fits(lookups);

        return RouteWalk.Unusable(fault ?? failure ?? VerificationResult.Fail(VerificationOutcome.MalformedCapability,
            $"Embedded capability '{parent.Id}' carries no delegation proof that names the chain's prefix, embeds its own parent and verifies."));
    }

    /// <summary>
    /// True when two values are the same JSON (compared by RFC 8785 canonical form, so an in-memory
    /// <see cref="Capability"/> equals its wire JSON).
    /// </summary>
    // Comparison only, never signing: allow canonical forms larger than NetCid's 1 MB default so a
    // legitimate maximum-length chain is not refused as CouldNotVerify.
    private const int MaxComparedJsonBytes = 16 * 1024 * 1024;

    private static byte[] CanonicalForComparison(object value) => NetCid.JcsCanonicalizer.Canonicalize(
        JsonSerializer.SerializeToElement(value, ZcapJsonOptions.Default), MaxComparedJsonBytes);

    private static bool IsSameJson(object first, object second)
        => CanonicalForComparison(first).AsSpan().SequenceEqual(CanonicalForComparison(second));

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
    /// delegation chain. Informational <c>reason</c>/<c>metadata</c> in the proof is recorded.
    /// </summary>
    /// <remarks>
    /// Fail-closed: structural, signature, authorization, replay or infrastructure failures
    /// return false. Unsupported vocabulary caveats are rejected in all capability representations.
    /// Authorization requires a valid chain, with expiration-ceiling and delegation-created
    /// policy exceptions. Already-expired capabilities or chains with a revoked ancestor are
    /// already inert and cannot be explicitly re-revoked; by design, audit callers must not expect
    /// a new record for them. Unsupported vocabulary is never exempted.
    /// The recorded RevokedBy is the authenticated verification method's bare DID. Replay keys
    /// on the request ID, so clients must mint a fresh ID for each request. Storage precedes nonce
    /// consumption to permit retries after store failures; a later replay denial does not undo a
    /// completed write. Only null arguments throw; other failures return false.
    /// COMPLIANCE: MUST-21, SHOULD-07.
    /// </remarks>
    /// <param name="capability">The capability to revoke, with its full delegation chain (for authorization).</param>
    /// <param name="signedRevocation">The signed revocation request (see <see cref="ISigningService.SignRevocationAsync"/>).</param>
    /// <returns>True if authenticated, authorized, fresh, and recorded; otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Capability or signedRevocation is null.</exception>
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
            if (!CapabilityProfile.IsSupported(capability, caveats: _caveats) || !CapabilityProfile.IsSupported(explicitRoot) ||
                !CapabilityProfile.IsSupported(signedRevocation.Capability?.EmbeddedCapability, caveats: _caveats) ||
                !CapabilityProfile.IsSupportedProof(signedRevocation.Proof, _caveats))
                return false;

            // The request id is the replay nonce and the capability id the revocation key; only their
            // normalized forms are bound by the signatures (#157).
            if (!CanonicalIri.IsCanonical(signedRevocation.Id) || !CanonicalIri.IsCanonical(capability.Id))
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
            if (signedRevocation.Capability is null ||
                !string.Equals(signedRevocation.Capability.CapabilityId, capability.Id, StringComparison.Ordinal))
                return false;

            // Proof payload fields MUST be consistent with the invocation body.
            var proofCapabilityId = proof.Capability?.CapabilityId;
            if (!string.Equals(proofCapabilityId, signedRevocation.Capability.CapabilityId, StringComparison.Ordinal) ||
                !string.Equals(proof.CapabilityAction, signedRevocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(proof.InvocationTarget, signedRevocation.InvocationTarget, StringComparison.Ordinal))
                return false;
            if (!TryReadSignedRevocationDetails(proof, out var reason, out var metadata))
                return false;

            // AUTHENTICATE: the signature proves the caller holds verificationMethod's private key.
            if (!await VerifyInvocationSignatureAsync(signedRevocation))
                return false;

            // AUTHORIZE: the authenticated verificationMethod must control the capability or an
            // ancestor. AuthorizeRevocationAsync verifies the chain first (fail-closed) and names the
            // scopes the record is written in (#158).
            if (await AuthorizeRevocationAsync(capability, proof.VerificationMethod, explicitRoot) is not { } grant)
                return false;

            // Record the revocation durably BEFORE consuming the replay nonce. If the store write
            // throws, control passes to the fail-closed catch with the nonce still unconsumed, so a
            // legitimate retry with the same signed request is not mistaken for a replay when nothing
            // was actually recorded. Revocation is idempotent, so the only cost of this ordering is a
            // replayed-after-eviction request re-applying the same record before the nonce check
            // below rejects it — harmless. (INonceStore has no release primitive, so reordering is
            // the minimal robust fix.)
            var revokerDid = RevocationScope.DelegatorOf(proof.VerificationMethod);
            if (!await RevokeCapabilityCoreAsync(capability.Id, grant, revokerDid, reason, metadata))
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
    /// The root the verifier trusts under <paramref name="capabilityId"/>, if any: the explicit root
    /// when its id matches, else the configured <see cref="IRootCapabilityResolver"/>'s root with
    /// exactly that id. Null means the verifier does not know this id as a root; a resolver result
    /// with a different id (a resolver that returns its one root for any id) is also "not a root".
    /// Resolver faults propagate so the caller fails closed.
    /// </summary>
    private async Task<Capability?> FindTrustedRootAsync(string capabilityId, Capability? explicitRoot)
    {
        if (explicitRoot is not null && string.Equals(explicitRoot.Id, capabilityId, StringComparison.Ordinal))
        {
            return explicitRoot;
        }

        if (_rootResolver is null)
        {
            return null;
        }

        var resolved = await _rootResolver.ResolveRootAsync(capabilityId);
        return resolved is not null && string.Equals(resolved.Id, capabilityId, StringComparison.Ordinal)
            ? resolved
            : null;
    }

    /// <summary>What a signed revocation records: the root of the authorizing chain and the scopes (#158).</summary>
    private sealed record RevocationGrant(string RootCapabilityId, IReadOnlyList<RevocationScope> Scopes);

    /// <summary>
    /// The grant when <paramref name="verificationMethod"/> may revoke <paramref name="capability"/> —
    /// i.e. it controls the capability or any ancestor in its delegation chain — otherwise null.
    /// Cryptographically verifies the chain before trusting any controller fields; a forged or invalid
    /// chain yields null. A root is authorized against the trusted root (explicit or resolved), never the
    /// caller's copy, and an explicit root admits only itself as a revocable root.
    /// <paramref name="verificationMethod"/> is the authenticated proof verification method (or a
    /// bare DID); authentication is performed by the caller.
    /// </summary>
    private async Task<RevocationGrant?> AuthorizeRevocationAsync(
        Capability capability, string verificationMethod, Capability? explicitRoot)
    {
        try
        {
            // A root is a trust anchor and is never taken from the request. Whether the id names a root
            // is decided by the verifier's own trust (the explicit root or the configured resolver), not
            // by the request's shape: an id the verifier knows as a root is authorized against that
            // trusted root however the request presents it. A root-only chain has no delegation proof,
            // so a root-shaped body naming the caller as controller — or a delegated-shaped body that
            // merely borrows a root's id under the caller's own, validly signed chain — would otherwise
            // let anyone who knows a root id revoke it (Issue #155). A root-shaped or urn:zcap:root:-
            // named capability the verifier cannot resolve has nothing trusted to authorize against.
            //
            // With an explicit root the resolver is still consulted for any other id being revoked:
            // skipping it would let a forged delegation under the explicit root borrow the id of another
            // root the resolver trusts. The explicit root's own id is anchored to the explicit root itself,
            // which the caller vouches for (never build it from request input). A resolver fault fails the
            // revocation closed; nothing is recorded and the nonce is not consumed, so the request can be
            // retried.
            var trustedRoot = await FindTrustedRootAsync(capability.Id, explicitRoot);
            if (trustedRoot is not null)
            {
                // An explicit root scopes the whole call, exactly as a delegated chain must end at it: a
                // different root the resolver knows cannot be revoked through it.
                if (explicitRoot is not null &&
                    !string.Equals(trustedRoot.Id, explicitRoot.Id, StringComparison.Ordinal))
                {
                    return null;
                }

                // Binds the trusted root to the id (and, for the standard form, to its encoded target).
                capability = await ResolveRootCapabilityAsync(capability.Id, trustedRoot);
            }
            else if (string.IsNullOrEmpty(capability.ParentCapability) ||
                     capability.Id.StartsWith(RootIdPrefix, StringComparison.OrdinalIgnoreCase))
            {
                // The "urn" scheme and the "zcap" namespace are case-insensitive (RFC 8141), so
                // URN:ZCAP:ROOT:… is the same reserved form. Refusing every casing keeps such a variant
                // from reaching a store whose keys compare case-insensitively and landing on a root.
                return null;
            }

            // Verify the chain cryptographically before trusting controller fields. Without that
            // verification, a caller passing a crafted Capability with a tampered controller could
            // authorize themselves to revoke a legitimate capability.
            //
            // Do NOT apply the opt-in 3-month expiration ceiling (Issue #73), the delegation-proof
            // `created` soundness check (Issue #99), nor the delegated-`expires` MUST here: revocation
            // must stay possible for a long-lived, malformed-`created`, or non-expiring delegation —
            // refusing to authorize its removal would be exactly backwards. All three are constraints on
            // accepting/invoking a zcap, not on revoking one.
            // Caveat policy (Validate, IsAttenuationOf) is skipped for the same reason; caveat integrity
            // (registered types, declared parameters, signed context) is still required (#157).
            //
            // Document-based authorization (Issue #65): the revoker is authorized when ANY link in
            // a cryptographically verified chain authorizes its verification method for the
            // capabilityDelegation relationship — revocation is a delegation-authority action (the
            // authority to delegate is the authority to revoke that delegation). This resolves each
            // controller's DID document (via the same IVerificationRelationshipResolver the
            // invocation/delegation paths use), so it honors cross-DID references and per-purpose key
            // separation: a key the controller's document lists only under capabilityInvocation can
            // no longer revoke. Self-revoke (the leaf's own controller) and up-chain delegators are
            // both covered because every link is checked. When the proofs name several chains, each
            // verified chain is checked in turn.
            RevocationGrant? grant = null;
            var (result, _) = await BuildAndVerifyChainAsync(
                capability, explicitRoot, applyExpirationCeiling: false, applyCreatedCheck: false,
                requireDelegatedExpires: false, applyCaveatPolicy: false,
                accept: async (chain, linkProofs, search) =>
                {
                    foreach (var link in chain)
                    {
                        if (await IsControllerAuthorizedAsync(
                                verificationMethod, link, VerificationRelationship.CapabilityDelegation,
                                search.RefusedControllers))
                        {
                            grant = await GrantForAsync(chain, linkProofs);
                            return true;
                        }
                    }

                    return false;
                });
            return result.IsValid ? grant : null;
        }
        catch (Exception ex)
        {
            // Fail closed on ANY fault from the chain walk, not just a malformed chain.
            // Building the chain can throw CapabilityValidationException, JsonException, or a
            // DID-resolution error — all of which mean "cannot establish authorization", i.e. not
            // authorized. RevokeCapabilityAsync's own top-level catch would also fail closed (no caller
            // was ever at crash risk), but catching here keeps the authorization decision local and
            // attributes the cause to THIS step rather than the broader revocation flow (PR #84 review;
            // Issue #64). Severity is chosen by LogFailedClosed.
            LogFailedClosed(ex,
                "AuthorizeRevocationAsync failed closed for capability {CapabilityId}", capability.Id);
            return null;
        }
    }

    /// <summary>
    /// The scopes a revocation of the accepted chain's leaf is recorded in (#158): the root scope for a
    /// root; otherwise the delegator of the proof the walk verified the leaf with, plus the delegator of
    /// every other delegation proof on the leaf that names the same chain and also verifies against the
    /// same parent. Recording the co-signers keeps a proof set from failing open: with a single record,
    /// a holder could drop the recorded signer's proof and present the leaf under a co-signer's.
    /// </summary>
    private async Task<RevocationGrant> GrantForAsync(List<Capability> chain, IReadOnlyList<Proof?> linkProofs)
    {
        var rootId = chain[0].Id;
        if (chain.Count == 1)
            return new RevocationGrant(rootId, [RevocationScope.Root]);

        var leaf = chain[^1];
        var parent = chain[^2];
        var accepted = linkProofs[^1]!;
        var scopes = new List<RevocationScope> { RevocationScope.ForDelegationProof(accepted) };
        var acceptedChainIds = ChainIds(accepted.CapabilityChain!);
        foreach (var proof in leaf.Proof?.DelegationProofs() ?? Enumerable.Empty<Proof>())
        {
            if (ReferenceEquals(proof, accepted) ||
                proof.CapabilityChain is not { Length: > 0 } rawChain ||
                !ChainIds(rawChain).SequenceEqual(acceptedChainIds, StringComparer.Ordinal) ||
                !RevocationScope.TryForDelegationProof(proof, out var scope) ||
                scopes.Contains(scope))
                continue;

            var verified = await VerifySingleDelegationProofAsync(
                leaf, proof, parent, requireParentAuthorization: true,
                applyCreatedCheck: false, applyCaveatPolicy: false);
            if (verified.IsValid)
                scopes.Add(scope);
        }

        return new RevocationGrant(rootId, scopes);
    }

    /// <summary>
    /// Reads the informational reason/metadata, which the revocation context makes RDFC sign. They
    /// must not be used for authorization. Only the shapes the signer emits are accepted: a reason
    /// written as an array (<c>["…"]</c>) signs the same statement, so the record would silently lose it.
    /// </summary>
    private static bool TryReadSignedRevocationDetails(
        Proof proof, out string? reason, out IDictionary<string, string>? metadata)
    {
        reason = null;
        metadata = null;
        if (proof.AdditionalProperties is not { } extra)
            return true;

        if (extra.TryGetValue(Proof.RevocationReasonField, out var reasonElement))
        {
            if (reasonElement.ValueKind != JsonValueKind.String)
                return false;
            reason = reasonElement.GetString();
        }

        if (extra.TryGetValue(Proof.RevocationMetadataField, out var metadataElement))
        {
            if (metadataElement.ValueKind != JsonValueKind.Object ||
                metadataElement.EnumerateObject().Any(entry => entry.Value.ValueKind != JsonValueKind.String))
                return false;
            metadata = metadataElement.Deserialize<Dictionary<string, string>>(ZcapJsonOptions.Default);
        }

        return true;
    }

    /// <summary>
    /// Checks whether a capability id is revoked in <paramref name="scope"/> (#158): by a record in that
    /// scope or by an unscoped one.
    /// COMPLIANCE FIX: MUST-21 - Check revocation status
    /// </summary>
    public Task<bool> IsCapabilityRevokedAsync(string capabilityId, RevocationScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrEmpty(capabilityId))
            return Task.FromResult(false);

        return _revocationService.IsRevokedAsync(capabilityId, scope);
    }

    /// <summary>One record per granted scope, all naming the authorizing chain's root (informational).</summary>
    private async Task<bool> RevokeCapabilityCoreAsync(
        string capabilityId,
        RevocationGrant grant,
        string revokerDid,
        string? reason = null,
        IDictionary<string, string>? metadata = null)
    {
        foreach (var scope in grant.Scopes)
        {
            await _revocationService.RevokeAsync(new RevocationRequest
            {
                CapabilityId = capabilityId,
                Scope = scope,
                RootCapabilityId = grant.RootCapabilityId,
                RevokedBy = revokerDid,
                Reason = reason,
                Metadata = metadata
            });
        }

        return true;
    }
}
