using System.Text.Json;
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
    private const int MaxChainLength = 10; // Per spec: SHOULD limit to 10

    /// <summary>
    /// Default window during which invocation nonces are tracked for replay protection.
    /// </summary>
    public static readonly TimeSpan DefaultNonceWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Backward-compatible constructor (Ed25519 only).
    /// </summary>
    public VerificationService(IDidResolver didResolver, ICaveatProcessor caveatProcessor)
        : this(didResolver, caveatProcessor, CreateDefaultSuiteProvider(),
               new RevocationService(new InMemoryRevocationStore()))
    {
    }

    /// <summary>
    /// Backward-compatible constructor with custom revocation service (Ed25519 only).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        IRevocationService revocationService)
        : this(didResolver, caveatProcessor, CreateDefaultSuiteProvider(), revocationService)
    {
    }

    /// <summary>
    /// Constructor with explicit crypto suite provider.
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
    /// Full constructor with all dependencies including canonicalizer provider.
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService,
        INonceStore nonceStore,
        IDocumentCanonicalizerProvider canonicalizerProvider,
        TimeSpan? nonceWindow = null)
    {
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));
        _caveatProcessor = caveatProcessor ?? throw new ArgumentNullException(nameof(caveatProcessor));
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
        _revocationService = revocationService ?? throw new ArgumentNullException(nameof(revocationService));
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        _canonicalizerProvider = canonicalizerProvider ?? throw new ArgumentNullException(nameof(canonicalizerProvider));
        _nonceWindow = nonceWindow ?? DefaultNonceWindow;
    }

    internal static ICryptoSuiteProvider CreateDefaultSuiteProvider()
    {
        var provider = new CryptoSuiteProvider();
        provider.Register(CryptoSuite.Ed25519());
        provider.Register(CryptoSuite.P256());
        return provider;
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

        try
        {
            // Standalone proof verification requires parent authorization context.
            return await VerifyDelegationProofAsync(
                capability,
                parentCapabilityOverride: null,
                requireParentAuthorization: true);
        }
        catch
        {
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

            if (parentCapability != null &&
                !IsControllerAuthorized(proof.VerificationMethod, parentCapability))
            {
                return false;
            }

            // A delegation signed by the controller of a now-revoked parent is not a valid basis
            // for authority. VerifyCapabilityChainAsync checks revocation for every link, but the
            // standalone VerifyCapabilityProofAsync path previously checked only the leaf — so a
            // capability whose immediate parent had been revoked still passed (Issue #63). Check
            // the resolved parent (embedded in proof.capabilityChain, or the chain-walk override)
            // here so both paths honour ancestor revocation.
            if (parentCapability != null && await IsCapabilityRevokedAsync(parentCapability.Id))
            {
                return false;
            }

            if (requireParentAuthorization &&
                (parentCapability == null || parentCapability.Controller is null || parentCapability.Controller.IsEmpty))
            {
                return false;
            }

            // Get the public key and look up the crypto suite for this proof type
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(proof.VerificationMethod);
            var suite = _suiteProvider.GetByProofType(proof.Type);
            if (suite == null)
            {
                return false;
            }

            var canonicalizer = ResolveCanonicalizer(suite);
            var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
            var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
                capabilityWithoutProof,
                proof,
                canonicalizer);
            var signatureBytes = MultibaseCodec.Decode(proof.ProofValue);

            return suite.Verify(canonicalBytes, signatureBytes, resolvedKey.PublicKeyBytes);
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

            // 1. Verify the capability chain is valid
            if (!await VerifyCapabilityChainAsync(capability))
                return false;

            // 2. Verify invocation proof exists and has correct purpose
            if (invocation.Proof == null || invocation.Proof.ProofPurpose != "capabilityInvocation")
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
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(invocation.Proof.VerificationMethod);
            var suite = _suiteProvider.GetByProofType(invocation.Proof.Type)
                ?? throw new CapabilityValidationException(
                    $"Unsupported proof type: {invocation.Proof.Type}");

            var canonicalizer = ResolveCanonicalizer(suite);
            var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
            var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
                invocationWithoutProof,
                invocation.Proof,
                canonicalizer);
            var signatureBytes = MultibaseCodec.Decode(invocation.Proof.ProofValue);

            if (!suite.Verify(canonicalBytes, signatureBytes, resolvedKey.PublicKeyBytes))
                return false;

            // 6. Verify the controller is authorized
            if (!IsControllerAuthorized(invocation.Proof.VerificationMethod, capability))
                return false;

            // 7. SECURITY FIX S-05: Evaluate ALL caveats from the entire chain
            // Per spec: Children inherit ALL parent caveats, so we must check the entire chain
            var chain = await BuildCapabilityChainAsync(capability);
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
        catch
        {
            return false;
        }
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
            // Build the complete chain from leaf to root
            var chain = await BuildCapabilityChainAsync(capability);

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
        catch
        {
            // For other unexpected exceptions, return false
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
    /// Checks if the controller (from the proof's verification method) is authorized for
    /// this capability. A capability may have multiple controllers; the proof is authorized
    /// when its verification method matches any one of them (by bare DID or full VM URI).
    /// </summary>
    private bool IsControllerAuthorized(string verificationMethod, Capability capability)
    {
        return capability.Controller is not null &&
               capability.Controller.ContainsVerificationMethod(verificationMethod);
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

    private IDocumentCanonicalizer ResolveCanonicalizer(ICryptoSuite suite)
    {
        return _canonicalizerProvider.GetByMethod(suite.CanonicalizationMethod)
            ?? throw new CryptographicException(
                $"No canonicalizer registered for method: {suite.CanonicalizationMethod}");
    }

    /// <summary>
    /// Revokes a capability after verifying the revoker is authorized: the revoker must control
    /// the capability itself or any ancestor in its delegation chain (an up-chain delegator).
    /// <paramref name="revokerDid"/> is a DID the host has already authenticated — the library
    /// performs authorization, not authentication. Returns <c>false</c> (recording nothing) when
    /// the revoker is not authorized or the chain cannot be cryptographically verified.
    /// COMPLIANCE: MUST-21, SHOULD-07 — revoked capabilities are stored until their expiration.
    /// </summary>
    public async Task<bool> RevokeCapabilityAsync(Capability capability, string revokerDid)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));
        if (string.IsNullOrEmpty(revokerDid))
            throw new ArgumentException("Revoker DID cannot be null or empty", nameof(revokerDid));

        if (!await IsRevokerAuthorizedAsync(capability, revokerDid))
            return false;

        return await RevokeCapabilityCoreAsync(capability.Id, revokerDid);
    }

    /// <summary>
    /// True when <paramref name="revokerDid"/> may revoke <paramref name="capability"/> — i.e. it
    /// controls the capability or any ancestor in its delegation chain. Cryptographically verifies
    /// the chain before trusting any controller fields; a forged or invalid chain yields false.
    /// </summary>
    private async Task<bool> IsRevokerAuthorizedAsync(Capability capability, string revokerDid)
    {
        // Verify the chain cryptographically first so controller fields can be trusted.
        // Without this, a caller passing a crafted Capability with a tampered controller
        // could authorize themselves to revoke a legitimate capability.
        if (!await VerifyCapabilityChainAsync(capability))
            return false;

        try
        {
            var chain = await BuildCapabilityChainAsync(capability);
            // Authorization is a string-level controller match: revokerDid (a bare DID or a
            // did#key-fragment) authorizes when it equals a chain controller, or its bare DID
            // does. This covers did:key (the DID *is* the key) and a did:web controller whose
            // bare DID matches the revoker's key fragment (did:web:issuer#key-1 → did:web:issuer).
            // It does NOT resolve the controller's DID document, so a revoker key belonging to a
            // *different* DID that the controller would authorize is not matched.
            // TODO: support cross-DID key authorization by resolving the controller's DID
            // document and checking its verificationMethod/capabilityDelegation relationships.
            return chain.Any(link =>
                link.Controller is not null &&
                link.Controller.ContainsVerificationMethod(revokerDid));
        }
        catch (CapabilityValidationException)
        {
            // Only the structural re-build (BuildCapabilityChainAsync) runs here, and it raises
            // exactly CapabilityValidationException — a malformed chain → not authorized. Infra
            // errors (DID resolution, network, crypto) can't reach this catch: VerifyCapabilityChainAsync
            // above is fully fail-closed (swallows everything → false), so we never get here unless the
            // chain already verified. Net effect for the caller: this method is fail-closed end to end.
            return false;
        }
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

    private async Task<bool> RevokeCapabilityCoreAsync(string capabilityId, string revokerDid)
    {
        await _revocationService.RevokeAsync(new RevocationRequest
        {
            CapabilityId = capabilityId,
            RevokedBy = revokerDid
        });

        return true;
    }
}
