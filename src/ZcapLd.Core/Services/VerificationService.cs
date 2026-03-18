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
    /// Constructor with all core dependencies (no replay protection).
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService)
        : this(didResolver, caveatProcessor, suiteProvider, revocationService,
               NullNonceStore.Instance)
    {
    }

    /// <summary>
    /// Full constructor with all dependencies including replay protection.
    /// </summary>
    public VerificationService(
        IDidResolver didResolver,
        ICaveatProcessor caveatProcessor,
        ICryptoSuiteProvider suiteProvider,
        IRevocationService revocationService,
        INonceStore nonceStore,
        TimeSpan? nonceWindow = null)
    {
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));
        _caveatProcessor = caveatProcessor ?? throw new ArgumentNullException(nameof(caveatProcessor));
        _suiteProvider = suiteProvider ?? throw new ArgumentNullException(nameof(suiteProvider));
        _revocationService = revocationService ?? throw new ArgumentNullException(nameof(revocationService));
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
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

        if (capability.Proof.ProofPurpose != "capabilityDelegation")
        {
            return false;
        }

        var parentCapability = parentCapabilityOverride;
        if (parentCapability == null &&
            !TryExtractEmbeddedParentFromProofChain(capability.Proof.CapabilityChain, out parentCapability))
        {
            if (requireParentAuthorization)
            {
                // Without embedded parent context, standalone authorization cannot be proven.
                return false;
            }
        }

        if (parentCapability != null &&
            !IsControllerAuthorized(capability.Proof.VerificationMethod, parentCapability))
        {
            return false;
        }

        if (requireParentAuthorization &&
            (parentCapability == null || string.IsNullOrWhiteSpace(parentCapability.Controller)))
        {
            return false;
        }

        // Get the public key and look up the crypto suite for this proof type
        var resolvedKey = await _didResolver.ResolvePublicKeyAsync(capability.Proof.VerificationMethod);
        var suite = _suiteProvider.GetByProofType(capability.Proof.Type)
            ?? throw new CapabilityValidationException(
                $"Unsupported proof type: {capability.Proof.Type}");

        var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            capabilityWithoutProof,
            capability.Proof);
        var signatureBytes = MultibaseCodec.Decode(capability.Proof.ProofValue);

        return suite.Verify(canonicalBytes, signatureBytes, resolvedKey.PublicKeyBytes);
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

            // 2b. Proof payload fields MUST be semantically consistent with invocation fields
            if (!string.Equals(invocation.Proof.Capability as string, invocation.Capability, StringComparison.Ordinal) ||
                !string.Equals(invocation.Proof.CapabilityAction, invocation.CapabilityAction, StringComparison.Ordinal) ||
                !string.Equals(invocation.Proof.InvocationTarget, invocation.InvocationTarget, StringComparison.Ordinal))
                return false;

            // 3. Verify invocation target matches capability
            if (!IsValidInvocationTarget(invocation.InvocationTarget, capability.InvocationTarget))
                return false;

            // 4. Verify action is allowed
            if (capability.AllowedAction.Length > 0 &&
                !capability.AllowedAction.Contains(invocation.CapabilityAction))
                return false;

            // 5. Verify the invocation signature
            var resolvedKey = await _didResolver.ResolvePublicKeyAsync(invocation.Proof.VerificationMethod);
            var suite = _suiteProvider.GetByProofType(invocation.Proof.Type)
                ?? throw new CapabilityValidationException(
                    $"Unsupported proof type: {invocation.Proof.Type}");

            var invocationWithoutProof = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
            var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
                invocationWithoutProof,
                invocation.Proof);
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
                if (child.Expires.HasValue && child.Expires.Value < DateTime.UtcNow)
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

            if (current.Proof?.CapabilityChain == null || current.Proof.CapabilityChain.Length == 0)
            {
                throw new CapabilityValidationException(
                    "Delegated capability missing capabilityChain in proof");
            }

            var chainRootId = TryExtractStringValue(current.Proof.CapabilityChain[0]);
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

            if (current.Proof.CapabilityChain.Length < 2)
            {
                throw new CapabilityValidationException(
                    "capabilityChain MUST include root capability ID and embedded immediate parent capability object.");
            }

            if (!TryDeserializeCapability(current.Proof.CapabilityChain[^1], out var parentCapability) || parentCapability == null)
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

        if (string.IsNullOrWhiteSpace(root.Controller))
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
        if (child.Expires.HasValue && parent.Expires.HasValue)
        {
            if (child.Expires.Value > parent.Expires.Value)
                return false;
        }

        // 3. Allowed actions must be subset of parent (if parent specifies)
        if (parent.AllowedAction.Length > 0 && child.AllowedAction.Length > 0)
        {
            if (!child.AllowedAction.All(action => parent.AllowedAction.Contains(action)))
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
    /// Checks if the controller (from verification method) is authorized for this capability
    /// </summary>
    private bool IsControllerAuthorized(string verificationMethod, Capability capability)
    {
        // Extract DID from verification method
        // Format: did:key:z...#z... or just did:key:z...
        var did = verificationMethod.Split('#')[0];

        // Check if this DID is in the capability's controller
        // Controller is always a string in current model
        return did == capability.Controller || verificationMethod == capability.Controller;
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
            capability = JsonSerializer.Deserialize<Capability>(jsonElement.GetRawText());
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
    /// Revokes a capability by ID
    /// COMPLIANCE FIX: MUST-21, SHOULD-07 - Revocation support
    /// Per W3C spec: Revoked capabilities must be stored until their expiration
    /// </summary>
    public Task<bool> RevokeCapabilityAsync(string capabilityId, string revokerDid)
    {
        if (string.IsNullOrEmpty(capabilityId))
            throw new ArgumentException("Capability ID cannot be null or empty", nameof(capabilityId));
        if (string.IsNullOrEmpty(revokerDid))
            throw new ArgumentException("Revoker DID cannot be null or empty", nameof(revokerDid));

        return RevokeCapabilityCoreAsync(capabilityId, revokerDid);
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
