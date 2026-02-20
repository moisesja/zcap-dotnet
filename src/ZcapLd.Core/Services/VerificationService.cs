using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Service for verifying ZCAP-LD capabilities and invocations
/// Implements W3C ZCAP-LD specification verification requirements
/// </summary>
public class VerificationService : IVerificationService
{
    private readonly ISigningService _signingService;
    private readonly ICaveatProcessor _caveatProcessor;
    private const int MaxChainLength = 10; // Per spec: SHOULD limit to 10

    public VerificationService(ISigningService signingService, ICaveatProcessor caveatProcessor)
    {
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
        _caveatProcessor = caveatProcessor ?? throw new ArgumentNullException(nameof(caveatProcessor));
    }

    /// <summary>
    /// Verifies a capability's cryptographic proof
    /// </summary>
    public async Task<bool> VerifyCapabilityProofAsync(Capability capability)
    {
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        // Root capabilities have no proof
        if (string.IsNullOrEmpty(capability.ParentCapability))
        {
            // Root capability should NOT have a proof
            return capability.Proof == null;
        }

        // Delegated capability MUST have a proof
        if (capability.Proof == null)
            return false;

        // Verify proof purpose is capabilityDelegation
        if (capability.Proof.ProofPurpose != "capabilityDelegation")
            return false;

        try
        {
            // Get the public key for verification
            var publicKey = await ResolvePublicKeyAsync(capability.Proof.VerificationMethod);

            // Serialize the capability without the proof
            var capabilityWithoutProof = new
            {
                context = capability.Context,
                id = capability.Id,
                parentCapability = capability.ParentCapability,
                controller = capability.Controller,
                invocationTarget = capability.InvocationTarget,
                expires = capability.Expires,
                allowedAction = capability.AllowedAction.Length > 0 ? capability.AllowedAction : null,
                caveat = capability.Caveat.Length > 0 ? capability.Caveat : null
            };

            // Canonicalize and verify signature
            var canonicalBytes = Ed25519Signer.CanonicalizeDocument(capabilityWithoutProof);
            var signatureBytes = Ed25519Signer.DecodeSignature(capability.Proof.ProofValue);

            return Ed25519Signer.Verify(canonicalBytes, signatureBytes, publicKey);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an invocation request
    /// </summary>
    public async Task<bool> VerifyInvocationAsync(Invocation invocation, Capability capability)
    {
        if (invocation == null)
            throw new ArgumentNullException(nameof(invocation));
        if (capability == null)
            throw new ArgumentNullException(nameof(capability));

        try
        {
            // 1. Verify the capability chain is valid
            if (!await VerifyCapabilityChainAsync(capability))
                return false;

            // 2. Verify invocation proof exists and has correct purpose
            if (invocation.Proof == null || invocation.Proof.ProofPurpose != "capabilityInvocation")
                return false;

            // 3. Verify invocation target matches capability
            if (!IsValidInvocationTarget(invocation.InvocationTarget, capability.InvocationTarget))
                return false;

            // 4. Verify action is allowed
            if (capability.AllowedAction.Length > 0 &&
                !capability.AllowedAction.Contains(invocation.CapabilityAction))
                return false;

            // 5. Verify the invocation signature
            var publicKey = await ResolvePublicKeyAsync(invocation.Proof.VerificationMethod);

            var invocationWithoutProof = new
            {
                capability = invocation.Capability,
                capabilityAction = invocation.CapabilityAction,
                invocationTarget = invocation.InvocationTarget
            };

            var canonicalBytes = Ed25519Signer.CanonicalizeDocument(invocationWithoutProof);
            var signatureBytes = Ed25519Signer.DecodeSignature(invocation.Proof.ProofValue);

            if (!Ed25519Signer.Verify(canonicalBytes, signatureBytes, publicKey))
                return false;

            // 6. Verify the controller is authorized
            if (!IsControllerAuthorized(invocation.Proof.VerificationMethod, capability))
                return false;

            // 7. Evaluate all caveats
            var context = new InvocationContext
            {
                InvocationTime = DateTime.UtcNow,
                RequestedAction = invocation.CapabilityAction,
                TargetResource = invocation.InvocationTarget
            };

            return await _caveatProcessor.EvaluateCaveatsAsync(capability, context);
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
                throw new CapabilityValidationException(
                    $"Capability chain length ({chain.Count}) exceeds maximum allowed ({MaxChainLength})");
            }

            // 2. Verify each link in the chain
            for (int i = chain.Count - 1; i > 0; i--)
            {
                var child = chain[i];
                var parent = chain[i - 1];

                // Verify delegation proof
                if (!await VerifyCapabilityProofAsync(child))
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

            // 3. Verify root capability (should have no proof)
            var root = chain[0];
            if (root.Proof != null)
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Resolves a DID to its public key for verification
    /// </summary>
    public async Task<byte[]> ResolvePublicKeyAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        // For did:key format, extract the public key directly
        if (did.StartsWith("did:key:"))
        {
            // Format: did:key:z{multibase-encoded-public-key}#z{multibase-encoded-public-key}
            // Extract the key after "did:key:"
            var keyPart = did.Replace("did:key:", "").Split('#')[0];

            if (keyPart.StartsWith("z"))
            {
                try
                {
                    // Decode multibase (base58-btc)
                    var decoded = Ed25519Signer.DecodeSignature(keyPart);

                    // For Ed25519, the decoded value includes a multicodec prefix
                    // 0xed01 for Ed25519 public key, so we skip the first 2 bytes
                    if (decoded.Length >= 34 && decoded[0] == 0xed && decoded[1] == 0x01)
                    {
                        return decoded.Skip(2).ToArray();
                    }

                    // If it's exactly 32 bytes, it's already the raw public key
                    if (decoded.Length == 32)
                    {
                        return decoded;
                    }
                }
                catch
                {
                    // Fall through to exception
                }
            }
        }

        // For other DID methods, would need DID resolution
        // For now, delegate to signing service which may have registered keys
        try
        {
            var verificationMethod = await _signingService.GetVerificationMethodAsync(did);
            return await ResolvePublicKeyAsync(verificationMethod);
        }
        catch
        {
            throw new CapabilityValidationException($"Unable to resolve public key for DID: {did}");
        }
    }

    /// <summary>
    /// Builds the complete capability chain from leaf to root
    /// </summary>
    private async Task<List<Capability>> BuildCapabilityChainAsync(Capability capability)
    {
        var chain = new List<Capability>();
        var current = capability;

        while (current != null)
        {
            chain.Insert(0, current); // Add to beginning to build root->leaf order

            if (string.IsNullOrEmpty(current.ParentCapability))
            {
                // Reached root
                break;
            }

            // For delegated capabilities, the parent should be embedded in the proof's capabilityChain
            if (current.Proof?.CapabilityChain != null && current.Proof.CapabilityChain.Length > 0)
            {
                // Last element should be the parent capability object
                var lastElement = current.Proof.CapabilityChain[^1];

                if (lastElement is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Object)
                {
                    current = JsonSerializer.Deserialize<Capability>(jsonElement.GetRawText());
                }
                else if (lastElement is Capability parentCap)
                {
                    current = parentCap;
                }
                else
                {
                    throw new CapabilityValidationException(
                        "Parent capability not properly embedded in capability chain");
                }
            }
            else
            {
                throw new CapabilityValidationException(
                    "Delegated capability missing capabilityChain in proof");
            }
        }

        return chain;
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
    /// Per spec: suffix MUST start with '/' or '?' if no '?', or '&' if '?' present
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
}
