using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Implementation of cryptographic signing operations for ZCAP-LD
/// </summary>
public class SigningService : ISigningService
{
    private readonly Dictionary<string, byte[]> _keyStore = new();

    /// <summary>
    /// Registers a signing key for a DID
    /// </summary>
    /// <param name="did">The DID to register the key for</param>
    /// <param name="privateKey">The Ed25519 private key (32 bytes)</param>
    public void RegisterKey(string did, byte[] privateKey)
    {
        if (string.IsNullOrEmpty(did))
        {
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        }

        if (privateKey == null || privateKey.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes for Ed25519", nameof(privateKey));
        }

        _keyStore[did] = privateKey;
    }

    /// <summary>
    /// Signs a capability with the specified signing key
    /// </summary>
    public async Task<Proof> SignCapabilityAsync(
        Capability capability,
        string signerDid,
        string proofPurpose,
        object[]? capabilityChain = null)
    {
        if (capability == null)
        {
            throw new ArgumentNullException(nameof(capability));
        }

        if (string.IsNullOrEmpty(signerDid))
        {
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));
        }

        if (!_keyStore.TryGetValue(signerDid, out var privateKey))
        {
            throw new InvalidOperationException($"No private key registered for DID: {signerDid}");
        }

        // Create a copy of the capability without the proof
        var capabilityWithoutProof = new Capability
        {
            Context = capability.Context,
            Id = capability.Id,
            Controller = capability.Controller,
            InvocationTarget = capability.InvocationTarget,
            AllowedAction = capability.AllowedAction,
            Expires = capability.Expires,
            ParentCapability = capability.ParentCapability,
            Caveat = capability.Caveat,
            Proof = null // Explicitly null for signing
        };

        // Canonicalize and sign
        var canonicalBytes = Ed25519Signer.CanonicalizeDocument(capabilityWithoutProof);
        var signatureBytes = Ed25519Signer.Sign(canonicalBytes, privateKey);
        var proofValue = Ed25519Signer.EncodeSignature(signatureBytes);

        // Get verification method
        var verificationMethod = await GetVerificationMethodAsync(signerDid);

        // Create the proof
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = DateTime.UtcNow,
            ProofPurpose = proofPurpose,
            VerificationMethod = verificationMethod,
            CapabilityChain = capabilityChain ?? Array.Empty<object>(),
            ProofValue = proofValue
        };

        return await Task.FromResult(proof);
    }

    /// <summary>
    /// Signs an invocation request
    /// </summary>
    public async Task<Proof> SignInvocationAsync(Invocation invocation, string signerDid)
    {
        if (invocation == null)
        {
            throw new ArgumentNullException(nameof(invocation));
        }

        if (string.IsNullOrEmpty(signerDid))
        {
            throw new ArgumentException("Signer DID cannot be null or empty", nameof(signerDid));
        }

        if (!_keyStore.TryGetValue(signerDid, out var privateKey))
        {
            throw new InvalidOperationException($"No private key registered for DID: {signerDid}");
        }

        // Create a copy of the invocation without the proof for signing
        var invocationWithoutProof = new
        {
            capability = invocation.Capability,
            capabilityAction = invocation.CapabilityAction,
            invocationTarget = invocation.InvocationTarget
        };

        // Canonicalize and sign
        var canonicalBytes = Ed25519Signer.CanonicalizeDocument(invocationWithoutProof);
        var signatureBytes = Ed25519Signer.Sign(canonicalBytes, privateKey);
        var proofValue = Ed25519Signer.EncodeSignature(signatureBytes);

        // Get verification method
        var verificationMethod = await GetVerificationMethodAsync(signerDid);

        // Create the invocation proof
        var proof = new Proof
        {
            Type = "Ed25519Signature2020",
            Created = DateTime.UtcNow,
            ProofPurpose = "capabilityInvocation",
            VerificationMethod = verificationMethod,
            CapabilityChain = Array.Empty<object>(), // Invocation proofs don't have chains
            ProofValue = proofValue
        };

        return await Task.FromResult(proof);
    }

    /// <summary>
    /// Gets the verification method URI for a DID
    /// In a real implementation, this would resolve the DID document
    /// For now, we return the DID with a key fragment
    /// </summary>
    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
        {
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        }

        // For did:key, the verification method is typically the DID itself with a fragment
        // Format: did:key:{multibase-encoded-public-key}#{multibase-encoded-public-key}
        if (did.StartsWith("did:key:"))
        {
            // Extract the key identifier from the DID
            var keyId = did.Substring("did:key:".Length);
            return Task.FromResult($"{did}#{keyId}");
        }

        // For other DID methods, return with a standard key fragment
        return Task.FromResult($"{did}#key-1");
    }

    /// <summary>
    /// Builds the capability chain for a delegation proof
    /// According to spec:
    /// - First element: root capability ID (string)
    /// - Middle elements: intermediate capability IDs (strings)
    /// - Last element: immediate parent capability (full object)
    /// </summary>
    public static object[] BuildCapabilityChain(Capability parentCapability, Capability? grandparentCapability = null)
    {
        var chain = new List<object>();

        // If parent has a chain, it's a delegated capability
        if (parentCapability.Proof?.CapabilityChain != null && parentCapability.Proof.CapabilityChain.Length > 0)
        {
            // Copy the parent's chain (which includes root and intermediates)
            chain.AddRange(parentCapability.Proof.CapabilityChain);

            // Add parent's ID to the chain (it becomes an intermediate)
            chain.Add(parentCapability.Id);
        }
        else
        {
            // Parent is a root capability, so just add its ID
            chain.Add(parentCapability.Id);
        }

        return chain.ToArray();
    }

    /// <summary>
    /// Generates a new Ed25519 key pair and registers it for a DID
    /// </summary>
    /// <param name="did">The DID to register the key pair for</param>
    /// <returns>Tuple of (privateKey, publicKey)</returns>
    public (byte[] PrivateKey, byte[] PublicKey) GenerateAndRegisterKeyPair(string did)
    {
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        RegisterKey(did, privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Gets the public key for a registered DID
    /// </summary>
    public byte[] GetPublicKey(string did)
    {
        if (!_keyStore.TryGetValue(did, out var privateKey))
        {
            throw new InvalidOperationException($"No private key registered for DID: {did}");
        }

        return Ed25519Signer.GetPublicKey(privateKey);
    }
}
