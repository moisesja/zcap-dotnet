using System.Security.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Builds deterministic signing payloads for capabilities and invocations.
/// Proof metadata (excluding proofValue) is included so metadata tampering
/// invalidates signatures.
///
/// Supports two canonicalization strategies:
/// - JCS: combines document + proof into single anonymous object, canonicalizes once (default)
/// - RDFC-1.0: canonicalizes document and proof options separately, hashes each with SHA-256,
///   then concatenates the hashes (per W3C Data Integrity spec)
/// </summary>
internal static class ProofSigningPayloadBuilder
{
    private static readonly JcsDocumentCanonicalizer DefaultJcs = new();

    public static Capability CloneCapabilityWithoutProof(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);

        return new Capability
        {
            Context = capability.Context,
            Id = capability.Id,
            ParentCapability = capability.ParentCapability,
            Controller = capability.Controller,
            InvocationTarget = capability.InvocationTarget,
            Expires = capability.Expires,
            AllowedAction = capability.AllowedAction,
            Caveat = capability.Caveat,
            Proof = null
        };
    }

    public static Invocation CloneInvocationWithoutProof(Invocation invocation)
    {
        ArgumentNullException.ThrowIfNull(invocation);

        return new Invocation
        {
            Id = invocation.Id,
            Capability = invocation.Capability,
            CapabilityAction = invocation.CapabilityAction,
            InvocationTarget = invocation.InvocationTarget,
            Proof = null
        };
    }

    public static byte[] CanonicalizeCapabilityPayload(
        Capability capabilityWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(capabilityWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeCapabilityRdfc(capabilityWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeCapabilityJcs(capabilityWithoutProof, proof, canonicalizer);
    }

    public static byte[] CanonicalizeInvocationPayload(
        Invocation invocationWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(invocationWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeInvocationRdfc(invocationWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeInvocationJcs(invocationWithoutProof, proof, canonicalizer);
    }

    // ─── JCS path (current behavior) ───────────────────────────────────

    private static byte[] CanonicalizeCapabilityJcs(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var payload = new
        {
            capability = capabilityWithoutProof,
            proof = new
            {
                type = proof.Type,
                created = proof.Created,
                proofPurpose = proof.ProofPurpose,
                verificationMethod = proof.VerificationMethod,
                capabilityChain = proof.CapabilityChain
            }
        };

        return canonicalizer.Canonicalize(payload);
    }

    private static byte[] CanonicalizeInvocationJcs(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var payload = new
        {
            invocation = new
            {
                id = invocationWithoutProof.Id,
                capability = invocationWithoutProof.Capability,
                capabilityAction = invocationWithoutProof.CapabilityAction,
                invocationTarget = invocationWithoutProof.InvocationTarget
            },
            proof = new
            {
                type = proof.Type,
                created = proof.Created,
                proofPurpose = proof.ProofPurpose,
                verificationMethod = proof.VerificationMethod,
                capability = proof.Capability,
                capabilityAction = proof.CapabilityAction,
                invocationTarget = proof.InvocationTarget,
                capabilityChain = proof.CapabilityChain
            }
        };

        return canonicalizer.Canonicalize(payload);
    }

    // ─── RDFC-1.0 path (W3C Data Integrity spec) ──────────────────────
    // Per spec: canonicalize document and proof options separately,
    // SHA-256 hash each, concatenate hashes → signing input.

    private static byte[] CanonicalizeCapabilityRdfc(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Proof options document — needs @context from the capability for JSON-LD processing
        var proofOptions = new Dictionary<string, object?>
        {
            ["@context"] = capabilityWithoutProof.Context,
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["proofPurpose"] = proof.ProofPurpose,
            ["verificationMethod"] = proof.VerificationMethod,
            ["capabilityChain"] = proof.CapabilityChain
        };

        return ConcatenateHashes(
            canonicalizer.Canonicalize(capabilityWithoutProof),
            canonicalizer.Canonicalize(proofOptions));
    }

    private static byte[] CanonicalizeInvocationRdfc(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Invocation document — add @context for JSON-LD processing
        var invocationDoc = new Dictionary<string, object?>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["id"] = invocationWithoutProof.Id,
            ["capability"] = invocationWithoutProof.Capability,
            ["capabilityAction"] = invocationWithoutProof.CapabilityAction,
            ["invocationTarget"] = invocationWithoutProof.InvocationTarget
        };

        var proofOptions = new Dictionary<string, object?>
        {
            ["@context"] = "https://w3id.org/zcap/v1",
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["proofPurpose"] = proof.ProofPurpose,
            ["verificationMethod"] = proof.VerificationMethod,
            ["capability"] = proof.Capability,
            ["capabilityAction"] = proof.CapabilityAction,
            ["invocationTarget"] = proof.InvocationTarget,
            ["capabilityChain"] = proof.CapabilityChain
        };

        return ConcatenateHashes(
            canonicalizer.Canonicalize(invocationDoc),
            canonicalizer.Canonicalize(proofOptions));
    }

    /// <summary>
    /// Per W3C Data Integrity: SHA-256(proofOptionsCanonical) || SHA-256(documentCanonical).
    /// </summary>
    private static byte[] ConcatenateHashes(byte[] documentCanonical, byte[] proofOptionsCanonical)
    {
        var proofHash = SHA256.HashData(proofOptionsCanonical);
        var docHash = SHA256.HashData(documentCanonical);

        var result = new byte[proofHash.Length + docHash.Length];
        proofHash.CopyTo(result, 0);
        docHash.CopyTo(result, proofHash.Length);
        return result;
    }
}
