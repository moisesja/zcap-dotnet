using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Builds deterministic signing payloads for capabilities and invocations.
/// Proof metadata (excluding proofValue) is included so metadata tampering
/// invalidates signatures.
/// </summary>
internal static class ProofSigningPayloadBuilder
{
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

    public static byte[] CanonicalizeCapabilityPayload(Capability capabilityWithoutProof, Proof proof)
    {
        ArgumentNullException.ThrowIfNull(capabilityWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

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

        return MultibaseCodec.CanonicalizeDocument(payload);
    }

    public static byte[] CanonicalizeInvocationPayload(Invocation invocationWithoutProof, Proof proof)
    {
        ArgumentNullException.ThrowIfNull(invocationWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

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

        return MultibaseCodec.CanonicalizeDocument(payload);
    }
}
