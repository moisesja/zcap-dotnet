using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// The set of Data Integrity proofs attached to a delegated capability.
///
/// Per W3C ZCAP-LD v0.3, a delegated zcap's <c>proof</c> field MAY be a single DI proof
/// object <b>or</b> an array of proof objects, and at least one of them MUST be a
/// <c>capabilityDelegation</c> proof. This immutable value type models both shapes behind
/// one API and, like <see cref="ControllerSet"/>, <b>preserves the on-wire shape</b> it was
/// created from: a single proof round-trips as a bare JSON object, an array round-trips as a
/// JSON array (even a single-element one).
///
/// Shape preservation matters for round-trip fidelity, but note the cryptographic signing
/// payload is unaffected by it: each proof is verified independently over the document with
/// <i>all</i> proofs removed plus that one proof's options (W3C Data Integrity proof sets),
/// so canonicalization always operates on a single <see cref="Proof"/>, never the set.
///
/// The <see cref="ProofSetJsonConverter"/> (carried by the <see cref="JsonConverterAttribute"/>
/// on this type) reads/writes both shapes; the implicit conversion from a single
/// <see cref="Proof"/> keeps signing call sites ergonomic (<c>capability.Proof = proof;</c>).
/// </summary>
[JsonConverter(typeof(ProofSetJsonConverter))]
public sealed class ProofSet
{
    private const string CapabilityDelegationPurpose = "capabilityDelegation";

    private readonly Proof[] _values;

    private ProofSet(Proof[] values, bool isArrayForm)
    {
        _values = values;
        IsArrayForm = isArrayForm;
    }

    /// <summary>The proofs, in declaration order.</summary>
    public IReadOnlyList<Proof> Values => _values;

    /// <summary>Number of proofs in the set.</summary>
    public int Count => _values.Length;

    /// <summary>
    /// True when this set serializes as a JSON array, false when it serializes as a single
    /// bare proof object. Tracks the original wire/construction shape so round-trips are stable.
    /// </summary>
    public bool IsArrayForm { get; }

    /// <summary>
    /// The first proof. Convenience for the common single-proof case (a capability produced
    /// by this library's signing APIs carries exactly one proof).
    /// </summary>
    public Proof Primary => _values[0];

    /// <summary>Builds a single-proof set that serializes as a bare proof object.</summary>
    public static ProofSet FromSingle(Proof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        return new ProofSet(new[] { proof }, isArrayForm: false);
    }

    /// <summary>
    /// Builds a proof set from many proofs. Defaults to array wire form. Throws when the
    /// input is null, empty, or contains a null entry — a delegated zcap with an empty/absent
    /// proof set is invalid and must not silently produce a valid-looking capability.
    /// </summary>
    public static ProofSet FromValues(IEnumerable<Proof> proofs, bool asArray = true)
    {
        ArgumentNullException.ThrowIfNull(proofs);

        var array = proofs.ToArray();
        if (array.Length == 0)
        {
            throw new ArgumentException("Proof set must contain at least one proof.", nameof(proofs));
        }

        foreach (var proof in array)
        {
            if (proof is null)
            {
                throw new ArgumentException("Proof set entries must not be null.", nameof(proofs));
            }
        }

        return new ProofSet(array, isArrayForm: asArray);
    }

    /// <summary>All proofs whose <c>proofPurpose</c> is <c>capabilityDelegation</c>.</summary>
    public IEnumerable<Proof> DelegationProofs() =>
        _values.Where(p => string.Equals(p.ProofPurpose, CapabilityDelegationPurpose, StringComparison.Ordinal));

    /// <summary>The first <c>capabilityDelegation</c> proof, or null if none.</summary>
    public Proof? FirstDelegationProof() =>
        _values.FirstOrDefault(p => string.Equals(p.ProofPurpose, CapabilityDelegationPurpose, StringComparison.Ordinal));

    /// <summary>
    /// The first <c>capabilityDelegation</c> proof that carries a non-empty
    /// <see cref="Proof.CapabilityChain"/> — used to reconstruct the delegation chain.
    /// </summary>
    public Proof? FirstDelegationProofWithChain() =>
        _values.FirstOrDefault(p =>
            string.Equals(p.ProofPurpose, CapabilityDelegationPurpose, StringComparison.Ordinal) &&
            p.CapabilityChain is { Length: > 0 });

    /// <summary>
    /// Implicit conversion from a single proof (object wire form). Keeps signing call sites
    /// such as <c>capability.Proof = signedProof;</c> ergonomic.
    /// </summary>
    public static implicit operator ProofSet(Proof proof) => FromSingle(proof);

    /// <summary>
    /// Implicit conversion from a proof array (array wire form). Mirrors
    /// <see cref="ControllerSet"/>'s array conversion and keeps multi-proof call sites
    /// ergonomic (<c>capability.Proof = new[] { a, b };</c>). Delegates to
    /// <see cref="FromValues"/>, which throws on a null or empty array — a delegated zcap
    /// with no proofs is invalid and must not silently produce a valid-looking capability.
    /// </summary>
    public static implicit operator ProofSet(Proof[] proofs) => FromValues(proofs);
}
