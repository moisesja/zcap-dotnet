using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// The capability an <see cref="Invocation"/> (and its invocation <see cref="Proof"/>) references.
///
/// Per W3C ZCAP-LD v0.3 the <c>capability</c> field of a capability-invocation Data Integrity proof
/// takes one of two spec-defined shapes:
/// <list type="bullet">
/// <item><b>Root invocation</b> — <i>Invoking a Root ZCAP</i>: <c>capability</c> is the root zcap
/// <b>id string</b> (<c>urn:zcap:root:…</c>). The verifier dereferences the root locally by id.</item>
/// <item><b>Delegated invocation</b> — <i>Invoking a Delegated ZCAP</i>: "When invoking using a DI
/// proof, the <c>capability</c> property must express the <b>full delegated zcap</b>." The whole
/// delegated <see cref="Capability"/> object (its <c>id</c>, <c>parentCapability</c>, <c>controller</c>,
/// <c>invocationTarget</c>, <c>expires</c>, <c>allowedAction</c>/caveats, and its delegation
/// <c>proof</c> with <c>capabilityChain</c>) is embedded, so the verifier has the full authority
/// chain without dereferencing the delegated zcap by id (Issue #51).</item>
/// </list>
///
/// This immutable value type models both shapes behind one API and, like <see cref="ProofSet"/> and
/// <see cref="ControllerSet"/>, preserves the on-wire shape it was created from: a root reference
/// round-trips as a JSON string, a delegated capability round-trips as the embedded JSON object. The
/// <see cref="InvocationCapabilityJsonConverter"/> (carried by the <see cref="JsonConverterAttribute"/>
/// on this type) reads/writes both; the implicit conversion from <see cref="string"/> keeps root
/// invocation call sites ergonomic (<c>invocation.Capability = rootId;</c>).
/// </summary>
[JsonConverter(typeof(InvocationCapabilityJsonConverter))]
public sealed class InvocationCapability
{
    private InvocationCapability(string? id, Capability? embeddedCapability)
    {
        Id = id;
        EmbeddedCapability = embeddedCapability;
    }

    /// <summary>
    /// The root capability id, when this is a root reference (string wire form); <see langword="null"/>
    /// for a delegated invocation (use <see cref="CapabilityId"/> for the id regardless of shape).
    /// </summary>
    public string? Id { get; }

    /// <summary>
    /// The full embedded delegated zcap, when this is a delegated invocation (object wire form);
    /// <see langword="null"/> for a root reference.
    /// </summary>
    public Capability? EmbeddedCapability { get; }

    /// <summary>
    /// True when this is a bare root-id reference (string wire form), false when it carries an embedded
    /// delegated capability object. Tracks the spec-defined shape so verification can require the
    /// correct one: a root id string for a root invocation, the full object for a delegated invocation.
    /// </summary>
    public bool IsRootReference => EmbeddedCapability is null;

    /// <summary>
    /// The referenced capability's id regardless of wire shape — the embedded capability's <c>id</c>
    /// for a delegated invocation, otherwise the root-id string.
    /// </summary>
    public string CapabilityId => EmbeddedCapability?.Id ?? Id ?? string.Empty;

    /// <summary>
    /// Builds a root reference that serializes as the bare id string. Used for root invocations and
    /// for revocation requests (which reference the target capability by id).
    /// </summary>
    public static InvocationCapability FromId(string id)
    {
        ArgumentNullException.ThrowIfNull(id);
        return new InvocationCapability(id, embeddedCapability: null);
    }

    /// <summary>
    /// Builds a delegated invocation reference that embeds the full delegated zcap object. The
    /// capability MUST carry an <c>id</c> so the verifier can bind the embedded object to the
    /// capability being invoked.
    /// </summary>
    public static InvocationCapability FromCapability(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);
        if (string.IsNullOrEmpty(capability.Id))
        {
            throw new ArgumentException("Embedded delegated capability MUST have an id.", nameof(capability));
        }

        return new InvocationCapability(id: null, capability);
    }

    /// <summary>
    /// Implicit conversion from a root-id string. Keeps root invocation and revocation call sites
    /// ergonomic and source-compatible with the prior <c>string Capability</c> property
    /// (<c>invocation.Capability = capability.Id;</c>).
    /// </summary>
    public static implicit operator InvocationCapability(string id) => FromId(id);
}
