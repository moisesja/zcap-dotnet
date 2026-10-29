using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// Base class for a custom, signed restriction carried in a delegated capability's <c>caveat</c>
/// array (#157). Derive one class per caveat type, expose its parameters as JSON-serializable
/// properties (mark mandatory ones <c>required</c>), and register it with
/// <see cref="CaveatTypeRegistry.Register{TCaveat}(string)"/>.
/// <para>
/// A caveat is data plus two rules: <see cref="Validate"/> (well-formed values) and
/// <see cref="IsAttenuationOf"/> (a child may only narrow its parent). It never decides whether an
/// invocation is allowed: that authority belongs to the resource's
/// <see cref="Services.ICaveatHandler"/>, which the verifier requires for every caveat type it meets.
/// </para>
/// </summary>
/// <remarks>
/// Every parameter is signed: the registry generates a pinned JSON-LD context that defines the
/// type and each declared parameter as a JSON literal, and the verifier rejects any parameter the
/// class does not declare. Caveats are an application-specific extension profile: they are not part
/// of ZCAP-LD v0.4 and other ZCAP implementations will reject capabilities that carry them.
/// </remarks>
public abstract class Caveat
{
    /// <summary>
    /// The caveat type, as registered (for example <c>"EpsilonBudget"</c>). Written to the wire as
    /// <c>type</c> by the library; it is not a serialized parameter.
    /// </summary>
    [JsonIgnore]
    public abstract string Type { get; }

    /// <summary>
    /// Checks that the parameter values are well formed (for example a positive, bounded budget).
    /// Throw <see cref="Exceptions.CapabilityValidationException"/> or <see cref="ArgumentException"/>
    /// to reject the caveat. Called before signing and whenever a caveat is read for verification.
    /// </summary>
    public virtual void Validate()
    {
    }

    /// <summary>
    /// Returns <see langword="true"/> when this caveat, carried by a child capability, grants no more
    /// than <paramref name="parent"/>, the same-type caveat of its parent. Must be reflexive and
    /// transitive. The default requires the child to restate the parent's parameters exactly; override
    /// it to allow narrowing (for example a smaller budget).
    /// </summary>
    /// <param name="parent">The parent's caveat of the same type.</param>
    public virtual bool IsAttenuationOf(Caveat parent)
    {
        ArgumentNullException.ThrowIfNull(parent);
        return CaveatCodec.ParametersEqual(this, parent);
    }
}

/// <summary>Reads the custom caveats a capability carries (#157).</summary>
public static class CapabilityCaveatExtensions
{
    /// <summary>
    /// Returns the capability's caveats, validated against <paramref name="caveats"/>, in wire order.
    /// This checks only the caveats' form; it does not verify the capability's signature or chain.
    /// </summary>
    /// <exception cref="Exceptions.CapabilityValidationException">A caveat is unregistered or invalid.</exception>
    public static IReadOnlyList<Caveat> GetCaveats(this Capability capability, CaveatTypeRegistry caveats)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(caveats);
        if (CaveatCodec.TryRead(capability, caveats, materialize: true, out var entries) is { } failure)
            throw new Exceptions.CapabilityValidationException(failure.Message ?? "The capability's caveats are invalid.");
        return entries.Select(entry => entry.Value!).ToArray();
    }
}
