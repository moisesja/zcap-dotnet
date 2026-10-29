using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// The authority a revocation record is bound to (#158). A capability id alone does not identify a
/// capability: a delegated id is chosen by whoever signs the delegation, so a record keyed by the bare
/// id could be written by anyone holding a chain under any trusted root and would revoke every
/// capability carrying that id, across roots and across verifiers sharing a store. A record is
/// therefore keyed by the id <i>and</i> a scope, and a chain link is revoked only by a record in its
/// own scope or by an <see cref="Unscoped"/> one:
/// <list type="bullet">
/// <item><see cref="Delegated(string)"/>: a delegated capability, scoped to its <b>delegator</b>, the
/// controller identifier of the verification method that signed the link's verified delegation proof
/// (the DID before <c>#</c>). This is what <c>@digitalbazaar/zcap</c> reports as <c>delegator</c> and
/// what <c>bedrock-zcap-storage</c> keys records by. Writing a record in this scope needs the
/// delegator's own key, and the delegator may already revoke what it delegated.</item>
/// <item><see cref="Root"/>: a root capability, resolved through the verifier's trust boundary (#155).</item>
/// <item><see cref="Unscoped"/>: matches the id on every link. Written only by 5.x stores (see the
/// migration note in the revocation guide) or by an operator through
/// <c>IRevocationService.RevokeAsync</c>; the signed revocation path never writes it.</item>
/// </list>
/// Stores key records by <see cref="KeyFor"/>, never by the bare id. The text form (<see cref="ToString"/>,
/// <see cref="Parse"/>, JSON) is <c>"unscoped"</c>, <c>"root"</c> or <c>"delegated:&lt;delegator&gt;"</c>.
/// </summary>
[JsonConverter(typeof(RevocationScopeJsonConverter))]
public sealed record RevocationScope
{
    private const string UnscopedText = "unscoped";
    private const string RootText = "root";
    private const string DelegatedPrefix = "delegated:";

    private RevocationScope(RevocationScopeKind kind, string? delegator)
    {
        Kind = kind;
        Delegator = delegator;
    }

    /// <summary>Which case this scope is.</summary>
    public RevocationScopeKind Kind { get; }

    /// <summary>The delegator for <see cref="RevocationScopeKind.Delegated"/>; otherwise null.</summary>
    public string? Delegator { get; }

    /// <summary>The scope of a root capability's record.</summary>
    public static RevocationScope Root { get; } = new(RevocationScopeKind.Root, null);

    /// <summary>A record that applies to its capability id on every link (legacy and operator records).</summary>
    public static RevocationScope Unscoped { get; } = new(RevocationScopeKind.Unscoped, null);

    /// <summary>
    /// The scope of a delegated capability's record. <paramref name="delegator"/> is the controller
    /// identifier (bare DID or other absolute IRI, without a <c>#fragment</c>) of the verification method
    /// that signed the capability's delegation proof; see <see cref="ForDelegationProof"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The delegator is empty, carries a fragment or is not an absolute IRI.</exception>
    public static RevocationScope Delegated(string delegator)
    {
        if (string.IsNullOrWhiteSpace(delegator))
            throw new ArgumentException("A delegator is required.", nameof(delegator));
        if (delegator.Contains('#'))
            throw new ArgumentException(
                "A delegator is a controller identifier, not a verification method: drop the #fragment.", nameof(delegator));
        if (!CanonicalIri.IsBindable(delegator))
            throw new ArgumentException("A delegator must be an absolute IRI.", nameof(delegator));
        return new RevocationScope(RevocationScopeKind.Delegated, delegator);
    }

    /// <summary>
    /// The scope a link verified with <paramref name="delegationProof"/> is looked up and revoked in:
    /// <see cref="Delegated(string)"/> with the proof's <c>verificationMethod</c> before its <c>#</c>.
    /// </summary>
    public static RevocationScope ForDelegationProof(Proof delegationProof)
    {
        ArgumentNullException.ThrowIfNull(delegationProof);
        if (string.IsNullOrWhiteSpace(delegationProof.VerificationMethod))
            throw new ArgumentException("The delegation proof has no verificationMethod.", nameof(delegationProof));
        return Delegated(DelegatorOf(delegationProof.VerificationMethod));
    }

    /// <summary>
    /// <see cref="ForDelegationProof"/> without throwing: false when the proof has no usable
    /// verification method, in which case it cannot verify either.
    /// </summary>
    internal static bool TryForDelegationProof(Proof? delegationProof, [NotNullWhen(true)] out RevocationScope? scope)
    {
        scope = null;
        if (delegationProof is null || string.IsNullOrWhiteSpace(delegationProof.VerificationMethod))
            return false;
        var delegator = DelegatorOf(delegationProof.VerificationMethod);
        if (!IsDelegator(delegator))
            return false;
        scope = new RevocationScope(RevocationScopeKind.Delegated, delegator);
        return true;
    }

    private static bool IsDelegator(string? delegator)
        => !string.IsNullOrWhiteSpace(delegator) && !delegator.Contains('#') && CanonicalIri.IsBindable(delegator);

    /// <summary>The controller identifier of a verification method: everything before its <c>#</c>.</summary>
    internal static string DelegatorOf(string verificationMethod)
    {
        var fragment = verificationMethod.IndexOf('#');
        return fragment < 0 ? verificationMethod : verificationMethod[..fragment];
    }

    /// <summary>
    /// The store key of this scope's record for <paramref name="capabilityId"/>: the lowercase hex
    /// SHA-256 of the RFC 8785 form of <c>{"capabilityId": id, "scope": text}</c>. It is opaque and
    /// fixed width, so no bare id is ever a key and a case-insensitive collation cannot merge records.
    /// </summary>
    public string KeyFor(string capabilityId)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
            throw new ArgumentException("A capability id is required.", nameof(capabilityId));
        var subject = new JsonObject { ["capabilityId"] = capabilityId, ["scope"] = ToString() };
        return Convert.ToHexStringLower(SHA256.HashData(NetCid.JcsCanonicalizer.Canonicalize(subject)));
    }

    /// <summary>Parses the text form; see <see cref="TryParse"/>.</summary>
    /// <exception cref="FormatException">The text is not a scope.</exception>
    public static RevocationScope Parse(string text)
        => TryParse(text, out var scope)
            ? scope
            : throw new FormatException(
                $"'{text}' is not a revocation scope; expected \"{UnscopedText}\", \"{RootText}\" or \"{DelegatedPrefix}<delegator>\".");

    /// <summary>Parses <c>"unscoped"</c>, <c>"root"</c> or <c>"delegated:&lt;delegator&gt;"</c>.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out RevocationScope? scope)
    {
        scope = null;
        switch (text)
        {
            case UnscopedText:
                scope = Unscoped;
                return true;
            case RootText:
                scope = Root;
                return true;
            case { } when text.StartsWith(DelegatedPrefix, StringComparison.Ordinal):
                var delegator = text[DelegatedPrefix.Length..];
                if (!IsDelegator(delegator))
                    return false;
                scope = new RevocationScope(RevocationScopeKind.Delegated, delegator);
                return true;
            default:
                return false;
        }
    }

    /// <inheritdoc />
    public override string ToString() => Kind switch
    {
        RevocationScopeKind.Root => RootText,
        RevocationScopeKind.Delegated => DelegatedPrefix + Delegator,
        _ => UnscopedText,
    };
}

/// <summary>The cases of <see cref="RevocationScope"/>.</summary>
public enum RevocationScopeKind
{
    /// <summary>Applies to the capability id on every link.</summary>
    Unscoped,

    /// <summary>A root capability.</summary>
    Root,

    /// <summary>A delegated capability, bound to the delegator that signed it.</summary>
    Delegated,
}

/// <summary>One revocation query: a capability id in the scope its link is verified under.</summary>
public readonly record struct RevocationLookup(string CapabilityId, RevocationScope Scope);

/// <summary>Serializes a <see cref="RevocationScope"/> as its text form.</summary>
internal sealed class RevocationScopeJsonConverter : JsonConverter<RevocationScope>
{
    public override RevocationScope Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException("A revocation scope must be a string.");
        return RevocationScope.TryParse(reader.GetString(), out var scope)
            ? scope
            : throw new JsonException("The revocation scope is not \"unscoped\", \"root\" or \"delegated:<delegator>\".");
    }

    public override void Write(Utf8JsonWriter writer, RevocationScope value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString());
}
