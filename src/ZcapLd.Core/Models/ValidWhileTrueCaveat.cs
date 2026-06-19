using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Caveat that requires a remote URI to confirm the capability is still valid.
/// Per W3C ZCAP-LD spec: capability is valid while the URI returns a non-revoked status.
///
/// SECURITY: <see cref="IsSatisfied"/> returns false (fail-closed) because evaluation
/// requires an async HTTP check handled by <see cref="Services.CaveatProcessor"/> via
/// <see cref="Services.IValidWhileTrueHandler"/>. Without a handler configured, this
/// caveat always denies access.
///
/// CROSS-STACK: <c>@digitalbazaar/zcap</c> has no generic caveat engine, so a capability whose
/// security depends on this caveat verifies there with the caveat <b>silently un-enforced</b>. For
/// cross-stack security guarantees, rely only on <c>expires</c>/<c>allowedAction</c>/<c>invocationTarget</c>.
/// </summary>
public class ValidWhileTrueCaveat : Caveat
{
    // [JsonPropertyName] explicitly re-declared on the override — STJ on .NET 10
    // doesn't auto-inherit from the abstract base, so without this the wire body
    // carries duplicate `Type`/`type` keys. See #45.
    [JsonPropertyName("type")]
    public override string Type => "ValidWhileTrue";

    /// <summary>
    /// The URI to check for continued validity.
    /// Typically a revocation status endpoint hosted by the delegator/controller.
    /// </summary>
    [JsonPropertyName("uri")]
    public string Uri { get; set; } = string.Empty;

    /// <summary>
    /// Always returns false (fail-closed).
    /// Actual evaluation is async and handled by <see cref="Services.CaveatProcessor"/>
    /// when an <see cref="Services.IValidWhileTrueHandler"/> is configured.
    /// </summary>
    public override bool IsSatisfied(InvocationContext context) => false;
}
