using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.AspNetCore.Contracts;

/// <summary>
/// HTTP request payload for a <b>signed</b> revocation (proof-of-possession). The caller presents
/// the full <see cref="Capability"/> being revoked (the verifier needs its embedded delegation
/// chain to authorize) together with a signed revocation request produced by
/// <c>ISigningService.SignRevocationAsync</c>. There is no unauthenticated bare-DID alternative.
/// </summary>
public sealed class SignedRevocationHttpRequest
{
    /// <summary>
    /// The capability to revoke, with its full delegation chain (used for authorization).
    /// </summary>
    [JsonPropertyName("capability")]
    public Capability? Capability { get; set; }

    /// <summary>
    /// The signed revocation request (a <c>capabilityRevocation</c>-purpose, <c>revoke</c>-action
    /// invocation). Its signature authenticates the revoker; any signed reason/metadata is recorded.
    /// </summary>
    [JsonPropertyName("signedRevocation")]
    public Invocation? SignedRevocation { get; set; }
}
