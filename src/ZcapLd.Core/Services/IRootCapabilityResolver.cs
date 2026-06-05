using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Resolves a root capability from its identifier so the verifier can validate spec-exact
/// delegation chains.
/// </summary>
/// <remarks>
/// <para>
/// W3C ZCAP-LD requires the root zcap to appear in a delegation proof's <c>capabilityChain</c>
/// <b>by reference only</b> (its id string) and never embedded. A first-level delegation therefore
/// carries a chain of exactly <c>[rootId]</c>. To verify that delegation the verifier still needs the
/// root capability itself — its <c>controller</c> authorizes the first delegation — but the root id
/// (<c>urn:zcap:root:{encodeURIComponent(invocationTarget)}</c>) encodes only the invocation target,
/// not the controller, so the root cannot be reconstructed from its id alone. Implement this interface
/// to supply it (the relying party / resource owner inherently knows its own root zcaps).
/// </para>
/// <para>
/// This mirrors the reference implementation's <c>getRootCapability</c> hook. It is consulted only
/// when a verify/revoke call is made <i>without</i> an explicitly supplied root capability; an explicit
/// root always takes precedence. When neither is available the verifier fails closed.
/// </para>
/// <para>
/// <b>Performance:</b> resolution happens while the verifier builds the chain — before the leaf's
/// signature is checked — so an attacker-supplied (and ultimately rejected) chain can still trigger a
/// lookup. Keep <see cref="ResolveRootAsync"/> cheap; an I/O- or database-backed implementation should
/// cache, since a process's set of roots is small and changes rarely.
/// </para>
/// </remarks>
public interface IRootCapabilityResolver
{
    /// <summary>
    /// Resolves the root capability identified by <paramref name="rootCapabilityId"/>, or
    /// <see langword="null"/> if it is unknown. The verifier binds the result to the chain by
    /// requiring the returned capability's <c>id</c> to equal <paramref name="rootCapabilityId"/>,
    /// so a resolver must not return an unrelated capability.
    /// </summary>
    /// <param name="rootCapabilityId">The root capability id referenced by the delegation chain
    /// (e.g. <c>urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo</c>).</param>
    /// <returns>The resolved root capability, or <see langword="null"/> when unknown.</returns>
    Task<Capability?> ResolveRootAsync(string rootCapabilityId);
}
