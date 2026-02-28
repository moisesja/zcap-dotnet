namespace ZcapLd.Core.Services;

/// <summary>
/// Handler for evaluating ValidWhileTrue caveats asynchronously.
/// Implementors check a remote URI to determine if a capability is still valid.
///
/// The default behavior when no handler is registered is fail-closed
/// (ValidWhileTrueCaveat.IsSatisfied returns false).
/// </summary>
public interface IValidWhileTrueHandler
{
    /// <summary>
    /// Checks whether the capability referenced by the given URI is still valid.
    /// </summary>
    /// <param name="uri">The caveat URI to check (typically a revocation status endpoint)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the capability is still valid (not revoked); false otherwise</returns>
    Task<bool> CheckAsync(string uri, CancellationToken cancellationToken = default);
}
