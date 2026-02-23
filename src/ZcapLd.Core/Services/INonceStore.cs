namespace ZcapLd.Core.Services;

/// <summary>
/// Pluggable persistence abstraction for invocation nonce tracking (replay protection).
/// Implementations MUST be thread-safe.
/// </summary>
public interface INonceStore
{
    /// <summary>
    /// Atomically checks whether a nonce has been used and records it if not.
    /// Returns <c>true</c> if the nonce was already used (replay detected).
    /// Returns <c>false</c> if the nonce was fresh and has now been recorded.
    /// If <paramref name="expiresAt"/> is provided, the record MAY be evicted after that time.
    /// </summary>
    Task<bool> TryMarkAsUsedAsync(string nonce, DateTime? expiresAt = null, CancellationToken cancellationToken = default);
}
