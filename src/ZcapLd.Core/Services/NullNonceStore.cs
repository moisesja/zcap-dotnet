namespace ZcapLd.Core.Services;

/// <summary>
/// No-op nonce store that never flags replays. Used as the default
/// to preserve backward compatibility when replay protection is not configured.
/// </summary>
internal sealed class NullNonceStore : INonceStore
{
    public static readonly NullNonceStore Instance = new();

    public Task<bool> TryMarkAsUsedAsync(string nonce, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
        => Task.FromResult(false);
}
