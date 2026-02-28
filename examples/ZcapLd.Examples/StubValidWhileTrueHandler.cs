using ZcapLd.Core.Services;

namespace ZcapLd.Examples;

/// <summary>
/// Stub handler for demonstration purposes.
/// In production, use <c>AddZcapValidWhileTrueSupport()</c> from the
/// ZcapLd.AspNetCore package, which registers <c>HttpValidWhileTrueHandler</c>
/// to make real HTTP calls to the revocation status endpoint.
/// </summary>
public class StubValidWhileTrueHandler : IValidWhileTrueHandler
{
    private readonly bool _isActive;

    public StubValidWhileTrueHandler(bool isActive) => _isActive = isActive;

    public Task<bool> CheckAsync(string uri, CancellationToken cancellationToken = default)
    {
        // In production, HttpValidWhileTrueHandler GETs the URI and checks
        // the RevocationStatusHttpResponse.IsRevoked field.
        Console.WriteLine($"    [Stub handler] Checking {uri} -> active={_isActive}");
        return Task.FromResult(_isActive);
    }
}
