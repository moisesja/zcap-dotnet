using System.Net;
using System.Net.Sockets;

namespace ZcapLd.AspNetCore.Services;

/// <summary>
/// Server-side request forgery (SSRF) guard for outbound caveat-status requests. The target URI of a
/// <see cref="Core.Models.ValidWhileTrueCaveat"/> is attacker-controlled (an invoker presents a
/// self-issued capability carrying any URI), so the verifier must not let it coerce a GET to internal
/// infrastructure (cloud instance metadata at 169.254.169.254, loopback admin ports, RFC1918/ULA
/// hosts, etc.).
/// <para>
/// Two layers: <see cref="ValidateRequestUri"/> is a cheap pre-flight (absolute http/https + resolved
/// address not in a blocked range) usable even when the <see cref="System.Net.Http.HttpClient"/> is
/// not configured with the connect-time guard; <see cref="SafeConnectAsync"/> is a
/// <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/> that re-resolves and refuses to
/// connect to a blocked address, closing the DNS-rebinding TOCTOU window the pre-flight alone leaves
/// open and the redirect-follow bypass (used together with <c>AllowAutoRedirect = false</c>).
/// </para>
/// </summary>
internal static class SsrfGuard
{
    /// <summary>
    /// Pre-flight validation: the URI must be absolute http/https and every address its host resolves
    /// to must be outside the blocked (loopback/link-local/private/CGNAT/unspecified) ranges. Resolution
    /// failure, an empty result, or any blocked address fails closed (returns false).
    /// </summary>
    public static async Task<bool> ValidateRequestUri(string uri, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            return false;
        if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
            return false;

        IPAddress[] addresses;
        try
        {
            addresses = IPAddress.TryParse(parsed.DnsSafeHost, out var literal)
                ? new[] { literal }
                : await Dns.GetHostAddressesAsync(parsed.DnsSafeHost, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return false; // cannot resolve → fail closed
        }

        return addresses.Length > 0 && !addresses.Any(IsBlockedAddress);
    }

    /// <summary>
    /// <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/>: resolves the target host and
    /// connects only to a non-blocked address, so even a host that passed the pre-flight but rebinds to
    /// an internal IP (or a followed redirect) cannot reach internal infrastructure.
    /// </summary>
    public static async ValueTask<Stream> SafeConnectAsync(
        System.Net.Http.SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var endpoint = context.DnsEndPoint;

        IPAddress[] addresses = IPAddress.TryParse(endpoint.Host, out var literal)
            ? new[] { literal }
            : await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken).ConfigureAwait(false);

        var allowed = addresses.Where(a => !IsBlockedAddress(a)).ToArray();
        if (allowed.Length == 0)
        {
            throw new System.Net.Http.HttpRequestException(
                $"Refusing to connect to '{endpoint.Host}': it resolves only to blocked (internal) addresses.");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(allowed, endpoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// True if <paramref name="address"/> falls in a range that must never be reachable from an
    /// attacker-supplied caveat URI: loopback, the unspecified address, IPv4 link-local
    /// (169.254.0.0/16, incl. cloud metadata), RFC1918 private, CGNAT (100.64.0.0/10), and the IPv6
    /// equivalents (link/site-local, unique-local fc00::/7). IPv4-mapped IPv6 is unwrapped first so a
    /// <c>::ffff:169.254.169.254</c>-style bypass is also caught.
    /// </summary>
    public static bool IsBlockedAddress(IPAddress address)
    {
        var addr = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (IPAddress.IsLoopback(addr))
            return true;
        if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any))
            return true;

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            return b[0] switch
            {
                0 => true,                                   // 0.0.0.0/8
                10 => true,                                  // 10.0.0.0/8
                127 => true,                                 // 127.0.0.0/8 (also covered by IsLoopback)
                169 when b[1] == 254 => true,                // 169.254.0.0/16 link-local + metadata
                172 when b[1] >= 16 && b[1] <= 31 => true,   // 172.16.0.0/12
                192 when b[1] == 168 => true,                // 192.168.0.0/16
                100 when b[1] >= 64 && b[1] <= 127 => true,  // 100.64.0.0/10 CGNAT
                _ => false
            };
        }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal)
                return true;
            var b = addr.GetAddressBytes();
            return (b[0] & 0xfe) == 0xfc; // fc00::/7 unique-local
        }

        return false;
    }
}
