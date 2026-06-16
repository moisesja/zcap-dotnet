using System.Net;
using FluentAssertions;
using Xunit;
using ZcapLd.AspNetCore.Services;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// Regression tests for the ValidWhileTrue SSRF guard (the caveat URI is attacker-controlled).
/// </summary>
public class SsrfGuardTests
{
    [Theory]
    [InlineData("169.254.169.254")] // cloud instance metadata (the headline target)
    [InlineData("127.0.0.1")]       // loopback
    [InlineData("0.0.0.0")]         // unspecified
    [InlineData("10.1.2.3")]        // RFC1918
    [InlineData("172.16.0.1")]      // RFC1918
    [InlineData("172.31.255.255")]  // RFC1918 upper edge
    [InlineData("192.168.1.1")]     // RFC1918
    [InlineData("100.64.0.1")]      // CGNAT
    [InlineData("::1")]             // IPv6 loopback
    [InlineData("fe80::1")]         // IPv6 link-local
    [InlineData("fc00::1")]         // IPv6 unique-local
    [InlineData("fd12:3456::1")]    // IPv6 unique-local
    [InlineData("::ffff:169.254.169.254")] // IPv4-mapped metadata bypass attempt
    public void IsBlockedAddress_InternalRanges_AreBlocked(string ip)
    {
        SsrfGuard.IsBlockedAddress(IPAddress.Parse(ip)).Should().BeTrue();
    }

    [Theory]
    [InlineData("8.8.8.8")]      // public
    [InlineData("1.1.1.1")]      // public
    [InlineData("172.15.0.1")]   // just below RFC1918 172.16/12
    [InlineData("172.32.0.1")]   // just above RFC1918 172.16/12
    [InlineData("2606:4700:4700::1111")] // public IPv6 (Cloudflare)
    public void IsBlockedAddress_PublicAddresses_AreAllowed(string ip)
    {
        SsrfGuard.IsBlockedAddress(IPAddress.Parse(ip)).Should().BeFalse();
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")] // metadata theft
    [InlineData("http://127.0.0.1:8080/admin")]              // loopback admin
    [InlineData("https://10.0.0.5/internal")]                // RFC1918
    [InlineData("ftp://example.com/file")]                   // non-http(s) scheme
    [InlineData("file:///etc/passwd")]                       // file scheme
    [InlineData("not-a-uri")]                                // unparseable
    [InlineData("/relative/path")]                           // not absolute
    public async Task ValidateRequestUri_BlockedOrMalformed_ReturnsFalse(string uri)
    {
        (await SsrfGuard.ValidateRequestUri(uri, CancellationToken.None)).Should().BeFalse();
    }

    [Theory]
    [InlineData("http://8.8.8.8/status")]
    [InlineData("https://1.1.1.1/revocations/abc")]
    public async Task ValidateRequestUri_PublicLiteralHosts_ReturnsTrue(string uri)
    {
        (await SsrfGuard.ValidateRequestUri(uri, CancellationToken.None)).Should().BeTrue();
    }
}
