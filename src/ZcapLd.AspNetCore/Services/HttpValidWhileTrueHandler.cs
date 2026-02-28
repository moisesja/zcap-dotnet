using System.Net.Http.Json;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.Services;

/// <summary>
/// HTTP-based handler for ValidWhileTrue caveats.
/// GETs the caveat URI and interprets the response using the
/// <see cref="RevocationStatusHttpResponse"/> contract (checks the isRevoked field).
///
/// If the URI returns isRevoked: false, the capability is still valid.
/// If the URI returns isRevoked: true, or the request fails, the capability
/// is invalid (fail-closed).
///
/// Uses a named <see cref="HttpClient"/> (<see cref="HttpClientName"/>) via
/// <see cref="IHttpClientFactory"/>, so consumers can configure timeouts,
/// retry policies, and other options.
/// </summary>
public sealed class HttpValidWhileTrueHandler : IValidWhileTrueHandler
{
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// The named HttpClient used for ValidWhileTrue URI checks.
    /// Consumers can configure this client via
    /// <c>services.AddHttpClient("ZcapValidWhileTrue", client =&gt; { ... });</c>
    /// </summary>
    public const string HttpClientName = "ZcapValidWhileTrue";

    public HttpValidWhileTrueHandler(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    public async Task<bool> CheckAsync(string uri, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(uri))
            return false;

        try
        {
            var client = _httpClientFactory.CreateClient(HttpClientName);
            var response = await client.GetAsync(uri, cancellationToken);

            if (!response.IsSuccessStatusCode)
                return false;

            var status = await response.Content.ReadFromJsonAsync<RevocationStatusHttpResponse>(
                cancellationToken: cancellationToken);

            if (status == null)
                return false;

            // ValidWhileTrue: capability is valid when NOT revoked
            return !status.IsRevoked;
        }
        catch
        {
            // Fail-closed: any exception (network, parsing, etc.) means invalid
            return false;
        }
    }
}
