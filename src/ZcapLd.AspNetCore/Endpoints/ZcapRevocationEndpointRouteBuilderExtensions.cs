using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.Endpoints;

/// <summary>
/// Minimal API endpoint mapping helpers for revocation operations.
/// </summary>
public static class ZcapRevocationEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Upper bound on the (unauthenticated) revoke request body. A legitimate signed revocation —
    /// even one embedding a full delegation chain — is small; this caps the body an attacker can force
    /// the server to materialize before any structural/auth check runs.
    /// </summary>
    private const long MaxRevocationRequestBytes = 1 * 1024 * 1024; // 1 MB

    /// <summary>
    /// Maps the signed revocation endpoint, <c>POST {prefix}/{capabilityId}</c>, under the provided
    /// route prefix. Defaults to /zcaps/revocations.
    /// <para>
    /// Clients address a capability as <c>{prefix}/{encodeURIComponent(capabilityId)}</c>: one level
    /// of percent-encoding over the id, which the endpoint decodes exactly once. A root id already
    /// contains percent-escapes (<c>urn:zcap:root:https%3A%2F%2F…</c>), so it appears encoded twice in
    /// the URL; that is correct.
    /// </para>
    /// <para>
    /// The endpoint requires a <b>signed</b> revocation request and resolves an
    /// <see cref="IVerificationService"/> — register the full service graph via
    /// <c>AddZcapServices()</c>. <c>AddZcapRevocationSupport()</c> alone (which registers only the
    /// revocation store/service) is <b>not</b> sufficient.
    /// </para>
    /// <para>
    /// There is no status GET. The ZCAP specification and the <c>@digitalbazaar</c> reference stack
    /// define only the POST, and once records are scoped to the delegator that signed a capability
    /// (#158) a bare id has no single revocation status. Holders learn of revocation from a
    /// <c>Revoked</c> verification outcome; an operator who needs status queries exposes
    /// <see cref="IRevocationService"/> behind their own authorization.
    /// </para>
    /// </summary>
    public static RouteGroupBuilder MapZcapRevocationEndpoints(
        this IEndpointRouteBuilder endpoints,
        string routePrefix = "/zcaps/revocations")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (string.IsNullOrWhiteSpace(routePrefix))
        {
            throw new ArgumentException("Route prefix cannot be null or empty.", nameof(routePrefix));
        }

        var normalizedPrefix = NormalizePrefix(routePrefix);
        var group = endpoints.MapGroup(normalizedPrefix).WithTags("ZCAP Revocations");

        // The RequestDelegate overload: the Delegate overload binds parameters by reflection at startup
        // (RequiresUnreferencedCode/RequiresDynamicCode), and the Request Delegate Generator only
        // intercepts MapPost calls in the application's own compilation, never in a referenced library,
        // so a trimmed or native AOT host (#154) needs the handler to read the route value, request,
        // services and cancellation token itself.
        group.MapPost("/{*capabilityId}", RevokeCapabilityAsync)
            .WithName("ZcapRevokeCapability")
            .WithMetadata(new ProducesResponseTypeMetadata(
                StatusCodes.Status200OK, typeof(RevocationStatusHttpResponse), ["application/json"]))
            .WithMetadata(new ProducesResponseTypeMetadata(StatusCodes.Status400BadRequest, typeof(string), ["application/json"]))
            .WithMetadata(new ProducesResponseTypeMetadata(StatusCodes.Status403Forbidden));

        return group;
    }

    private static async Task RevokeCapabilityAsync(HttpContext context)
    {
        var result = await RevokeCapabilityAsync(
            context.GetRouteValue("capabilityId") as string,
            context.Request,
            context.RequestServices.GetRequiredService<IVerificationService>(),
            context.RequestAborted);
        await result.ExecuteAsync(context);
    }

    private static async Task<IResult> RevokeCapabilityAsync(
        string? capabilityId,
        HttpRequest httpRequest,
        IVerificationService verificationService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return BadRequest("Capability ID route value is required.");
        }

        if (!TryGetCapabilityId(httpRequest.HttpContext, capabilityId, out var requestedCapabilityId))
        {
            return BadRequest("Capability ID could not be read from the request path.");
        }

        // Bound the unauthenticated request body BEFORE materializing it (DoS): the verifier's
        // structural limits (chain length, etc.) only run after deserialization, so cap the body here.
        // Kestrel enforces the per-request limit mid-read and throws BadHttpRequestException on overflow.
        var bodySizeFeature = httpRequest.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (bodySizeFeature is { IsReadOnly: false })
        {
            bodySizeFeature.MaxRequestBodySize = MaxRevocationRequestBytes;
        }

        // Preserve embedded proofs, controller arrays and extension data with the shared options.
        // In particular, forbidden caveat fields must reach the verifier rather than disappear.
        // Source-generated metadata (#154): the body is read without reflection under native AOT.
        SignedRevocationHttpRequest? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync(
                httpRequest.Body, ZcapAspNetCoreJsonOptions.Request, cancellationToken);
        }
        catch (JsonException)
        {
            return BadRequest("Request body is not valid JSON.");
        }
        catch (BadHttpRequestException)
        {
            // Body exceeded MaxRevocationRequestBytes.
            return TypedResults.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        if (request?.Capability == null || request.SignedRevocation == null)
        {
            return BadRequest("Body must include 'capability' and 'signedRevocation'.");
        }

        if (!string.Equals(requestedCapabilityId, request.Capability.Id, StringComparison.Ordinal))
        {
            return BadRequest("Route capability id does not match the body capability id.");
        }

        // Authentication (signature/proof-of-possession) + authorization happen inside the verifier.
        var revoked = await verificationService.RevokeCapabilityAsync(
            request.Capability, request.SignedRevocation);

        if (!revoked)
        {
            return TypedResults.StatusCode(StatusCodes.Status403Forbidden);
        }

        // Explicit metadata so the response serializes without reflection under native AOT (#154): the
        // host needs no JsonOptions configuration, unlike TypedResults.Ok<T>, which resolves through the
        // application's JsonOptions resolver chain.
        return TypedResults.Json(
            new RevocationStatusHttpResponse
            {
                CapabilityId = request.Capability.Id,
                IsRevoked = true
            },
            ZcapAspNetCoreJsonOptions.Response,
            statusCode: StatusCodes.Status200OK);
    }

    /// <summary>
    /// A 400 whose body is the message as a JSON string, the shape <c>TypedResults.BadRequest(string)</c>
    /// writes, through explicit metadata: that result resolves <c>string</c> from the host's
    /// <c>JsonOptions</c>, whose resolver chain is empty under native AOT, so every malformed body would
    /// be a 500 there (#154).
    /// </summary>
    private static IResult BadRequest(string message)
        => TypedResults.Json(message, ZcapAspNetCoreJsonOptions.Text, statusCode: StatusCodes.Status400BadRequest);

    /// <summary>
    /// Recovers the capability id addressed by the request, decoded exactly once (Issue #155).
    /// </summary>
    /// <remarks>
    /// ASP.NET Core decodes every percent-escape in the request path except <c>%2F</c> before routing,
    /// so the <c>{*capabilityId}</c> route value is neither the encoded nor the decoded id: a root id
    /// (<c>urn:zcap:root:https%3A%2F%2F…</c>, sent as <c>…%253A%252F%252F…</c>) and an id containing
    /// <c>/</c> (sent as <c>%2F</c>) both arrive with <c>%2F</c> in them. Decoding the route value a
    /// second time repaired the latter and corrupted the former — every root id read as a different
    /// id. Only the raw request target tells the two apart, so when the server exposes it (Kestrel
    /// does; the in-memory TestServer does not) the id is cut from the raw target and decoded once.
    /// Without a raw target the route value is used verbatim, which is exact for every id that does not
    /// contain an encoded <c>/</c> (all <c>urn:zcap:root:</c> and <c>urn:uuid:</c> ids).
    /// </remarks>
    private static bool TryGetCapabilityId(HttpContext context, string routeValue, out string capabilityId)
    {
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget))
        {
            capabilityId = routeValue;
            return true;
        }

        capabilityId = string.Empty;

        var queryStart = rawTarget.IndexOf('?');
        var rawPath = queryStart < 0 ? rawTarget : rawTarget[..queryStart];

        // Path decoding never creates or removes a '/', so the raw form of the catch-all is the suffix of
        // the raw path holding exactly as many slashes as the route value. Counting back from the end
        // skips PathBase, the prefix (in whatever encoding it was sent) and an absolute-form target.
        var end = rawPath.Length;
        for (var slashes = routeValue.AsSpan().Count('/'); slashes >= 0; slashes--)
        {
            if (end == 0)
            {
                return false;
            }

            end = rawPath.LastIndexOf('/', end - 1);
            if (end < 0)
            {
                return false;
            }
        }

        var rawCapabilityId = rawPath[(end + 1)..];

        // The suffix must be what routing matched: decoded the way the server decodes the path (every
        // escape except %2F) it has to equal the route value. Otherwise the server rewrote or normalized
        // the path and the raw target no longer describes the routed request — fail closed.
        string? decodedLikeTheServer;
        try
        {
            decodedLikeTheServer = PathString.FromUriComponent("/" + rawCapabilityId).Value;
        }
        catch (InvalidOperationException)
        {
            // A NUL escape (%00). Kestrel rejects it before routing; another host might not.
            return false;
        }

        if (!string.Equals(decodedLikeTheServer, "/" + routeValue, StringComparison.Ordinal))
        {
            return false;
        }

        capabilityId = Uri.UnescapeDataString(rawCapabilityId);
        return true;
    }

    private static string NormalizePrefix(string routePrefix)
    {
        var trimmed = routePrefix.Trim();
        var withLeadingSlash = trimmed.StartsWith("/", StringComparison.Ordinal) ? trimmed : $"/{trimmed}";
        var normalized = withLeadingSlash.TrimEnd('/');
        return string.IsNullOrEmpty(normalized) ? "/" : normalized;
    }
}
