using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.Endpoints;

/// <summary>
/// Minimal API endpoint mapping helpers for revocation operations.
/// </summary>
public static class ZcapRevocationEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps revocation endpoints under the provided route prefix.
    /// Defaults to /zcaps/revocations.
    /// <para>
    /// The POST (revoke) endpoint requires a <b>signed</b> revocation request and resolves an
    /// <see cref="IVerificationService"/> — register the full service graph via
    /// <c>AddZcapServices()</c>. <c>AddZcapRevocationSupport()</c> alone (which registers only the
    /// revocation store/service) is <b>not</b> sufficient for the POST endpoint.
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

        group.MapPost("/{*capabilityId}", RevokeCapabilityAsync)
            .WithName("ZcapRevokeCapability")
            .Produces<RevocationStatusHttpResponse>(StatusCodes.Status200OK)
            .Produces<string>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status403Forbidden);

        group.MapGet("/{*capabilityId}", GetRevocationStatusAsync)
            .WithName("ZcapGetRevocationStatus")
            .Produces<RevocationStatusHttpResponse>(StatusCodes.Status200OK)
            .Produces<string>(StatusCodes.Status400BadRequest);

        return group;
    }

    private static async Task<IResult> RevokeCapabilityAsync(
        string capabilityId,
        HttpRequest httpRequest,
        IVerificationService verificationService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return TypedResults.BadRequest("Capability ID route value is required.");
        }

        // Deserialize with the ZCAP options (polymorphic caveat converter, etc.) so an embedded
        // capability carrying typed caveats / a controller array round-trips byte-faithfully —
        // otherwise dropped fields would drift the canonical bytes and fail verification.
        SignedRevocationHttpRequest? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<SignedRevocationHttpRequest>(
                httpRequest.Body, ZcapJsonOptions.Default, cancellationToken);
        }
        catch (JsonException)
        {
            return TypedResults.BadRequest("Request body is not valid JSON.");
        }

        if (request?.Capability == null || request.SignedRevocation == null)
        {
            return TypedResults.BadRequest("Body must include 'capability' and 'signedRevocation'.");
        }

        var decodedCapabilityId = Uri.UnescapeDataString(capabilityId);
        if (!string.Equals(decodedCapabilityId, request.Capability.Id, StringComparison.Ordinal))
        {
            return TypedResults.BadRequest("Route capability id does not match the body capability id.");
        }

        // Authentication (signature/proof-of-possession) + authorization happen inside the verifier.
        var revoked = await verificationService.RevokeCapabilityAsync(
            request.Capability, request.SignedRevocation);

        if (!revoked)
        {
            return TypedResults.StatusCode(StatusCodes.Status403Forbidden);
        }

        return TypedResults.Ok(new RevocationStatusHttpResponse
        {
            CapabilityId = request.Capability.Id,
            IsRevoked = true
        });
    }

    private static async Task<IResult> GetRevocationStatusAsync(
        string capabilityId,
        IRevocationService revocationService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return TypedResults.BadRequest("Capability ID route value is required.");
        }

        var decodedCapabilityId = Uri.UnescapeDataString(capabilityId);
        var revocation = await revocationService.GetRevocationAsync(decodedCapabilityId, cancellationToken);
        if (revocation == null)
        {
            return TypedResults.Ok(new RevocationStatusHttpResponse
            {
                CapabilityId = decodedCapabilityId,
                IsRevoked = false
            });
        }

        return TypedResults.Ok(ToHttpResponse(revocation, true));
    }

    private static string NormalizePrefix(string routePrefix)
    {
        var trimmed = routePrefix.Trim();
        var withLeadingSlash = trimmed.StartsWith("/", StringComparison.Ordinal) ? trimmed : $"/{trimmed}";
        var normalized = withLeadingSlash.TrimEnd('/');
        return string.IsNullOrEmpty(normalized) ? "/" : normalized;
    }

    private static RevocationStatusHttpResponse ToHttpResponse(RevocationRecord record, bool isRevoked)
    {
        return new RevocationStatusHttpResponse
        {
            CapabilityId = record.CapabilityId,
            IsRevoked = isRevoked,
            RootCapabilityId = record.RootCapabilityId,
            RevokedBy = record.RevokedBy,
            RevokedAt = record.RevokedAt,
            ExpiresAt = record.ExpiresAt,
            Reason = record.Reason,
            Metadata = record.Metadata
        };
    }
}
