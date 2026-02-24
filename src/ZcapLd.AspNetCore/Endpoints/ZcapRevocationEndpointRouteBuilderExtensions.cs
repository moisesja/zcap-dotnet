using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using ZcapLd.AspNetCore.Contracts;
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
            .Produces<string>(StatusCodes.Status400BadRequest);

        group.MapGet("/{*capabilityId}", GetRevocationStatusAsync)
            .WithName("ZcapGetRevocationStatus")
            .Produces<RevocationStatusHttpResponse>(StatusCodes.Status200OK)
            .Produces<string>(StatusCodes.Status400BadRequest);

        return group;
    }

    private static async Task<IResult> RevokeCapabilityAsync(
        string capabilityId,
        RevokeCapabilityHttpRequest request,
        IRevocationService revocationService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return TypedResults.BadRequest("Capability ID route value is required.");
        }

        if (request == null || string.IsNullOrWhiteSpace(request.RevokerDid))
        {
            return TypedResults.BadRequest("Body must include a non-empty revokerDid.");
        }

        var decodedCapabilityId = Uri.UnescapeDataString(capabilityId);
        var revocation = await revocationService.RevokeAsync(new RevocationRequest
        {
            CapabilityId = decodedCapabilityId,
            RootCapabilityId = request.RootCapabilityId,
            RevokedBy = request.RevokerDid,
            ExpiresAt = request.ExpiresAt,
            Reason = request.Reason,
            Metadata = request.Metadata
        }, cancellationToken);

        return TypedResults.Ok(ToHttpResponse(revocation, true));
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
