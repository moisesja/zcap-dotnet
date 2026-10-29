namespace ZcapLd.Core.Models;

/// <summary>
/// One authenticated caveat in a verified delegation chain: the capability that carries it, the
/// typed caveat, and a stable key for resource-side accounting (#157).
/// </summary>
/// <param name="CapabilityId">The id of the capability that carries the caveat.</param>
/// <param name="GrantKey">Lowercase hex SHA-256 over the RFC 8785 JSON array of ids from the root to
/// this capability. Unlike the issuer-chosen capability id it is unique per position in the
/// verified chain, so key budgets and counters by it rather than by the id.</param>
/// <param name="Caveat">The caveat, read from the signed JSON and validated.</param>
public sealed record CaveatGrant(string CapabilityId, string GrantKey, Caveat Caveat);
