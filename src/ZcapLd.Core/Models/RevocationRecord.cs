using System.Text.Json.Serialization;

namespace ZcapLd.Core.Models;

/// <summary>
/// Persisted revocation record for one capability id in one <see cref="RevocationScope"/> (#158).
/// </summary>
public sealed record RevocationRecord
{
    /// <summary>
    /// Capability ID that has been revoked.
    /// </summary>
    public required string CapabilityId { get; init; }

    /// <summary>
    /// The scope the record applies in. A chain link is revoked by a record for its id only in the
    /// link's own scope or in <see cref="RevocationScope.Unscoped"/>.
    /// </summary>
    public required RevocationScope Scope { get; init; }

    /// <summary>
    /// The store key: <see cref="RevocationScope.KeyFor"/> over <see cref="CapabilityId"/>. Stores
    /// insert, look up and delete records by this value alone. It is an opaque lowercase hex digest,
    /// so no bare id is ever a key and a case-insensitive collation cannot merge two records.
    /// </summary>
    [JsonIgnore]
    public string Key => Scope.KeyFor(CapabilityId);

    /// <summary>
    /// The root of the chain the revocation was authorized on, when known. Informational: it is not
    /// part of the key and never an authorization input.
    /// </summary>
    public string? RootCapabilityId { get; init; }

    /// <summary>
    /// DID or identifier of the actor that requested revocation.
    /// </summary>
    public string RevokedBy { get; init; } = string.Empty;

    /// <summary>
    /// UTC timestamp for when revocation was recorded.
    /// </summary>
    public DateTime RevokedAt { get; init; }

    /// <summary>
    /// UTC expiration timestamp for revocation retention.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>
    /// Optional free-form reason associated with the revocation.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Optional metadata for storage-provider-specific context.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
