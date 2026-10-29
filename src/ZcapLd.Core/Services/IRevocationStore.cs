using ZcapLd.Core.Models;

namespace ZcapLd.Core.Services;

/// <summary>
/// Pluggable persistence abstraction for capability revocation records.
/// </summary>
/// <remarks>
/// Records are keyed by <see cref="RevocationRecord.Key"/> <b>only</b>: an opaque lowercase hex digest
/// of the capability id and its <see cref="RevocationScope"/> (#158). A store must never key, merge or
/// look records up by the bare capability id: two records for one id in different scopes are
/// distinct, and a backend whose primary key is the capability id would let a record written under an
/// attacker's scope overwrite a legitimate one. Store every field of the record and return it
/// unchanged; <see cref="RevocationService"/> refuses a returned record whose key it did not request
/// or whose stored id and scope disagree with its key, and reads each record back after writing it,
/// so a store that drops or rewrites the scope fails verification closed instead of widening a
/// revocation. Keys are fixed-width hex, so collation does not matter, but compare them exactly. A
/// lookup asks for a few dozen keys at most (two per chain link).
/// </remarks>
public interface IRevocationStore
{
    /// <summary>
    /// Inserts or replaces the record stored under <see cref="RevocationRecord.Key"/>.
    /// </summary>
    Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the records stored under any of <paramref name="keys"/>, each at most once and in any
    /// order. Unknown keys contribute nothing.
    /// </summary>
    Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes the record stored under <paramref name="key"/>, if any.
    /// </summary>
    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}
