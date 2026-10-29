using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.RevocationEndpointsDemo;

/// <summary>
/// SQLite-backed <see cref="IRevocationStore"/>. Rows are keyed by <see cref="RevocationRecord.Key"/>
/// (#158), never by the capability id: two records for one id in different scopes are distinct rows,
/// so a record written under an attacker's scope can never overwrite a legitimate one. A pre-6.0
/// <c>revocation_registry</c> table, keyed by bare id, is migrated once at startup into
/// <see cref="RevocationScope.Unscoped"/> records, which every chain honours exactly as 5.x did.
/// </summary>
public sealed class SqliteRevocationStore : IRevocationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;

    public SqliteRevocationStore(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("Connection string cannot be null or empty.", nameof(connectionString));
        }

        _connectionString = connectionString;
        InitializeSchema();
        MigrateLegacyRegistry();
    }

    public async Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();

        const string sql = """
            INSERT INTO revocation_records
            (
                revocation_key,
                capability_id,
                scope,
                root_capability_id,
                revoked_by,
                revoked_at,
                expires_at,
                reason,
                metadata_json
            )
            VALUES
            (
                $revocationKey,
                $capabilityId,
                $scope,
                $rootCapabilityId,
                $revokedBy,
                $revokedAt,
                $expiresAt,
                $reason,
                $metadataJson
            )
            ON CONFLICT(revocation_key) DO UPDATE SET
                capability_id = excluded.capability_id,
                scope = excluded.scope,
                root_capability_id = excluded.root_capability_id,
                revoked_by = excluded.revoked_by,
                revoked_at = excluded.revoked_at,
                expires_at = excluded.expires_at,
                reason = excluded.reason,
                metadata_json = excluded.metadata_json;
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddRecordParameters(command, record);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<RevocationRecord>> GetAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        cancellationToken.ThrowIfCancellationRequested();

        var wanted = keys.Where(key => !string.IsNullOrWhiteSpace(key)).Distinct(StringComparer.Ordinal).ToList();
        if (wanted.Count == 0)
        {
            return [];
        }

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        var placeholders = new List<string>(wanted.Count);
        for (var i = 0; i < wanted.Count; i++)
        {
            placeholders.Add($"$k{i}");
            command.Parameters.AddWithValue($"$k{i}", wanted[i]);
        }

        command.CommandText = $"""
            SELECT
                capability_id,
                scope,
                root_capability_id,
                revoked_by,
                revoked_at,
                expires_at,
                reason,
                metadata_json
            FROM revocation_records
            WHERE revocation_key IN ({string.Join(", ", placeholders)});
            """;

        var records = new List<RevocationRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadRecord(reader));
        }

        return records;
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        const string sql = """
            DELETE FROM revocation_records
            WHERE revocation_key = $revocationKey;
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$revocationKey", key);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddRecordParameters(SqliteCommand command, RevocationRecord record)
    {
        command.Parameters.AddWithValue("$revocationKey", record.Key);
        command.Parameters.AddWithValue("$capabilityId", record.CapabilityId);
        command.Parameters.AddWithValue("$scope", record.Scope.ToString());
        command.Parameters.AddWithValue("$rootCapabilityId", (object?)record.RootCapabilityId ?? DBNull.Value);
        command.Parameters.AddWithValue("$revokedBy", record.RevokedBy);
        command.Parameters.AddWithValue("$revokedAt", record.RevokedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue(
            "$expiresAt",
            record.ExpiresAt.HasValue
                ? record.ExpiresAt.Value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
                : DBNull.Value);
        command.Parameters.AddWithValue("$reason", (object?)record.Reason ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$metadataJson",
            record.Metadata is { Count: > 0 } ? JsonSerializer.Serialize(record.Metadata, JsonOptions) : DBNull.Value);
    }

    private static RevocationRecord ReadRecord(SqliteDataReader reader)
    {
        IReadOnlyDictionary<string, string>? metadata = null;
        if (!reader.IsDBNull(7))
        {
            metadata = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(7), JsonOptions);
        }

        return new RevocationRecord
        {
            CapabilityId = reader.GetString(0),
            Scope = RevocationScope.Parse(reader.GetString(1)),
            RootCapabilityId = reader.IsDBNull(2) ? null : reader.GetString(2),
            RevokedBy = reader.GetString(3),
            RevokedAt = DateTime.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            ExpiresAt = reader.IsDBNull(5)
                ? null
                : DateTime.Parse(reader.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            Reason = reader.IsDBNull(6) ? null : reader.GetString(6),
            Metadata = metadata
        };
    }

    private void InitializeSchema()
    {
        const string sql = """
            CREATE TABLE IF NOT EXISTS revocation_records
            (
                revocation_key TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                root_capability_id TEXT NULL,
                revoked_by TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                expires_at TEXT NULL,
                reason TEXT NULL,
                metadata_json TEXT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_revocation_records_capability_id
            ON revocation_records (capability_id);

            CREATE INDEX IF NOT EXISTS idx_revocation_records_expires_at
            ON revocation_records (expires_at);
            """;

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// Moves every row of a pre-6.0 <c>revocation_registry</c> (keyed by bare capability id) into
    /// <c>revocation_records</c> as an <see cref="RevocationScope.Unscoped"/> record, then drops the old
    /// table, all in one transaction. Unscoped records apply to their id on every chain, so recorded
    /// revocations keep working; new signed revocations are always scoped.
    /// </summary>
    private void MigrateLegacyRegistry()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using (var probe = connection.CreateCommand())
        {
            probe.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'revocation_registry';";
            if (probe.ExecuteScalar() is null)
            {
                return;
            }
        }

        using var transaction = connection.BeginTransaction();

        var legacy = new List<RevocationRecord>();
        using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = """
                SELECT capability_id, root_capability_id, revoked_by, revoked_at, expires_at, reason, metadata_json
                FROM revocation_registry;
                """;
            using var reader = read.ExecuteReader();
            while (reader.Read())
            {
                IReadOnlyDictionary<string, string>? metadata = null;
                if (!reader.IsDBNull(6))
                {
                    metadata = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(6), JsonOptions);
                }

                legacy.Add(new RevocationRecord
                {
                    CapabilityId = reader.GetString(0),
                    Scope = RevocationScope.Unscoped,
                    RootCapabilityId = reader.IsDBNull(1) ? null : reader.GetString(1),
                    RevokedBy = reader.GetString(2),
                    RevokedAt = DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    ExpiresAt = reader.IsDBNull(4)
                        ? null
                        : DateTime.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    Reason = reader.IsDBNull(5) ? null : reader.GetString(5),
                    Metadata = metadata
                });
            }
        }

        foreach (var record in legacy)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO revocation_records
                (revocation_key, capability_id, scope, root_capability_id, revoked_by, revoked_at, expires_at, reason, metadata_json)
                VALUES
                ($revocationKey, $capabilityId, $scope, $rootCapabilityId, $revokedBy, $revokedAt, $expiresAt, $reason, $metadataJson);
                """;
            AddRecordParameters(insert, record);
            insert.ExecuteNonQuery();
        }

        using (var drop = connection.CreateCommand())
        {
            drop.Transaction = transaction;
            drop.CommandText = "DROP TABLE revocation_registry;";
            drop.ExecuteNonQuery();
        }

        transaction.Commit();
    }
}
